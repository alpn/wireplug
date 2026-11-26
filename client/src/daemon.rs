use std::{
    fmt::Write,
    fs,
    os::unix::fs::PermissionsExt,
    sync::Arc,
    thread::{self},
    time::Duration,
};

use tokio::{io::AsyncWriteExt, net::UnixListener, sync::Mutex};

use wireguard_control::Key;

use n0_future::StreamExt;
use n0_watcher::{self, Watcher};

use crate::{
    announce, nat,
    netstat::{self, NetInfo, NetworkState},
    utils, wg_interface,
};

static MON_SOCK: &str = "/var/run/wireplugd.sock";

async fn get_port_to_announce(traverse_nat: bool) -> Option<u16> {
    let new_port = utils::get_random_port();
    let new_port = if traverse_nat {
        let nat_kind = match nat::detect_kind(new_port) {
            Ok(res) => res,
            Err(e) => {
                log::warn!("failed to perform NAT detection: {e}");
                tokio::time::sleep(Duration::from_secs(5)).await;
                return None;
            }
        };
        match nat_kind {
            nat::NatKind::Easy => new_port,
            nat::NatKind::FixedPortMapping(port_mapping_nat) => port_mapping_nat.obsereved_port,
            nat::NatKind::Hard => {
                log::warn!("Destination-Dependent NAT detected");
                new_port
            }
        }
    } else {
        new_port
    };

    Some(new_port)
}

pub(crate) fn handle_inactive_peers(
    ifname: &str,
    peer_tracker: &mut wg_interface::PeerTracker,
    mut peers: Vec<Key>,
    netinfo: NetInfo,
    port_to_announce: u16,
    needs_relay: bool,
) -> anyhow::Result<()> {
    const MAX_ANNOUNCE_RETRIES: usize = 3;
    for _ in 1..=MAX_ANNOUNCE_RETRIES {
        match announce::announce(ifname, &peers, port_to_announce, &netinfo, needs_relay) {
            Ok(response) => {
                let peers_updated = wg_interface::update_peers(
                    ifname,
                    peer_tracker,
                    response.peer_endpoints,
                    netinfo.wan_ipv6.is_some(),
                )?;
                if !peers_updated.is_empty() {
                    log::info!(
                        "some endpoints were updated, waiting for peers to attempt handshakes.."
                    );
                    thread::sleep(Duration::from_secs(5));
                    peers.retain(|p| !peers_updated.contains(p));
                }
                return Ok(());
            }
            Err(e) => {
                log::warn!("announcement failed: {e}");
                thread::sleep(Duration::from_secs(5));
            }
        }
    }
    Ok(())
}

async fn serve_monitoring_socket(
    unix_listener: UnixListener,
    netstate: Arc<Mutex<NetworkState>>,
    ifname: String,
) -> anyhow::Result<()> {
    loop {
        let mut socket = match unix_listener.accept().await {
            Ok((s, _)) => {
                log::warn!("new monitoring client connected");
                s
            }
            Err(e) => {
                log::warn!("monitoring socket error: {e}");
                break;
            }
        };
        loop {
            let mut s = String::new();
            write!(s, "\x1B[2J\x1B[1;1H")?;
            writeln!(s, "Network:\n-------")?;

            match netstate.lock().await.get_current() {
                Some(n) => writeln!(s, "{n}")?,
                None => writeln!(s, "\tN/A\n")?,
            }
            write!(s, "\tWireGuard Port: ")?;
            match wg_interface::get_port(&ifname) {
                Some(p) => writeln!(s, "{p}")?,
                None => writeln!(s, "N/A")?,
            }
            let peer_info = wg_interface::get_peer_info(&ifname)?;
            s.write_str(&peer_info)?;
            if let Err(e) = socket.write_all(s.as_bytes()).await {
                log::warn!("bad monitoring client {e}");
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    Ok(())
}

pub(crate) async fn monitor_interface(ifname: &str, traverse_nat: bool) -> anyhow::Result<()> {
    let mut peers_manager = wg_interface::PeerTracker::new();
    let netstate = netstat::NetworkState::new(ifname).await?;
    let shared_netstate = Arc::new(Mutex::new(netstate));
    let netmon = netwatch::netmon::Monitor::new().await?;

    wg_interface::init_peers_activity(ifname, &mut peers_manager)?;

    let task_netstate = Arc::clone(&shared_netstate);
    let task_ifname = ifname.to_owned();
    tokio::spawn(async move {
        if let Err(e) = tokio::fs::remove_file(MON_SOCK).await {
            log::warn!("failed to unlink monitoring socket {}: {e}", MON_SOCK);
            return;
        }
        match tokio::net::UnixListener::bind(MON_SOCK) {
            Ok(unix_listener) => {
                if let Err(e) =
                    tokio::fs::set_permissions(MON_SOCK, fs::Permissions::from_mode(0o666)).await
                {
                    log::warn!(
                        "failed to set permissions on monitoring socket {}: {e}",
                        MON_SOCK
                    );
                    return;
                }
                if let Err(e) =
                    serve_monitoring_socket(unix_listener, task_netstate, task_ifname).await
                {
                    log::error!("monitoring socket error: {e}");
                }
            }
            Err(e) => {
                log::error!("failed to bind monitoring socket {}: {e}", MON_SOCK);
            }
        }
    });

    log::info!("monitoring interface: {ifname} | NAT travesal={traverse_nat}");
    let mut port_to_announce = None;

    loop {
        let mut netmon_update_stream = netmon.interface_state().stream_updates_only();
        let inactive_peers = tokio::select! {
            biased;
            state = netmon_update_stream.next() => {
                if shared_netstate.lock().await.has_endpoint_changed(state).await {
                    port_to_announce = None;
                }
                continue;

            },
            port = get_port_to_announce(traverse_nat), if port_to_announce.is_none() && shared_netstate.lock().await.is_online() => {
                port_to_announce = port;
                let Some(new_port) = port_to_announce else {
                    continue;
                };

                log::debug!("updating listen port to {new_port:?} ..");
                // wait before reusing the port
                tokio::time::sleep(Duration::from_secs(3)).await;
                if let Err(e) = wg_interface::update_port(ifname, new_port) {
                    log::error!("failed to update wg port: {e}");
                    continue;
                }
                wg_interface::get_all_peers(ifname)?
            },
            _ = tokio::time::sleep(Duration::from_secs(wg_interface::COMMON_PKA.into())) => {
                if shared_netstate.lock().await.is_online() {
                    wg_interface::get_inactive_peers_by_rx(ifname, &mut peers_manager)?
                }
                else {
                    continue;
                }
            }
        };

        if inactive_peers.is_empty() {
            continue;
        }

        log::info!("{ifname} has {} INACTIVE peers", inactive_peers.len());
        let Some(netinfo) = shared_netstate.lock().await.get_current() else {
            log::warn!("no NetInfo - skipping");
            continue;
        };
        let Some(port_to_announce) = port_to_announce else {
            log::warn!("no port_to_announce - skipping");
            continue;
        };
        handle_inactive_peers(
            ifname,
            &mut peers_manager,
            inactive_peers,
            netinfo,
            port_to_announce,
            shared_netstate.lock().await.needs_relay(),
        )?;
    }
}
