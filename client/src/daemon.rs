use std::{
    io::Write,
    os::unix::net::UnixStream,
    thread::{self},
    time::Duration,
};

use n0_future::StreamExt;
use n0_watcher::{self, Watcher};

use wireguard_control::Key;

use crate::{
    announce, nat,
    netstat::{self, NetInfo},
    utils, wg_interface,
};

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

fn show_stats(ifname: &str, net_info: Option<NetInfo>, port: Option<u16>) -> anyhow::Result<()> {
    let mut s = UnixStream::connect("/var/run/wireplugd.sock")?;
    write!(s, "\x1B[2J\x1B[1;1H")?;
    writeln!(s, "Network:\n-------")?;
    match net_info {
        Some(n) => writeln!(s, "{n}")?,
        None => writeln!(s, "\tN/A\n")?,
    }
    write!(s, "\tWireGuard Port: ")?;
    match port {
        Some(p) => writeln!(s, "{p}")?,
        None => writeln!(s, "N/A")?,
    }
    let peer_info = wg_interface::get_peer_info(ifname)?;
    s.write_all(peer_info.as_bytes())?;
    Ok(())
}

pub(crate) async fn monitor_interface(ifname: &str, traverse_nat: bool) -> anyhow::Result<()> {
    let mut peers_manager = wg_interface::PeerTracker::new();
    let mut netstate = netstat::NetworkState::new(ifname).await?;
    let nm = netwatch::netmon::Monitor::new().await?;

    wg_interface::init_peers_activity(ifname, &mut peers_manager)?;

    tokio::spawn(async move {
        /*
        if let Err(e) = show_stats(ifname, netmon.get_current(), port_to_announce) {
            log::warn!("could not show stats: {e}");
        }
        */
    });

    log::info!("monitoring interface: {ifname} | NAT travesal={traverse_nat}");
    let mut port_to_announce = None;

    loop {
        let mut nw_stream = nm.interface_state().stream_updates_only();
        let inactive_peers = tokio::select! {
            biased;
            state = nw_stream.next() => {
                if netstate.has_endpoint_changed(state).await {
                    port_to_announce = None;
                }
                continue;

            },
            port = get_port_to_announce(traverse_nat), if port_to_announce.is_none() && netstate.is_online() => {
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
                if netstate.is_online() {
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
        let Some(netinfo) = netstate.get_current() else {
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
            netstate.needs_relay(),
        )?;
    }
}
