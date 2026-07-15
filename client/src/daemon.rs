use std::{
    io::Write,
    os::unix::net::UnixStream,
    thread::{self},
    time::{Duration, Instant},
};

use wireguard_control::Key;

use crate::{
    announce, nat,
    netstat::{self, NetInfo},
    utils, wg_interface,
};

pub(crate) fn handle_inactive_peers(
    ifname: &String,
    peer_tracker: &mut wg_interface::PeerTracker,
    peers: &mut Vec<Key>,
    netinfo: NetInfo,
    port_to_announce: u16,
    needs_relay: bool,
) -> anyhow::Result<()> {
    const MAX_ANNOUNCE_RETRIES: usize = 3;
    for _ in 1..=MAX_ANNOUNCE_RETRIES {
        match announce::announce(ifname, peers, port_to_announce, &netinfo, needs_relay) {
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

fn show_stats(ifname: &str, net_info: Option<NetInfo>) -> anyhow::Result<()> {
    let mut s = UnixStream::connect("/var/run/wireplugd.sock")?;
    write!(s, "\x1B[2J\x1B[1;1H")?;
    writeln!(s, "Network:\n-------")?;
    match net_info {
        Some(n) => writeln!(s, "{n}")?,
        None => writeln!(s, "\tN/A")?,
    }
    let peer_info = wg_interface::get_peer_info(ifname)?;
    s.write_all(peer_info.as_bytes())?;
    Ok(())
}

pub(crate) fn monitor_interface(ifname: &String, traverse_nat: bool) -> anyhow::Result<()> {
    let mut netmon = netstat::NetworkMonitor::new(ifname);
    let mut peers_manager = wg_interface::PeerTracker::new();
    wg_interface::init_peers_activity(ifname, &mut peers_manager)?;

    log::info!("monitoring interface: {ifname} | NAT travesal={traverse_nat}");

    let peer_is_inactive_duration = Duration::from_secs(25);
    let mut next_inactivity_check = Instant::now() + peer_is_inactive_duration;
    let mut inactive_peers = vec![];
    let mut port_to_announce = 0;
    loop {
        if let Err(e) = show_stats(ifname, netmon.get_current()) {
            log::warn!("could not show stats: {e}");
        }
        match netmon.check_status() {
            netstat::NetStatus::Online | netstat::NetStatus::ChangedToPrev => (),
            netstat::NetStatus::Offline | netstat::NetStatus::HardNat => {
                thread::sleep(Duration::from_secs(5));
                continue;
            }
            netstat::NetStatus::ChangedToNew => {
                let new_port = utils::get_random_port();
                port_to_announce = match traverse_nat {
                    true => match nat::detect_kind(new_port)? {
                        nat::NatKind::Easy => new_port,
                        nat::NatKind::FixedPortMapping(port_mapping_nat) => {
                            port_mapping_nat.obsereved_port
                        }
                        nat::NatKind::Hard => {
                            log::warn!("Destination-Dependent NAT detected");
                            netmon.set_hard_nat(true);
                            new_port
                        }
                    },
                    false => new_port,
                };

                log::debug!("updating listen port to {new_port} ..");
                // wait before reusing the port
                std::thread::sleep(Duration::from_secs(3));
                wg_interface::update_port(ifname, new_port)?;

                inactive_peers = wg_interface::get_all_peers(ifname)?;
                next_inactivity_check += peer_is_inactive_duration;
            }
        }

        if Instant::now() > next_inactivity_check {
            next_inactivity_check += peer_is_inactive_duration;
            inactive_peers.clear();
            inactive_peers = wg_interface::get_inactive_peers_by_rx(ifname, &mut peers_manager)?;
        }
        if !inactive_peers.is_empty() {
            log::info!("{ifname} has {} INACTIVE peers", inactive_peers.len());
            let Some(netinfo) = netmon.get_current() else {
                log::warn!("no NetInfo - skipping");
                continue;
            };
            handle_inactive_peers(
                ifname,
                &mut peers_manager,
                &mut inactive_peers,
                netinfo,
                port_to_announce,
                netmon.needs_relay(),
            )?;
        }
        thread::sleep(Duration::from_secs(10));
    }
}
