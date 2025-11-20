use std::{
    thread::{self},
    time::{Duration, Instant},
};

use anyhow::Context;
use wireguard_control::Key;

use crate::{
    announce, nat,
    netstat::{self},
    utils, wg_interface,
};

pub(crate) fn handle_inactive_peers(
    ifname: &String,
    peer_tracker: &mut wg_interface::PeerTracker,
    peers: &mut Vec<Key>,
    port_to_announce: u16,
) -> anyhow::Result<()> {
    let lan_addrs = utils::get_lan_addrs(ifname).ok();
    const MAX_ANNOUNCE_RETRIES: usize = 3;
    for _ in 1..=MAX_ANNOUNCE_RETRIES {
        match announce::announce(ifname, peers, port_to_announce, &lan_addrs) {
            Ok(response) => {
                let peers_updated =
                    wg_interface::update_peers(ifname, peer_tracker, response.peer_endpoints)?;
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

pub(crate) fn monitor_interface(ifname: &String, traverse_nat: bool) -> anyhow::Result<()> {
    let mut netmon = netstat::NetworkMonitor::new();
    let mut peers_manager = wg_interface::PeerTracker::new();
    wg_interface::init_peers_activity(ifname, &mut peers_manager)?;

    log::info!("monitoring interface: {ifname} with NAT travesal={traverse_nat}");

    let peer_is_inactive_duration = Duration::from_secs(25);
    let mut next_inactivity_check = Instant::now() + peer_is_inactive_duration;
    let mut inactive_peers = vec![];
    loop {
        match netmon.status() {
            netstat::NetStatus::Online | netstat::NetStatus::ChangedToPrev => (),
            netstat::NetStatus::Offline | netstat::NetStatus::HardNat => {
                thread::sleep(Duration::from_secs(5));
                continue;
            }
            netstat::NetStatus::ChangedToNew => {
                let new_port = utils::get_random_port();
                let observed_port = match traverse_nat {
                    true => match nat::get_observed_port(new_port) {
                        Some(port) => port,
                        None => {
                            netmon.set_hard_nat(true);
                            continue;
                        }
                    },
                    false => new_port,
                };

                log::debug!("updating listen port to {observed_port} ..");
                // wait before reusing the port
                std::thread::sleep(Duration::from_secs(3));
                wg_interface::update_port(ifname, observed_port)?;

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
            let port_to_announce =
                wg_interface::get_port(ifname).context("listen port is not set")?;
            handle_inactive_peers(
                ifname,
                &mut peers_manager,
                &mut inactive_peers,
                port_to_announce,
            )?;
        } else {
            wg_interface::show_peers(ifname)?;
        }
        thread::sleep(Duration::from_secs(10));
    }
}
