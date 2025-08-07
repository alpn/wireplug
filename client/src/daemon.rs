use std::{thread, time::Duration};

use anyhow::Context;
use wireguard_control::Key;

use crate::{announce, nat, netstat::{self, NetworkMonitor}, utils, wg_interface};

pub(crate) fn handle_inactive_peers(ifname: &String, peers: Vec<Key>, netmon: &mut NetworkMonitor,listen_port: u16, traverse_nat: bool) -> anyhow::Result<u64> {
    let port_to_announce = if netmon.has_changed() && traverse_nat {
        let new_listen_port = utils::get_random_port();
        let nat = nat::detect_kind(new_listen_port)?;
        log::debug!("NAT: {nat:?}");
        let observed_port = match nat {
            nat::NatKind::Easy => new_listen_port,
            nat::NatKind::FixedPortMapping(port_mapping_nat) => {
                port_mapping_nat.obsereved_port
            }
            nat::NatKind::Hard => {
                log::warn!("can't do much about Hard NAT atm, will try again in a bit .. ");
                return Ok(shared::protocol::MONITORING_INTERVAL);
            }
        };
        log::debug!("updating listen port to {new_listen_port} ..");
        std::thread::sleep(Duration::from_secs(3));
        wg_interface::update_port(ifname, new_listen_port)?;
        observed_port
    } else {
        listen_port
    };
    let lan_addrs = utils::get_lan_addrs(ifname).ok();
    match announce::announce(
        ifname,
        peers,
        port_to_announce,
        lan_addrs,
    ){
        Ok(response) => {
            if wg_interface::update_peers(ifname, response)? {
                log::info!(
                    "some endpoints were updated, waiting for peers to attempt handshakes.."
                );
            }
        },
        Err(e) => {
            log::warn!(
                "announcement failed: {e}"
            );
            return Ok(5);
        },
    }
    Ok(shared::protocol::POST_UPDATE_INTERVAL)
}

pub(crate) fn monitor_interface(ifname: &String, traverse_nat: bool) -> anyhow::Result<()> {
    let mut peers_activity = wg_interface::PeersActivity::new();
    let mut netmon = netstat::NetworkMonitor::new();
    log::info!("monitoring interface: {ifname} with NAT travesal={traverse_nat}");
    loop {
        let Some(listen_port) = wg_interface::get_port(ifname) else {
            todo!();
        };
        let inactive_peers = wg_interface::get_inactive_peers(ifname, &mut peers_activity)?;
        log::info!("{ifname} has {} INACTIVE peers", inactive_peers.len());
        let seconds_to_wait = match  inactive_peers.is_empty() {
            false => handle_inactive_peers(ifname, inactive_peers,  &mut netmon, listen_port, traverse_nat)?,
            true => shared::protocol::MONITORING_INTERVAL,
        };
        thread::sleep(Duration::from_secs(seconds_to_wait));
    }
}
