use std::{
    collections::HashMap,
    fmt::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime},
};

use shared::protocol::{WireplugAnnouncement, WireplugEndpoint};
use tokio::sync::RwLock;

use crate::relay::{RelayKind, SharedRelayManager};

const RECORD_TIMEOUT_SEC: u64 = 60 * 60;
const RELAY_ENABLED: bool = false;

#[derive(Clone)]
struct Record {
    // XXX ipv4 is currently not optional
    // pub wan_ipv4: Option<Ipv4Addr>,
    pub wan_ipv4: Ipv4Addr,
    pub wan_ipv6: Option<Ipv6Addr>,
    pub lan_addrs: Vec<ipnet::IpNet>,
    pub wg_port: u16,
    pub timestamp: SystemTime,
    pub needs_relay: bool,
}

impl Record {
    fn new(
        wan_ipv4: Ipv4Addr,
        wan_ipv6: Option<Ipv6Addr>,
        lan_addrs: Vec<ipnet::IpNet>,
        wg_port: u16,
        timestamp: SystemTime,
        needs_relay: bool,
    ) -> Self {
        Self {
            wan_ipv4,
            wan_ipv6,
            lan_addrs,
            wg_port,
            timestamp,
            needs_relay,
        }
    }
}

type PeeringRecords = HashMap<(String, String), Record>;
pub(crate) struct Storage {
    peering_records: PeeringRecords,
}

impl Storage {
    pub fn new() -> Self {
        Self {
            peering_records: HashMap::new(),
        }
    }
    pub fn write_to<W: Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        let now = SystemTime::now();
        for p in self.peering_records.iter() {
            let peer_a = &p.0.0;
            let peer_b = &p.0.1;
            let ipv4 = &p.1.wan_ipv4;
            let ipv6 = &p.1.wan_ipv6;
            let lan = &p.1.lan_addrs;
            let timestamp = &p.1.timestamp;
            let sec = now.duration_since(*timestamp)?.as_secs();
            writeln!(
                writer,
                "\t{peer_a} @{:?}/{:?} (LAN: {:?} -> {peer_b}) | {sec} sec ago",
                ipv4, ipv6, lan
            )?;
        }
        Ok(())
    }
}

pub(crate) type SharedStorage = Arc<RwLock<Storage>>;

pub(crate) async fn get_peer_endpoints(
    announcement: &WireplugAnnouncement,
    announcing_peer_addr: SocketAddr,
    storage: &SharedStorage,
    relay_manager: SharedRelayManager,
) -> HashMap<String, WireplugEndpoint> {
    let mut res_peers = HashMap::new();
    let storage_reader = storage.read().await;
    let mut relay_manager = relay_manager.write().await;

    for peer in &announcement.peer_pubkeys {
        let peer_endpoint = match storage_reader
            .peering_records
            .get(&(peer.to_owned(), announcement.initiator_pubkey.to_owned()))
        {
            Some(record) => {
                if announcing_peer_addr.ip() == record.wan_ipv4 {
                    WireplugEndpoint::LocalNetwork {
                        ipv6: record.wan_ipv6,
                        lan_addrs: record.lan_addrs.clone(),
                        wg_port: record.wg_port,
                    }
                } else if RELAY_ENABLED && (announcement.needs_relay || record.needs_relay) {
                    let relay_port = match relay_manager.get_relay_port(
                        &announcement.initiator_pubkey,
                        peer,
                        announcing_peer_addr.ip(),
                    ) {
                        RelayKind::Proto(p) => {
                            log::trace!("Proto Relay port:{p}");
                            p
                        }
                        RelayKind::Pending(p) => {
                            log::trace!("Pending Relay port:{p}");
                            p
                        }
                        RelayKind::Established(p) => {
                            log::trace!("Established Relay port:{p}");
                            p
                        }
                    };
                    WireplugEndpoint::Relay {
                        id: 1,
                        port: relay_port,
                    }
                } else {
                    WireplugEndpoint::RemoteNetwork {
                        ipv4: Some(record.wan_ipv4),
                        ipv6: record.wan_ipv6,
                        wg_port: record.wg_port,
                    }
                }
            }
            None => {
                if RELAY_ENABLED && announcement.needs_relay {
                    let relay_port = match relay_manager.get_relay_port(
                        &announcement.initiator_pubkey,
                        peer,
                        announcing_peer_addr.ip(),
                    ) {
                        RelayKind::Proto(p) => p,
                        RelayKind::Pending(p) => p,
                        _ => todo!(), // error
                    };
                    WireplugEndpoint::Relay {
                        id: 1,
                        port: relay_port,
                    }
                } else {
                    WireplugEndpoint::Unknown
                }
            }
        };
        res_peers.insert(peer.to_owned(), peer_endpoint);
    }
    res_peers
}

pub(crate) async fn process_announcement(
    announcement: &WireplugAnnouncement,
    announcing_peer_addr: SocketAddr,
    storage: &SharedStorage,
) -> std::io::Result<()> {
    let announing_peer_ipv4 = match announcing_peer_addr.ip() {
        IpAddr::V4(ipv4_addr) => ipv4_addr,
        IpAddr::V6(_) => {
            return Err(std::io::Error::other("bad ip"));
        }
    };
    let mut storage_writer = storage.write().await;
    for peer in &announcement.peer_pubkeys {
        storage_writer.peering_records.insert(
            (announcement.initiator_pubkey.to_owned(), peer.to_owned()),
            Record::new(
                announing_peer_ipv4,
                announcement.ipv6,
                announcement.lan_addrs.to_owned(),
                announcement.wg_port,
                SystemTime::now(),
                announcement.needs_relay,
            ),
        );
    }
    Ok(())
}

pub(crate) async fn remove_old_records(storage: &SharedStorage) -> std::io::Result<()> {
    let now = SystemTime::now();
    storage.write().await.peering_records.retain(|_, record| {
        if let Ok(record_duration) = now.duration_since(record.timestamp)
            && record_duration < Duration::from_secs(RECORD_TIMEOUT_SEC)
        {
            return true;
        }
        false
    });
    Ok(())
}
