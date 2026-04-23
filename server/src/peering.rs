use std::{
    collections::HashMap,
    fmt::Write,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use shared::protocol::{WireplugAnnouncement, WireplugEndpoint};
use tokio::sync::RwLock;

use crate::relay::{RelayKind, SharedRelayManager};

const RECORD_TIMEOUT_SEC: u64 = 60 * 60;

#[derive(Clone)]
struct Record {
    pub wan_addr: SocketAddr,
    pub lan_addrs: Vec<String>,
    pub timestamp: SystemTime,
    pub needs_relay: bool,
}

impl Record {
    fn new(
        wan_addr: SocketAddr,
        lan_addrs: Vec<String>,
        timestamp: SystemTime,
        needs_relay: bool,
    ) -> Self {
        Self {
            wan_addr,
            lan_addrs,
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
    pub fn debug<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let now = SystemTime::now();
        for p in self.peering_records.iter() {
            let peer_a = &p.0.0;
            let peer_b = &p.0.1;
            let ip = p.1.wan_addr;
            let timestamp = &p.1.timestamp;
            let sec = now.duration_since(*timestamp).unwrap().as_secs();
            writeln!(writer, "\t{peer_a} @{ip} -> {peer_b} | {sec} sec ago").unwrap();
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
                if announcing_peer_addr.ip() == record.wan_addr.ip() {
                    WireplugEndpoint::LocalNetwork {
                        lan_addrs: record.lan_addrs.clone(),
                        listen_port: record.wan_addr.port(),
                    }
                } else if announcement.needs_relay || record.needs_relay {
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
                    WireplugEndpoint::RemoteNetwork(record.wan_addr)
                }
            }
            None => {
                if announcement.needs_relay {
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
    let peer_wg_wan_addr = SocketAddr::new(announcing_peer_addr.ip(), announcement.listen_port);
    let mut storage_writer = storage.write().await;
    for peer in &announcement.peer_pubkeys {
        storage_writer.peering_records.insert(
            (announcement.initiator_pubkey.to_owned(), peer.to_owned()),
            Record::new(
                peer_wg_wan_addr,
                announcement.lan_addrs.to_owned(),
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
