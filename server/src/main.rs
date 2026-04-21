use clap::Parser;
use shared::protocol::{WireplugEndpoint, WireplugResponse};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use shared::{BINCODE_CONFIG, TmpLogger, protocol};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use rustls::pki_types::pem::PemObject;
use tokio_rustls::{TlsAcceptor, rustls};

#[cfg(target_os = "openbsd")]
use openbsd::{pledge, unveil};

use crate::relay::{RelayKind, RelayManager};

pub mod config;
#[cfg(target_os = "openbsd")]
pub mod lockdown;
pub mod relay;
pub mod status;
pub mod stun;

#[derive(Parser)]
#[command(version, name="wpcod", about="", long_about = None)]
struct Cli {
    #[arg(short, long, help = "do not daemonize")]
    debug: bool,
    #[arg(short, long)]
    monitor: bool,
}

#[derive(Clone)]
struct Record {
    pub wan_addr: SocketAddr,
    pub lan_addrs: Option<Vec<String>>,
    pub timestamp: SystemTime,
    pub needs_relay: bool,
}

impl Record {
    fn new(
        wan_addr: SocketAddr,
        lan_addrs: Option<Vec<String>>,
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
struct Storage {
    peering_records: PeeringRecords,
}

impl Storage {
    fn new() -> Self {
        Self {
            peering_records: HashMap::new(),
        }
    }
}

type SharedStorage = Arc<RwLock<Storage>>;
type SharedRelayManager = Arc<RwLock<RelayManager>>;

const RECORD_TIMEOUT_SEC: u64 = 60 * 60;
static LOGGER: TmpLogger = TmpLogger;

async fn handle_connection<S>(
    mut stream: S,
    announcing_peer_addr: SocketAddr,
    storage: SharedStorage,
    relay_manager: SharedRelayManager,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let encoded_length = usize::try_from(stream.read_u32_le().await?)?;
    if encoded_length > shared::MAX_MESSAGE_SIZE {
        return Err(anyhow::anyhow!(
            "Message size {} exceeds maximum allowed size of {}",
            encoded_length,
            shared::MAX_MESSAGE_SIZE
        ));
    }

    let mut buffer = [0u8; shared::MAX_MESSAGE_SIZE];
    stream.read_exact(&mut buffer[0..encoded_length]).await?;
    let (announcement, _): (protocol::WireplugAnnouncement, usize) =
        bincode::decode_from_slice(&buffer[..], BINCODE_CONFIG)?;

    if !announcement.valid() {
        stream.shutdown().await?;
        return Ok(());
    }

    let mut res_peers = HashMap::new();
    {
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
                            lan_addrs: record.lan_addrs.clone().map_or(vec![], |v| v),
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
    }

    let response = WireplugResponse::from_peer_endpoints(res_peers);
    let encoded_message = bincode::encode_to_vec(&response, BINCODE_CONFIG)?;
    let encoded_size_bytes: [u8; 4] = u32::try_from(encoded_message.len())?.to_le_bytes();

    stream.write_all(&encoded_size_bytes).await?;
    stream.write_all(&encoded_message).await?;

    stream.shutdown().await?;

    let peer_wg_wan_addr = SocketAddr::new(announcing_peer_addr.ip(), announcement.listen_port);
    {
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
    }

    Ok(())
}

async fn start(cli: Cli) -> anyhow::Result<()> {
    #[cfg(target_os = "openbsd")]
    lockdown::step1()?;
    log::set_max_level(log::LevelFilter::Trace);
    log::set_logger(&LOGGER).map_err(|e| anyhow::Error::msg(format!("set_logger(): {e}")))?;
    log::info!("starting wireplug server");

    let config = config::read_from_file()?;
    let cert_path = PathBuf::from_str(&config.cert_path)?;
    let key_path = PathBuf::from_str(&config.key_path)?;

    let cert = CertificateDer::pem_file_iter(&cert_path)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(&key_path)?;

    let storage: SharedStorage = Arc::new(RwLock::new(Storage::new()));
    let relay_manager = Arc::new(RwLock::new(relay::RelayManager::new()));

    if cli.monitor {
        let s = Arc::clone(&storage);
        let rm = Arc::clone(&relay_manager);
        tokio::spawn(async move {
            if let Err(e) = status::start_writer(s, rm).await {
                log::error!("{e}");
            }
        });
    }

    let s = Arc::clone(&storage);
    tokio::spawn(async move {
        loop {
            async {
                let now = SystemTime::now();
                s.write().await.peering_records.retain(|_, record| {
                    if let Ok(record_duration) = now.duration_since(record.timestamp)
                        && record_duration < Duration::from_secs(RECORD_TIMEOUT_SEC)
                    {
                        return true;
                    }
                    false
                });
            }
            .await;
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });

    for stun_addr in config.stun_listen_on {
        log::info!("spawning STUN service @{stun_addr:?}");
        tokio::spawn(async move {
            let bind_to = format!("{stun_addr}:{}", shared::WIREPLUG_STUN_PORT);
            stun::start_serving(bind_to).await;
        });
    }

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let wp_listen_addr = format!("{}:443", config.wp_listen_on);
    let listener = TcpListener::bind(&wp_listen_addr).await?;
    log::info!("serving peer discovery @{wp_listen_addr:?}");
    #[cfg(target_os = "openbsd")]
    lockdown::step2(cli.monitor)?;

    loop {
        let (socket, peer_addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                log::error!("{e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let s = Arc::clone(&storage);
        let rm = Arc::clone(&relay_manager);

        tokio::spawn(async move {
            let stream = match acceptor.accept(socket).await {
                Ok(s) => s,
                Err(e) => {
                    log::error!("{e}");
                    return;
                }
            };

            log::info!("handling request over TLS from {peer_addr:?}");
            if let Err(e) = handle_connection(stream, peer_addr, s, rm).await {
                log::error!("{e}");
            }
        });
    }
}

fn main() {
    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("could not build tokio runtime");

    #[cfg(target_os = "openbsd")]
    if !cli.debug {
        if let Err(e) = shared::daemonize() {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }

    if let Err(e) = rt.block_on(start(cli)) {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}
