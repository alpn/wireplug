use clap::Parser;
use shared::protocol::{WireplugEndpoint, WireplugResponse};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
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
use openbsd::pledge;

pub mod config;
pub mod status;
pub mod stun;

#[derive(Parser)]
#[command(version, name="wireplugd", about="", long_about = None)]
struct Cli {
    config: String,
}

#[derive(Clone)]
struct Record {
    pub wan_addr: SocketAddr,
    pub lan_addrs: Option<Vec<String>>,
    pub timestamp: SystemTime,
}
type Storage = Arc<RwLock<HashMap<(String, String), Record>>>;

const RECORD_TIMEOUT_SEC: u64 = 60 * 60;
static LOGGER: TmpLogger = TmpLogger;

async fn handle_connection<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    storage: Storage,
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
    let (announcement, _): (protocol::WireplugAnnounce, usize) =
        bincode::decode_from_slice(&buffer[..], BINCODE_CONFIG)?;

    let announcer_ip = peer_addr.ip();
    if !announcement.valid() {
        stream.shutdown().await?;
        return Ok(());
    }

    let peer_wg_wan_addr = SocketAddr::new(peer_addr.ip(), announcement.listen_port);
    {
        let mut storage_writer = storage.write().await;
        for peer in &announcement.peer_pubkeys {
            storage_writer.insert(
                (announcement.initiator_pubkey.to_owned(), peer.to_owned()),
                Record {
                    wan_addr: peer_wg_wan_addr,
                    lan_addrs: announcement.lan_addrs.to_owned(),
                    timestamp: SystemTime::now(),
                },
            );
        }
    }
    let mut res_peers = HashMap::new();
    {
        let storage_reader = storage.read().await;

        for peer in announcement.peer_pubkeys {
            let peer_endpoint;
            match storage_reader.get(&(peer.to_owned(), announcement.initiator_pubkey.to_owned())) {
                Some(record) => {
                    if announcer_ip == record.wan_addr.ip() {
                        peer_endpoint = WireplugEndpoint::LocalNetwork {
                            lan_addrs: record.lan_addrs.clone().map_or(vec![], |v| v),
                            listen_port: record.wan_addr.port(),
                        };
                    } else {
                        peer_endpoint = WireplugEndpoint::RemoteNetwork(record.wan_addr);
                    }
                }
                None => peer_endpoint = WireplugEndpoint::Unknown,
            }
            res_peers.insert(peer.to_owned(), peer_endpoint);
        }
    }
    let response = WireplugResponse::from_peer_endpoints(res_peers);
    let encoded_message = bincode::encode_to_vec(&response, BINCODE_CONFIG)?;
    let encoded_size_bytes: [u8; 4] = u32::try_from(encoded_message.len())?.to_le_bytes();

    stream.write_all(&encoded_size_bytes).await?;
    stream.write_all(&encoded_message).await?;

    stream.shutdown().await?;

    Ok(())
}

async fn start(cli: Cli) -> anyhow::Result<()> {
    #[cfg(target_os = "openbsd")]
    openbsd::pledge!("stdio inet rpath unix", "")?;
    log::set_max_level(log::LevelFilter::Trace);
    log::set_logger(&LOGGER).map_err(|e| anyhow::Error::msg(format!("set_logger(): {e}")))?;
    log::info!("starting wireplug server");
    //XXX: unveil here
    let config = config::read_from_file(&cli.config)?;
    let cert_path = PathBuf::from_str(&config.cert_path)?;
    let key_path = PathBuf::from_str(&config.key_path)?;

    let cert = CertificateDer::pem_file_iter(&cert_path)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(&key_path)?;
    #[cfg(target_os = "openbsd")]
    openbsd::pledge!("stdio inet unix", "")?;

    let storage: Storage = Arc::new(RwLock::new(HashMap::new()));
    match UnixStream::connect("/var/run/wireplugd.sock") {
        Ok(mut unix_stream) => {
            let s = Arc::clone(&storage);
            tokio::spawn(async move {
                if let Err(e) = status::write_to_socket(s, &mut unix_stream).await {
                    log::error!("{e}");
                }
            });
        }
        Err(e) => {
            log::warn!("{e}");
        }
    };
    #[cfg(target_os = "openbsd")]
    openbsd::pledge!("stdio inet", "")?;

    let s = Arc::clone(&storage);
    tokio::spawn(async move {
        loop {
            async {
                let now = SystemTime::now();
                s.write().await.retain(|_, record| {
                    if let Ok(record_duration) = now.duration_since(record.timestamp) {
                        if record_duration < Duration::from_secs(RECORD_TIMEOUT_SEC) {
                            return true;
                        }
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
    log::info!("serving peer discovery @{wp_listen_addr:?}");
    let listener = TcpListener::bind(wp_listen_addr).await?;

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let s = Arc::clone(&storage);

        tokio::spawn(async move {
            let stream = match acceptor.accept(socket).await {
                Ok(s) => s,
                Err(e) => {
                    log::error!("{e}");
                    return;
                }
            };

            log::info!("handling request over TLS from {peer_addr:?}");
            if let Err(e) = handle_connection(stream, peer_addr, s).await {
                log::error!("{e}");
            }
        });
    }
}

fn main() {
    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("could not build tokio runtime");

    if let Err(e) = rt.block_on(start(cli)) {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}
