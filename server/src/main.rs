use clap::Parser;
use shared::protocol::WireplugResponse;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use shared::{BINCODE_CONFIG, TmpLogger, protocol};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use rustls::pki_types::pem::PemObject;
use tokio_rustls::{TlsAcceptor, rustls};

#[cfg(target_os = "openbsd")]
use openbsd::{pledge, unveil};

use crate::peering::{SharedStorage, Storage};
use crate::relay::SharedRelayManager;

pub mod config;
#[cfg(target_os = "openbsd")]
pub mod lockdown;
pub mod peering;
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

const RECORD_TIMEOUT_SEC: u64 = 60 * 60;
static LOGGER: TmpLogger = TmpLogger;

async fn handle_connection<S>(
    mut stream: S,
    announcing_peer_addr: SocketAddr,
    storage: peering::SharedStorage,
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

    let res_peers =
        peering::get_peer_endpoints(&announcement, announcing_peer_addr, &storage, relay_manager)
            .await;

    let response = WireplugResponse::from_peer_endpoints(res_peers);
    let encoded_message = bincode::encode_to_vec(&response, BINCODE_CONFIG)?;
    let encoded_size_bytes: [u8; 4] = u32::try_from(encoded_message.len())?.to_le_bytes();

    stream.write_all(&encoded_size_bytes).await?;
    stream.write_all(&encoded_message).await?;

    stream.shutdown().await?;

    peering::process_announcement(&announcement, announcing_peer_addr, &storage).await?;

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
            if let Err(e) = peering::remove_old_records(&s).await {
                log::error!("{e}");
            };
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
