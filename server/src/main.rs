use clap::Parser;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use shared::TmpLogger;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use rustls::pki_types::pem::PemObject;
use tokio_rustls::{TlsAcceptor, rustls};

#[cfg(target_os = "openbsd")]
use openbsd::{pledge, unveil};

use crate::peering::{SharedStorage, Storage};
use crate::relay::SharedRelayManager;
use crate::server::ServerStats;

pub mod config;
#[cfg(target_os = "openbsd")]
pub mod lockdown;
pub mod peering;
pub mod relay;
pub mod server;
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

static LOGGER: TmpLogger = TmpLogger;

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
    let server_stats = Arc::new(RwLock::new(server::ServerStats::new()));

    if cli.monitor {
        let s = Arc::clone(&storage);
        let rm = Arc::clone(&relay_manager);
        let ss = Arc::clone(&server_stats);
        tokio::spawn(async move {
            if let Err(e) = status::start_writer(s, rm, ss).await {
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

    #[cfg(target_os = "openbsd")]
    lockdown::step2(cli.monitor)?;

    log::info!("serving peer discovery @{wp_listen_addr:?}");
    server::serve(listener, acceptor, &storage, relay_manager, server_stats).await;

    Ok(())
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
