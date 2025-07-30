use chrono::Utc;
use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

use shared::{BINCODE_CONFIG, protocol};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};

use rustls::pki_types::pem::PemObject;
use tokio_rustls::{TlsAcceptor, rustls};

#[cfg(target_os = "openbsd")]
use openbsd::pledge;

pub mod config;
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

async fn handle_connection<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    storage: Storage,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 1024];
    stream.read(&mut buffer).await?;
    let (announcement, _): (protocol::WireplugAnnounce, usize) =
        bincode::decode_from_slice(&buffer[..], BINCODE_CONFIG)
            .map_err(|e| std::io::Error::other(format!("decoding error: {e}")))?;

    let announcer_ip = peer_addr.ip();
    if !announcement.valid() {
        stream.shutdown().await?;
        return Ok(());
    }

    let peer_wg_wan_addr = SocketAddr::new(peer_addr.ip(), announcement.listen_port);
    storage.write().await.insert(
        (
            announcement.initiator_pubkey.to_owned(),
            announcement.peer_pubkey.to_owned(),
        ),
        Record {
            wan_addr: peer_wg_wan_addr,
            lan_addrs: announcement.lan_addrs,
            timestamp: SystemTime::now(),
        },
    );

    let response = match storage
        .read()
        .await
        .get(&(announcement.peer_pubkey, announcement.initiator_pubkey))
        .cloned()
    {
        Some(record) => {
            if announcer_ip == record.wan_addr.ip() {
                protocol::WireplugResponse::from_lan_addrs(
                    record.lan_addrs.map_or(vec![], |v| v),
                    record.wan_addr.port(),
                )
            } else {
                protocol::WireplugResponse::from_sockaddr(record.wan_addr)
            }
        }
        None => protocol::WireplugResponse::new(),
    };

    let buffer = bincode::encode_to_vec(&response, BINCODE_CONFIG)
        .map_err(|e| std::io::Error::other(format!("encoding error: {e}")))?;
    stream.write_all(&buffer).await?;
    stream.shutdown().await?;

    Ok(())
}

async fn status(storage: &Storage) {
    print!("\x1B[2J\x1B[1;1H");
    println!("\n\nPeers:\n-----");
    for p in storage.read().await.iter() {
        let peer_a = &p.0.0;
        let peer_b = &p.0.1;
        let ip = p.1.wan_addr;
        let timestamp = &p.1.timestamp;
        let datetime: chrono::DateTime<Utc> = (*timestamp).into();
        println!("\t{peer_a} @{ip} -> {peer_b} | {datetime}");
    }
}

async fn start(cli: Cli) -> anyhow::Result<()> {
    #[cfg(target_os = "openbsd")]
    openbsd::pledge!("stdio inet rpath", "")?;
    //XXX: unveil here
    let config = config::read_from_file(&cli.config)?;
    let cert_path = PathBuf::from_str(&config.cert_path)?;
    let key_path = PathBuf::from_str(&config.key_path)?;

    let cert = CertificateDer::pem_file_iter(&cert_path)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(&key_path)?;

    #[cfg(target_os = "openbsd")]
    openbsd::pledge!("stdio inet", "")?;

    let storage: Storage = Arc::new(RwLock::new(HashMap::new()));
    let arc_mutex = Arc::new(Mutex::new(()));

    let s = Arc::clone(&storage);
    let mtx = Arc::clone(&arc_mutex);

    tokio::spawn(async move {
        loop {
            let _guard = mtx.lock().await;
            status(&s).await;
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });

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
        let mtx = Arc::clone(&arc_mutex);
        tokio::spawn(async move {
            let bind_to = format!("{stun_addr}:{}", shared::WIREPLUG_STUN_PORT);
            stun::start_serving(bind_to, mtx).await;
        });
    }

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let wp_listen_addr = format!("{}:443",config.wp_listen_on);
    let listener = TcpListener::bind(wp_listen_addr).await?;

    loop {
        let (socket, peer_addrs) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let s = Arc::clone(&storage);

        tokio::spawn(async move {
            let stream = match acceptor.accept(socket).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{e}");
                    return;
                }
            };
            if let Err(e) = handle_connection(stream, peer_addrs, s).await {
                eprintln!("{e}");
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
