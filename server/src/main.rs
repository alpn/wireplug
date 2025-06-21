use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use shared::{BINCODE_CONFIG, WireplugAnnounce, WireplugResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

#[cfg(target_os = "openbsd")]
use openbsd::pledge;

#[derive(Clone, Copy)]
struct Record {
    pub endpoint: SocketAddr,
    pub timestamp: SystemTime,
}
type Storage = Arc<RwLock<HashMap<(String, String), Record>>>;

async fn handle_connection(mut stream: TcpStream, storage: Storage) -> std::io::Result<()> {
    let mut buffer = [0u8; 1024];
    stream.read(&mut buffer).await?;
    let (announcement, _): (WireplugAnnounce, usize) =
        bincode::decode_from_slice(&buffer[..], BINCODE_CONFIG).map_err(|e| {
            std::io::Error::new(
                ErrorKind::Other,
                format!("decoding error: {}", e.to_string()),
            )
        })?;

    let announcer_ip = stream.peer_addr()?;
    if !announcement.valid() {
        //println!("got bs from {}", ip.to_string());
        stream.shutdown().await?;
        return Ok(());
    }

    let addr = SocketAddr::new(announcer_ip.ip(), announcement.listen_port);
    storage.write().await.insert(
        (
            announcement.initiator_pubkey.to_owned(),
            announcement.peer_pubkey.to_owned(),
        ),
        Record {
            endpoint: addr,
            timestamp: SystemTime::now(),
        },
    );

    let peer_endpoint = match storage
        .read()
        .await
        .get(&(announcement.peer_pubkey, announcement.initiator_pubkey))
        .copied()
    {
        Some(record) => Some(record.endpoint),
        None => None,
    };
    let response = WireplugResponse::new(peer_endpoint);
    let buffer = bincode::encode_to_vec(&response, BINCODE_CONFIG).map_err(|e| {
        std::io::Error::new(
            ErrorKind::Other,
            format!("encoding error: {}", e.to_string()),
        )
    })?;
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
        let ip = p.1.endpoint;
        println!("\t{peer_a} @{ip}");
        println!("\ttell {peer_b}");
    }
}
#[tokio::main]
async fn main() -> std::io::Result<()> {
    #[cfg(target_os = "openbsd")]
    openbsd::pledge!("stdio inet", "").map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("pledge: {}", e.to_string()),
        )
    })?;

    let listener = TcpListener::bind("0.0.0.0:4455").await?;
    let storage: Storage = Arc::new(RwLock::new(HashMap::new()));

    let s = Arc::clone(&storage);
    tokio::spawn(async move {
        loop {
            status(&s).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    loop {
        let (socket, _) = listener.accept().await?;
        let s = Arc::clone(&storage);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, s).await {
                eprintln!("{e}");
            }
        });
    }
}
