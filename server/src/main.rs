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
    pub ip: SocketAddr,
    pub timestamp: SystemTime,
}
type Storage = Arc<RwLock<HashMap<(String, String), Record>>>;

async fn handle_connection(mut socket: TcpStream, storage: Storage) -> std::io::Result<()> {
    let mut buffer = [0u8; 1024];
    socket.read(&mut buffer).await?;
    let (announcement, _): (WireplugAnnounce, usize) =
        bincode::decode_from_slice(&buffer[..], BINCODE_CONFIG).map_err(|e| {
            std::io::Error::new(
                ErrorKind::Other,
                format!("decoding error: {}", e.to_string()),
            )
        })?;

    let announcer_ip = socket.peer_addr()?;
    if !announcement.valid() {
        //println!("got bs from {}", ip.to_string());
        socket.shutdown().await?;
        return Ok(());
    }

    let addr = SocketAddr::new(announcer_ip.ip(), announcement.listen_port);
    storage.write().await.insert(
        (
            announcement.initiator_pubkey.to_owned(),
            announcement.peer_pubkey.to_owned(),
        ),
        Record {
            ip: addr,
            timestamp: SystemTime::now(),
        },
    );

    let ip = match storage
        .read()
        .await
        .get(&(announcement.peer_pubkey, announcement.initiator_pubkey))
        .copied()
    {
        Some(record) => Some(record.ip),
        None => None,
    };
    let hello = WireplugResponse::new(ip);
    let v = bincode::encode_to_vec(&hello, BINCODE_CONFIG).map_err(|e| {
        std::io::Error::new(
            ErrorKind::Other,
            format!("encoding error: {}", e.to_string()),
        )
    })?;
    socket.write_all(&v).await?;
    socket.shutdown().await?;

    Ok(())
}

async fn status(storage: &Storage) {
    print!("\x1B[2J\x1B[1;1H");
    println!("\n\nPeers:\n-----");
    for p in storage.read().await.iter() {
        let peer_a = &p.0.0;
        let peer_b = &p.0.1;
        let ip = p.1.ip;
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
