use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bincode::config::Configuration;
use shared::{WireplugAnnounce, WireplugResponse};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

#[cfg(target_os = "openbsd")]
use openbsd::pledge;

type Storage = Arc<RwLock<HashMap<(String, String), IpAddr>>>;
const BINCODE_CONFIG : Configuration= bincode::config::standard();

async fn handle_connection(mut socket: TcpStream, storage: Storage) -> std::io::Result<()> {
    
    let mut buffer = [0u8; 1024];
    socket.read(&mut buffer).await?;
    let (hello, _): (WireplugAnnounce, usize)= bincode::decode_from_slice(&buffer[..], BINCODE_CONFIG)
        .map_err(|e| std::io::Error::new(ErrorKind::Other, format!("decoding error: {}" ,e.to_string())))?;

    let ip = socket.peer_addr()?;
    if !hello.valid() {
        //println!("got bs from {}" ,ip.to_string());
        socket.shutdown().await?;
        return Ok(());
    }

    storage.write().await.insert((hello.initiator_pubkey.to_owned(), hello.peer_pubkey.to_owned()), ip.ip());

    let ip = storage.read().await.get(&(hello.peer_pubkey, hello.initiator_pubkey)).copied();
    let hello = WireplugResponse::new(ip);
    let v = bincode::encode_to_vec(&hello, BINCODE_CONFIG)
        .map_err(|e| std::io::Error::new(ErrorKind::Other, format!("encoding error: {}" ,e.to_string())))?;
    socket.write_all(&v).await?;
    socket.shutdown().await?;

    Ok(())
}

async fn status(storage: &Storage) {
    print!("\x1B[2J\x1B[1;1H");
    println!("\n\nPeers:\n-----");
    for p in storage.read().await.iter(){
        let peer_a= &p.0.0;
        let peer_b = &p.0.1;
        let ip = p.1;
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
    let storage: Storage= Arc::new(RwLock::new(HashMap::new()));

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