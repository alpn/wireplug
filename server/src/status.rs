use std::fmt::Write as OtherWrite;
use std::time::Duration;

use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio::{io::AsyncWriteExt, net::UnixListener};

use crate::{SharedRelayManager, SharedStorage, server::SharedServerStats};

pub(crate) static MON_SOCK: &str = "/var/run/wpcod.sock";

pub(crate) async fn start_writer(
    unix_listener: UnixListener,
    storage: SharedStorage,
    relay_manager: SharedRelayManager,
    server_stats: SharedServerStats,
) -> anyhow::Result<()> {
    let clients = std::sync::Arc::new(Mutex::new(Vec::<UnixStream>::new()));
    let c = std::sync::Arc::clone(&clients);
    tokio::spawn(async move {
        loop {
            match unix_listener.accept().await {
                Ok((s, _)) => {
                    log::warn!("new monitoring client connected");
                    c.lock().await.push(s);
                }
                Err(e) => {
                    log::warn!("monitoring client failed to connect: {e}");
                }
            }
        }
    });
    loop {
        let mut writer = String::new();
        write!(writer, "\x1B[2J\x1B[1;1H")?;
        writeln!(writer, "\n\nPeers:\n-----")?;
        storage.read().await.write_to(&mut writer)?;
        writeln!(writer, "\n\nRelays:\n------")?;
        relay_manager.read().await.write_to(&mut writer)?;
        writeln!(writer, "\n\nStats:\n------")?;
        server_stats.read().await.write_to(&mut writer)?;

        let mut guard = clients.lock().await;
        let mut kept_clients = vec![];
        for mut c in guard.drain(..) {
            if let Err(e) = c.write_all(writer.as_bytes()).await {
                log::warn!("bad monitoring client {e}");
            } else {
                kept_clients.push(c);
            }
        }
        *guard = kept_clients;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
