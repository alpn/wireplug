use std::fmt::Write as OtherWrite;
use std::time::{Duration, SystemTime};

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

use crate::{SharedRelayManager, SharedStorage};

pub static MON_SOCK: &str = "/var/run/wpcod/wpcod.sock";

pub(crate) async fn start_writer(
    storage: SharedStorage,
    relay_manager: SharedRelayManager,
) -> anyhow::Result<()> {
    let mut prev_ok = true;
    loop {
        let mut writer = String::new();
        write!(writer, "\x1B[2J\x1B[1;1H")?;
        writeln!(writer, "\n\nPeers:\n-----")?;
        let now = SystemTime::now();
        {
            for p in storage.read().await.peering_records.iter() {
                let peer_a = &p.0.0;
                let peer_b = &p.0.1;
                let ip = p.1.wan_addr;
                let timestamp = &p.1.timestamp;
                let sec = now.duration_since(*timestamp)?.as_secs();
                writeln!(writer, "\t{peer_a} @{ip} -> {peer_b} | {sec} sec ago")?;
            }
        }
        writeln!(writer, "\n\nRelays:\n------")?;
        {
            relay_manager.read().await.debug(&mut writer)?;
        }
        match UnixStream::connect(MON_SOCK).await {
            Ok(mut unix_stream) => {
                if let Err(e) = unix_stream.write_all(writer.as_bytes()).await {
                    log::warn!("monitoring socket: {e}");
                } else {
                    prev_ok = true;
                }
            }
            Err(e) => {
                if prev_ok {
                    prev_ok = false;
                    log::warn!("failed to open monitoring socket: {e}");
                }
            }
        };
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
