use std::fmt::Write as OtherWrite;
use std::time::Duration;

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
        {
            let s = storage.read().await;
            s.debug(&mut writer)?;
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
