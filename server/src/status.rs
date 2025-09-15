use std::fmt::Write as OtherWrite;
use std::io::Write;
use std::{
    os::unix::net::UnixStream,
    time::{Duration, SystemTime},
};

use crate::Storage;

pub(crate) async fn write_to_socket(
    storage: Storage,
    unix_stream: &mut UnixStream,
) -> anyhow::Result<()> {
    loop {
        let mut writer = String::new();
        write!(writer, "\x1B[2J\x1B[1;1H")?;
        writeln!(writer, "\n\nPeers:\n-----")?;
        let now = SystemTime::now();
        {
            for p in storage.read().await.iter() {
                let peer_a = &p.0.0;
                let peer_b = &p.0.1;
                let ip = p.1.wan_addr;
                let timestamp = &p.1.timestamp;
                let sec = now.duration_since(*timestamp).unwrap().as_secs();
                writeln!(writer, "\t{peer_a} @{ip} -> {peer_b} | {sec} sec ago")?;
            }
        }
        unix_stream.write_all(writer.as_bytes())?;
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
