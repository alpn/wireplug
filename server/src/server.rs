use std::{fmt::Write, net::SocketAddr, sync::Arc};

use shared::protocol::{self, WireplugResponse};
use tokio::net::TcpListener;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::RwLock,
};
use tokio_rustls::TlsAcceptor;

use crate::{
    peering::{self, SharedStorage},
    relay::SharedRelayManager,
};

pub(crate) struct ServerStats {
    tls_errros: usize,
    relays_needed: usize,
}

pub(crate) type SharedServerStats = Arc<RwLock<ServerStats>>;

impl ServerStats {
    pub(crate) fn new() -> Self {
        Self {
            tls_errros: 0,
            relays_needed: 0,
        }
    }
    fn inc_tls_errors(&mut self) {
        self.tls_errros += 1;
    }
    fn inc_relays_needed(&mut self) {
        self.relays_needed += 1;
    }
    pub fn write_to<W: Write>(&self, writer: &mut W) -> std::fmt::Result {
        writeln!(writer, "tls errors: {}", self.tls_errros)?;
        writeln!(writer, "relays needed: {}", self.relays_needed)?;
        Ok(())
    }
}

async fn handle_connection<S>(
    mut stream: S,
    announcing_peer_addr: SocketAddr,
    storage: peering::SharedStorage,
    relay_manager: SharedRelayManager,
    server_stats: SharedServerStats,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[..3] != protocol::WIREPLUG_PROTOCOL_MAGIC {
        stream.shutdown().await?;
        return Ok(());
    }
    if header[3..] != protocol::WIREPLUG_PROTOCOL_VERSION {
        stream.write_all(&protocol::WIREPLUG_PROTOCOL_MAGIC).await?;
        stream
            .write_all(&protocol::WIREPLUG_PROTOCOL_VERSION)
            .await?;

        stream.shutdown().await?;
        return Ok(());
    }
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
    let announcement: protocol::WireplugAnnouncement = postcard::from_bytes(&buffer)?;

    if !announcement.valid() {
        stream.shutdown().await?;
        return Ok(());
    }

    let res_peers =
        peering::get_peer_endpoints(&announcement, announcing_peer_addr, &storage, relay_manager)
            .await;

    let response = WireplugResponse::from_peer_endpoints(res_peers);
    let encoded_message = postcard::to_allocvec(&response)?;
    let encoded_size_bytes: [u8; 4] = u32::try_from(encoded_message.len())?.to_le_bytes();

    stream.write_all(&protocol::WIREPLUG_PROTOCOL_MAGIC).await?;
    stream
        .write_all(&protocol::WIREPLUG_PROTOCOL_VERSION)
        .await?;
    stream.write_all(&encoded_size_bytes).await?;
    stream.write_all(&encoded_message).await?;

    stream.shutdown().await?;

    peering::process_announcement(&announcement, announcing_peer_addr, &storage).await?;

    if announcement.needs_relay {
        server_stats.write().await.inc_relays_needed();
    }
    Ok(())
}

pub(crate) async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    storage: &SharedStorage,
    relay_manager: SharedRelayManager,
    server_stats: SharedServerStats,
) {
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
        let ss = Arc::clone(&server_stats);

        tokio::spawn(async move {
            let stream = match acceptor.accept(socket).await {
                Ok(s) => s,
                Err(e) => {
                    log::error!("tls acceptor: {e}");
                    ss.write().await.inc_tls_errors();
                    return;
                }
            };

            log::info!("handling request over TLS from {peer_addr:?}");
            if let Err(e) = handle_connection(stream, peer_addr, s, rm, ss).await {
                log::error!("{e}");
            }
        });
    }
}
