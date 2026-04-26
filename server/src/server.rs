use std::{net::SocketAddr, sync::Arc};

use shared::{
    BINCODE_CONFIG,
    protocol::{self, WireplugResponse},
};
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
}

pub(crate) type SharedServerStats = Arc<RwLock<ServerStats>>;

impl ServerStats {
    pub(crate) fn new() -> Self {
        Self { tls_errros: 0 }
    }

    fn inc_tls_errors(&mut self) {
        self.tls_errros += 1;
    }
    pub fn get_tls_errors(&self) -> usize {
        self.tls_errros
    }
}

async fn handle_connection<S>(
    mut stream: S,
    announcing_peer_addr: SocketAddr,
    storage: peering::SharedStorage,
    relay_manager: SharedRelayManager,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
    let (announcement, _): (protocol::WireplugAnnouncement, usize) =
        bincode::decode_from_slice(&buffer[..], BINCODE_CONFIG)?;

    if !announcement.valid() {
        stream.shutdown().await?;
        return Ok(());
    }

    let res_peers =
        peering::get_peer_endpoints(&announcement, announcing_peer_addr, &storage, relay_manager)
            .await;

    let response = WireplugResponse::from_peer_endpoints(res_peers);
    let encoded_message = bincode::encode_to_vec(&response, BINCODE_CONFIG)?;
    let encoded_size_bytes: [u8; 4] = u32::try_from(encoded_message.len())?.to_le_bytes();

    stream.write_all(&encoded_size_bytes).await?;
    stream.write_all(&encoded_message).await?;

    stream.shutdown().await?;

    peering::process_announcement(&announcement, announcing_peer_addr, &storage).await?;

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
            if let Err(e) = handle_connection(stream, peer_addr, s, rm).await {
                log::error!("{e}");
            }
        });
    }
}
