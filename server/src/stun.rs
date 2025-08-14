use std::sync::Arc;

use shared::{BINCODE_CONFIG, protocol};
use tokio::{net::UdpSocket, sync::Mutex};

pub async fn start_serving(bind_to: String, mtx: Arc<Mutex<()>>) {
    let socket = match UdpSocket::bind(bind_to).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("{e}");
            return;
        }
    };
    let socket = Arc::new(socket);
    let mut buf = [0u8; 1024];
    loop {
        let addr = match socket.recv_from(&mut buf).await {
            Ok((_, addr)) => addr,
            Err(e) => {
                log::error!("{e}");
                continue;
            }
        };
        log::debug!("udp test from addr: {:?}", &addr);
        let observed_port = addr.port();
        let socket = Arc::clone(&socket);
        let mtx = Arc::clone(&mtx);
        tokio::spawn(async move {
            let udp_test_request: protocol::WireplugStunRequest =
                match bincode::decode_from_slice(&buf[..], BINCODE_CONFIG) {
                    Ok((req, _)) => req,
                    Err(e) => {
                        log::error!("{e}");
                        return;
                    }
                };

            let _guard = mtx.lock().await;
            log::debug!("stated port: {}", udp_test_request.port);
            log::debug!("observed port: {observed_port}");
            let udp_test_response = match observed_port == udp_test_request.port {
                true => protocol::WireplugStunResponse::new(None),
                false => protocol::WireplugStunResponse::new(Some(observed_port)),
            };

            let data = match bincode::encode_to_vec(udp_test_response, BINCODE_CONFIG) {
                Ok(data) => data,
                Err(e) => {
                    log::error!("{e}");
                    return;
                }
            };
            let _ = socket.send_to(&data, addr).await.map_err(|e| {
                log::error!("{e}");
            });
        });
    }
}
