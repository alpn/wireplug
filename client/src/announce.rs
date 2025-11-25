use shared::{
    self, BINCODE_CONFIG, WIREPLUG_ORG_WP,
    protocol::{self, WireplugResponse},
};
use std::{
    io::{Read, Write},
    net::TcpStream, time::Duration,
};
use wireguard_control::{Backend, Device, Key};

use crate::utils;

fn send_announcement<S: Read + Write>(
    stream: &mut S,
    announcement: protocol::WireplugAnnouncement,
) -> Result<protocol::WireplugResponse, std::io::Error> {
    let encoded_message = bincode::encode_to_vec(&announcement, BINCODE_CONFIG)
        .map_err(|e| std::io::Error::other(format!("encoding error: {e}")))?;

    let encoded_message_size: [u8; 4] = u32::try_from(encoded_message.len())
        .expect("Message length exceeds u32::MAX")
        .to_le_bytes();
    stream.write_all(&encoded_message_size)?;
    stream.write_all(&encoded_message)?;

    let mut length_bytes = [0u8; 4];
    stream.read_exact(&mut length_bytes)?;
    let encoded_length = u32::from_le_bytes(length_bytes) as usize;
    if encoded_length > shared::MAX_MESSAGE_SIZE {
        return Err(std::io::Error::other(format!(
            "Message size {} exceeds maximum allowed size of {}",
            encoded_length,
            shared::MAX_MESSAGE_SIZE
        )));
    }
    let mut encoded_message = vec![0u8; encoded_length];
    stream.read_exact(&mut encoded_message)?;

    let (response, _): (protocol::WireplugResponse, usize) =
        bincode::decode_from_slice(&encoded_message[..], BINCODE_CONFIG)
            .map_err(|e| std::io::Error::other(format!("encoding error: {e}")))?;

    Ok(response)
}

pub(crate) fn announce(
    if_name: &String,
    peers: &[Key],
    announcement_port: u16,
    lan_addrs: &Option<Vec<String>>,
) -> Result<WireplugResponse, std::io::Error> {
    let iface = if_name.parse()?;
    let device = Device::get(&iface, Backend::default())?;
    let Some(initiator_pubkey) = &device.public_key.clone() else {
        return Err(std::io::Error::other(format!(
            "{if_name} is not configured"
        )));
    };

    let mut socket = TcpStream::connect((WIREPLUG_ORG_WP, 443))?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut client_connection = utils::get_tls_client_connection(WIREPLUG_ORG_WP)
        .map_err(|e| std::io::Error::other(format!("failed to create TLS client: {e}")))?;
    let mut stream = rustls::Stream::new(&mut client_connection, &mut socket);

    let announcement = protocol::WireplugAnnouncement::new(
        &initiator_pubkey.to_base64(),
        peers.iter().map(|p| p.to_base64()).collect(),
        announcement_port,
        lan_addrs.to_owned(),
    );

    let response = send_announcement(&mut stream, announcement)?;
    if !response.valid() {
        return Err(std::io::Error::other("invalid response"));
    }
    Ok(response)
}
