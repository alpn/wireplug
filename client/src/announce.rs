use shared::{
    self, WIREPLUG_ORG_WP,
    protocol::{self, WireplugResponse},
};
use std::{
    io::{Read, Write},
    net::TcpStream,
    process,
    time::Duration,
};
use wireguard_control::{Backend, Device, Key};

use crate::{netstat::NetInfo, utils};

fn send_announcement<S: Read + Write>(
    stream: &mut S,
    announcement: protocol::WireplugAnnouncement,
) -> Result<protocol::WireplugResponse, std::io::Error> {
    stream.write_all(&protocol::WIREPLUG_PROTOCOL_MAGIC)?;
    stream.write_all(&protocol::WIREPLUG_PROTOCOL_VERSION)?;

    let encoded_message = postcard::to_allocvec(&announcement)
        .map_err(|e| std::io::Error::other(format!("encoding error: {e}")))?;

    let encoded_message_size: [u8; 4] = u32::try_from(encoded_message.len())
        .expect("Message length exceeds u32::MAX")
        .to_le_bytes();
    stream.write_all(&encoded_message_size)?;
    stream.write_all(&encoded_message)?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    if header[..3] != protocol::WIREPLUG_PROTOCOL_MAGIC {
        return Err(std::io::Error::other("bad message"));
    }
    if header[3..] != protocol::WIREPLUG_PROTOCOL_VERSION {
        log::warn!("You're running an outdated version of wireplugd.");
        log::warn!("Please update to the latest version to continue using the service.");
        // XXX needs to return custom error so we can kill wireguard-go before we go down
        process::exit(1);
    }

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

    let response: protocol::WireplugResponse = postcard::from_bytes(&encoded_message)
        .map_err(|e| std::io::Error::other(format!("encoding error: {e}")))?;

    Ok(response)
}

pub(crate) fn announce(
    if_name: &String,
    peers: &[Key],
    announcement_port: u16,
    netinfo: &NetInfo,
    needs_relay: bool,
) -> Result<WireplugResponse, std::io::Error> {
    let iface = if_name.parse()?;
    let device = Device::get(&iface, Backend::default())?;
    let Some(initiator_pubkey) = &device.public_key.clone() else {
        return Err(std::io::Error::other(format!(
            "{if_name} is not configured"
        )));
    };

    let mut socket = TcpStream::connect((WIREPLUG_ORG_WP, shared::WIREPLUG_WPCOD_PORT))?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    let mut client_connection = utils::get_tls_client_connection(WIREPLUG_ORG_WP)
        .map_err(|e| std::io::Error::other(format!("failed to create TLS client: {e}")))?;
    let mut stream = rustls::Stream::new(&mut client_connection, &mut socket);

    let announcement = protocol::WireplugAnnouncement::new(
        &initiator_pubkey.to_base64(),
        peers.iter().map(|p| p.to_base64()).collect(),
        netinfo.wan_ipv6,
        announcement_port,
        netinfo.lan_addrs.clone(),
        needs_relay,
    );

    let response = send_announcement(&mut stream, announcement)?;
    if !response.valid() {
        return Err(std::io::Error::other("invalid response"));
    }
    Ok(response)
}
