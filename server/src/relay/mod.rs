use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use futures::future::join_all;
mod port_mapping;

pub struct Relay {
    a_ip: IpAddr,
    pub a_oport: u16,
    b_ip: IpAddr,
    b_oport: u16,
    relay_ip: IpAddr,
}

impl Relay {
    pub fn new(a_ip: IpAddr, a_oport: u16, b_ip: IpAddr, b_oport: u16, relay_ip: IpAddr) -> Self {
        Self {
            a_ip,
            a_oport,
            b_ip,
            b_oport,
            relay_ip,
        }
    }

    pub fn write_rules<Write: std::io::Write>(&self, writer: &mut Write) -> std::io::Result<()> {
        let rdr_to_1 = format!(
            //"pass in proto udp from {} port {} to {} port {} rdr-to {}\n",
            //self.a_ip, self.a_oport, self.relay_ip, self.b_oport, self.b_ip
            "pass in proto udp from {} to {} port {} rdr-to {}\n",
            self.a_ip, self.relay_ip, self.b_oport, self.b_ip
        );
        let nat_to_1 = format!(
            "pass out proto udp from {} to {} nat-to {} static-port\n",
            self.a_ip, self.b_ip, self.relay_ip
        );
        let rdr_to_2 = format!(
            "pass in proto udp from {} port {} to {} port {} rdr-to {}\n",
            self.b_ip, self.b_oport, self.relay_ip, self.a_oport, self.a_ip
        );
        let nat_to_2 = format!(
            "pass out proto udp from {} to {} nat-to {} static-port\n",
            self.b_ip, self.a_ip, self.relay_ip
        );
        writer.write_all(rdr_to_1.as_bytes())?;
        writer.write_all(nat_to_1.as_bytes())?;
        writer.write_all(rdr_to_2.as_bytes())?;
        writer.write_all(nat_to_2.as_bytes())?;

        Ok(())
    }
}

pub(crate) async fn get_relays(
    ip: &IpAddr,
    peers_info: HashMap<String, SocketAddr>,
) -> anyhow::Result<HashMap<String, Relay>> {
    let work = peers_info.iter().map(|(peer, peer_endpoint)| async move {
        let observed_source_port = port_mapping::detect_source_port(&ip, peer_endpoint.port())
            .await
            .ok();
        (
            peer.to_owned(),
            peer_endpoint.to_owned(),
            observed_source_port,
        )
    });

    let mut res = HashMap::new();
    join_all(work)
        .await
        .iter()
        .for_each(|(peer, peer_endpoint, observed_source_port)| {
            if let Some(port) = observed_source_port {
                let relay = Relay::new(
                    *ip,
                    *port,
                    peer_endpoint.ip(),
                    peer_endpoint.port(),
                    "1.1.1.1".parse().unwrap(),
                );
                res.insert(peer.to_owned(), relay);
            }
        });
    Ok(res)
}
