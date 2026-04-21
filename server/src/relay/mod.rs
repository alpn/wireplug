use futures::future::join_all;
use std::{collections::HashMap, fmt::Write, net::IpAddr};
mod port_mapping;

pub struct ProtoRelay {
    a_ip: IpAddr,
    pub relay_port: u16,
}

pub struct PendingRelay {
    pub a_ip: IpAddr,
    pub a_oport: u16,
    pub relay_port: u16,
}

impl PendingRelay {
    pub fn new(a_ip: IpAddr, a_oport: u16, relay_port: u16) -> Self {
        Self {
            a_ip,
            a_oport,
            relay_port,
        }
    }
}

pub struct EstablishedRelay {
    a_ip: IpAddr,
    pub a_oport: u16,
    b_ip: IpAddr,
    b_oport: u16,
    relay_ip: IpAddr,
    pub relay_port: u16,
}

impl EstablishedRelay {
    pub fn new(
        a_ip: IpAddr,
        a_oport: u16,
        b_ip: IpAddr,
        b_oport: u16,
        relay_ip: IpAddr,
        relay_port: u16,
    ) -> Self {
        Self {
            a_ip,
            a_oport,
            b_ip,
            b_oport,
            relay_ip,
            relay_port,
        }
    }
}

pub trait WriteTo {
    fn write_to<Write: std::io::Write>(&self, writer: &mut Write) -> std::io::Result<()>;
}

pub enum RelayKind {
    Proto(u16),
    Pending(u16),
    Established(u16),
}

#[derive(PartialEq, PartialOrd, Eq, Clone, Hash)]
pub struct Key(pub [u8; 32]);
#[derive(PartialEq, PartialOrd, Eq, Clone, Hash)]
pub struct NormalizedKey(pub [u8; 64]);

// XXX
fn tmp_string_to_bytes(_s: &String) -> [u8; 32] {
    let out = [0u8; 32];
    out
}

// XXX
//fn get_normalized(a: Key, b: Key) -> NormalizedKey {
fn get_normalized(a: &String, b: &String) -> NormalizedKey {
    let a = tmp_string_to_bytes(a);
    let b = tmp_string_to_bytes(b);
    let mut out = [0u8; 64];
    if a <= b {
        out[..32].copy_from_slice(a.as_slice());
        out[32..].copy_from_slice(b.as_slice());
    } else {
        out[..32].copy_from_slice(b.as_slice());
        out[32..].copy_from_slice(a.as_slice());
    }
    NormalizedKey(out)
}

pub struct RelayManager {
    proto: HashMap<(String, String), ProtoRelay>,
    pending: HashMap<(String, String), PendingRelay>,
    established: HashMap<NormalizedKey, EstablishedRelay>,
}

impl RelayManager {
    pub fn new() -> Self {
        Self {
            proto: HashMap::new(),
            pending: HashMap::new(),
            established: HashMap::new(),
        }
    }

    pub fn get_relay_port(
        &mut self,
        peer_a: &String,
        peer_b: &String,
        announcing_ip: IpAddr,
    ) -> RelayKind {
        let normalized_key = get_normalized(peer_a, peer_b);
        if let Some(relay) = self.established.get(&normalized_key) {
            return RelayKind::Established(relay.relay_port);
        }
        if let Some(relay) = self.pending.get(&(peer_a.to_string(), peer_b.to_string())) {
            return RelayKind::Pending(relay.relay_port);
        }
        if let Some(relay) = self.proto.get(&(peer_a.to_string(), peer_b.to_string())) {
            return RelayKind::Proto(relay.relay_port);
        }
        // the non-announcing peer is already pending so use the same port
        let port = if let Some(relay) = self.pending.get(&(peer_b.to_string(), peer_a.to_string()))
        {
            relay.relay_port
        } else {
            0u16 // XXX get_free_random_port()
        };
        self.proto.insert(
            (peer_a.to_string(), peer_b.to_string()),
            ProtoRelay {
                a_ip: announcing_ip,
                relay_port: port,
            },
        );
        RelayKind::Proto(port)
    }

    // XXX
    pub(crate) async fn wait_for_protos(&mut self) -> std::io::Result<()> {
        let work = self.proto.drain().map(|((a, b), proto)| async move {
            match port_mapping::detect_source_port(&proto.a_ip, proto.relay_port)
                .await
                .ok()
            {
                Some(observed_source_port) => Some((
                    (a, b),
                    PendingRelay::new(proto.a_ip, observed_source_port, proto.relay_port),
                )),
                None => None,
            }
        });

        join_all(work).await.iter().for_each(|thing| {
            if let Some(((a, b), pending)) = thing {
                // XXX
                // if we got a port:
                //  if we have a matching pending, establish (pf) and promote to established
                //  else promote to pending
            };
        });

        Ok(())
    }

    pub fn remove_for_pair(&mut self, peer_a: &String, peer_b: &String) {
        // remove peers' protos and pending
        // destroy (pf) and remove established
    }

    pub fn debug<W: Write>(&self, writer: &mut W) -> std::fmt::Result {
        for ((a, b), r) in &self.proto {
            let ip = r.a_ip.to_string();
            let port = r.relay_port;
            writeln!(writer, "{a} => {b} waiting for {ip} on port:{port} (proto)")?;
        }
        for ((a, b), r) in &self.pending {
            let ip = r.a_ip.to_string();
            let port = r.a_oport;
            writeln!(writer, "{a} => {b} {ip}:{port} (pending)")?;
        }
        for (_, r) in &self.established {
            writeln!(
                writer,
                "{}:{} <=> {}:{} (established)",
                r.a_ip, r.a_oport, r.b_ip, r.b_oport
            )?;
        }
        Ok(())
    }
}

/*
/////////////////////////////////////////////////////////////////////////////////////////////
*/

impl WriteTo for EstablishedRelay {
    fn write_to<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
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

fn get_free_random_port() -> u16 {
    todo!()
}
