use std::{
    collections::HashSet,
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
};

use ipnet::IpNet;

use n0_future::StreamExt;
use n0_watcher::{self, Watcher};

use crate::utils;

#[derive(Default, Debug, Clone)]
pub(crate) struct NetInfo {
    wan_ipv4: Option<Ipv4Addr>,
    pub(crate) wan_ipv6: Option<Ipv6Addr>,
    pub(crate) lan_addrs: Vec<IpNet>,
    pub(crate) hard_nat: bool,
    /*
    default_gateway: String,
    dns_server: String,
     */
}

impl PartialEq for NetInfo {
    fn eq(&self, other: &Self) -> bool {
        self.wan_ipv4 == other.wan_ipv4
            && self.wan_ipv6 == other.wan_ipv6
            && self.lan_addrs == other.lan_addrs
    }
}

impl Display for NetInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\tPublic IPv4: ")?;
        if let Some(ip) = self.wan_ipv4 {
            writeln!(f, "{ip}")?;
        } else {
            writeln!(f, "N/A")?;
        }
        write!(f, "\tPublic IPv6: ")?;
        if let Some(ip) = self.wan_ipv6 {
            writeln!(f, "{ip}")?;
        } else {
            writeln!(f, "N/A")?;
        }
        for l in &self.lan_addrs {
            writeln!(f, "\tLAN IP: {:?}", l)?;
        }
        write!(f, "\tNAT: ")?;
        match self.hard_nat {
            true => writeln!(f, "relay required")?,
            false => writeln!(f, "easy")?,
        };
        Ok(())
    }
}
impl NetInfo {
    fn detect(if_name: &str) -> Self {
        let (mut wan_ipv4, mut wan_ipv6) = innernet_publicip::get_both();
        if wan_ipv4.is_none() && wan_ipv6.is_none() {
            (wan_ipv4, wan_ipv6) = utils::get_ip64_over_https();
            if wan_ipv4.is_some() || wan_ipv6.is_some() {
                log::warn!(
                    "Network: quad9 is unreachable, ip found via HTTPS {:?} / {:?}",
                    wan_ipv4,
                    wan_ipv6
                );
            }
        }
        let lan_addrs = match utils::get_lan_addrs(if_name) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("could not get LAN addresses: {e}");
                vec![]
            }
        };
        NetInfo {
            wan_ipv4,
            wan_ipv6,
            lan_addrs,
            hard_nat: false,
        }
    }
    pub(crate) fn online(&self) -> bool {
        self.wan_ipv4.is_some() || self.wan_ipv6.is_some()
    }
    pub(crate) fn offline(&self) -> bool {
        !self.online()
    }
}

pub(crate) struct NetworkMonitor {
    nw_monitor: netwatch::netmon::Monitor,
    current: NetInfo,
    last_online: Option<NetInfo>,
    wg_if_name: String,
}

impl NetworkMonitor {
    pub async fn new(wg_if_name: &str) -> anyhow::Result<Self> {
        let nm = netwatch::netmon::Monitor::new().await?;
        Ok(Self {
            nw_monitor: nm,
            current: NetInfo::default(),
            last_online: None,
            wg_if_name: wg_if_name.to_owned(),
        })
    }
    pub fn set_hard_nat(&mut self, hard_nat: bool) {
        self.current.hard_nat = hard_nat;
    }
    pub async fn monitor_endpoint_change(&mut self) -> anyhow::Result<()> {
        if self.last_online.is_none() && self.detect_public_ip_change() {
            return Ok(());
        }
        let mut nw_stream = self.nw_monitor.interface_state().stream_updates_only();
        loop {
            let Some(state) = nw_stream.next().await else {
                return Err(anyhow::anyhow!(
                    "netmon: stream has ended due to underlying actor shutting down"
                ));
            };
            let Some(default_route_interface_name) = state.default_route_interface else {
                log::warn!("netmon: no deafult route");
                continue;
            };

            let Some(default_route_interface) = state.interfaces.get(&default_route_interface_name)
            else {
                log::warn!("netmon: could not get deafult route interface");
                continue;
            };

            if self.current.lan_addrs.is_empty() {
                log::warn!("netmon: no LAN address");
                continue;
            }

            let current_lan_set: HashSet<_> = self
                .current
                .lan_addrs
                .clone()
                .into_iter()
                .filter_map(|addr| match addr {
                    IpNet::V4(ipv4_net) => Some(ipv4_net),
                    IpNet::V6(_) => None,
                })
                .collect();

            let new_lan_set: HashSet<_> = default_route_interface
                .addrs()
                .filter_map(|addr| match addr {
                    netwatch::interfaces::IpNet::V4(ipv4_net) => Some(ipv4_net),
                    _ => None,
                })
                .collect();

            if current_lan_set != new_lan_set {
                log::debug!(
                    "netmon: local ip changed {:?} -> {:?}",
                    current_lan_set,
                    new_lan_set
                );
                if self.detect_public_ip_change() {
                    log::info!("netmon: new public ip");
                    return Ok(());
                }
            }
        }
    }
    pub fn detect_public_ip_change(&mut self) -> bool {
        self.current = NetInfo::detect(&self.wg_if_name);
        if self.current.offline() {
            log::debug!("netmon: Offline");
            return false;
        }
        log::debug!("netmon: Online");
        let last_online = self.last_online.replace(self.current.clone());
        match last_online {
            Some(last_online) => last_online.wan_ipv4 != self.current.wan_ipv4,
            None => true,
        }
    }

    pub(crate) fn get_current(&self) -> Option<NetInfo> {
        Some(self.current.clone())
    }

    pub(crate) fn needs_relay(&self) -> bool {
        self.current.hard_nat
    }
}
