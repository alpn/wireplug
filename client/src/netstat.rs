use std::{
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
};

use ipnet::IpNet;

use crate::utils;

#[derive(Debug, Clone)]
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
    fn online(&self) -> bool {
        self.wan_ipv4.is_some() || self.wan_ipv6.is_some()
    }
    fn offline(&self) -> bool {
        !self.online()
    }
}

#[derive(Clone)]
pub(crate) struct NetworkMonitor {
    current: Option<NetInfo>,
    last_online: Option<NetInfo>,
    wg_if_name: String,
}

pub(crate) enum NetStatus {
    ChangedToNew,
    ChangedToPrev,
    Online,
    HardNat,
    Offline,
}

impl NetworkMonitor {
    pub fn new(wg_if_name: &str) -> Self {
        Self {
            current: None,
            last_online: None,
            wg_if_name: wg_if_name.to_owned(),
        }
    }
    pub fn set_hard_nat(&mut self, hard_nat: bool) {
        if let Some(c) = &mut self.current {
            c.hard_nat = hard_nat
        }
    }

    pub fn check_status(&mut self) -> NetStatus {
        let new_info = NetInfo::detect(&self.wg_if_name);
        log::trace!("Network: {new_info:?}");

        let Some(current) = self.current.clone() else {
            self.current = Some(new_info.clone());
            self.last_online = Some(new_info);
            return NetStatus::ChangedToNew;
        };
        if new_info.offline() {
            if current.online() {
                log::debug!("Network: changed to Offline");
            }
            self.current = Some(new_info);
            return NetStatus::Offline;
        }
        if new_info == current {
            return match self.current.as_ref().is_some_and(|c| c.hard_nat) {
                true => NetStatus::HardNat,
                false => NetStatus::Online,
            };
        }
        let new_info = Some(new_info);
        if current.offline() && new_info == self.last_online {
            log::trace!("Network: changed to previous");
            let last_online_hard_nat = self.last_online.as_ref().is_some_and(|lo| lo.hard_nat);
            self.current = new_info;
            return match last_online_hard_nat {
                true => NetStatus::HardNat,
                false => NetStatus::ChangedToPrev,
            };
        }
        log::debug!("Network: changed to new {:?}", &new_info);
        self.current = new_info.clone();
        self.last_online = new_info;
        NetStatus::ChangedToNew
    }

    pub(crate) fn get_current(&self) -> Option<NetInfo> {
        self.current.clone()
    }

    pub(crate) fn needs_relay(&self) -> bool {
        self.current.as_ref().is_some_and(|c| c.hard_nat)
    }
}
