use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use crate::utils;

#[derive(Debug, Clone)]
pub(crate) struct NetInfo {
    wan_ip4: Option<Ipv4Addr>,
    pub(crate) wan_ip6: Option<Ipv6Addr>,
    pub(crate) lan_addrs: Vec<IpNet>,
    pub(crate) hard_nat: bool,
    /*
    default_gateway: String,
    dns_server: String,
     */
}

impl PartialEq for NetInfo {
    fn eq(&self, other: &Self) -> bool {
        self.wan_ip4 == other.wan_ip4
            && self.wan_ip6 == other.wan_ip6
            && self.lan_addrs == other.lan_addrs
    }
}

impl NetInfo {
    fn detect(if_name: &str) -> Self {
        let (mut wan_ip4, wan_ip6) = innernet_publicip::get_both();
        if wan_ip4.is_none() && wan_ip6.is_none() {
            wan_ip4 = utils::get_ip_over_https();
            if wan_ip4.is_some() {
                log::warn!(
                    "Network: quad9 is unreachable, ip found via HTTPS {:?}",
                    wan_ip4
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
            wan_ip4,
            wan_ip6,
            lan_addrs,
            hard_nat: false,
        }
    }
    fn online(&self) -> bool {
        self.wan_ip4.is_some() || self.wan_ip6.is_some()
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
pub(crate) enum ExternalIpKind {
    None,
    Ipv4,
    Ipv6,
    Both,
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
        match &mut self.current {
            Some(c) => c.hard_nat = hard_nat,
            None => (),
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
            let last_online_hard_nat = self.last_online.as_ref().map_or(false, |lo| lo.hard_nat);
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

    pub(crate) fn get_current_lan_info(&self) -> Vec<IpNet> {
        match &self.current {
            Some(current) => current.lan_addrs.clone(),
            None => Vec::new(),
        }
    }

    pub(crate) fn needs_relay(&self) -> bool {
        self.current.as_ref().map_or(false, |c| c.hard_nat)
    }

    pub(crate) fn _get_external_ip_kind(&self) -> ExternalIpKind {
        let Some(current) = &self.current else {
            return ExternalIpKind::None;
        };
        match (current.wan_ip4, current.wan_ip6) {
            (Some(_), Some(_)) => ExternalIpKind::Both,
            (Some(_), None) => ExternalIpKind::Ipv4,
            (None, Some(_)) => ExternalIpKind::Ipv6,
            (None, None) => ExternalIpKind::None,
        }
    }
}
