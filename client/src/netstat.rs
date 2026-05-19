use std::net::{Ipv4Addr, Ipv6Addr};

use crate::utils;

#[derive(Debug, Clone)]
pub(crate) struct NetInfo {
    wan_ip4: Option<Ipv4Addr>,
    pub(crate) wan_ip6: Option<Ipv6Addr>,
    pub(crate) lan_addrs: Vec<String>,
    /*
    default_gateway: String,
    dns_server: String,
     */
}

impl PartialEq for NetInfo {
    fn eq(&self, other: &Self) -> bool {
        self.wan_ip4 == other.wan_ip4
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
    hard_nat: bool,
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
            hard_nat: false,
            wg_if_name: wg_if_name.to_owned(),
        }
    }
    pub fn set_hard_nat(&mut self, hard_nat: bool) {
        self.hard_nat = hard_nat;
    }

    pub fn check_status(&mut self) -> NetStatus {
        let new_info = NetInfo::detect(&self.wg_if_name);
        log::trace!("Network: {new_info:?}");

        let Some(current) = self.current.take() else {
            self.current = Some(new_info.clone());
            self.last_online = Some(new_info);
            return NetStatus::ChangedToNew;
        };

        if new_info.offline() {
            if current.online() {
                self.last_online = Some(current);
                self.current = Some(new_info);
                log::trace!("Network: changed to Offline");
            }
            return NetStatus::Offline;
        }
        if new_info == current {
            return match self.hard_nat {
                true => NetStatus::HardNat,
                false => NetStatus::Online,
            };
        }
        let new_info = Some(new_info);
        if new_info == self.last_online {
            log::trace!("Network: changed to previous");
            self.current = new_info;
            return match self.hard_nat {
                true => NetStatus::HardNat,
                false => NetStatus::ChangedToPrev,
            };
        }
        log::trace!("Network: changed to new");
        log::debug!("Network: {:?}", &new_info);
        self.current = new_info;
        self.hard_nat = false;
        NetStatus::ChangedToNew
    }

    pub(crate) fn get_current_lan_info(&self) -> Vec<String> {
        match &self.current {
            Some(current) => current.lan_addrs.clone(),
            None => Vec::new(),
        }
    }

    pub(crate) fn needs_relay(&self) -> bool {
        self.hard_nat
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
