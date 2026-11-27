use crate::{nat, netstat::NetInfo, utils};
use portmapper::Protocol;
use std::time::Duration;

#[derive(Debug)]
enum PortMappingService {
    Upnp,
    NatPmp,
    Pcp,
}

async fn try_portmapping(service: PortMappingService) {
    let cfg = match service {
        PortMappingService::Upnp => portmapper::Config {
            enable_upnp: true,
            enable_pcp: false,
            enable_nat_pmp: false,
            protocol: Protocol::Udp,
        },
        PortMappingService::NatPmp => portmapper::Config {
            enable_upnp: false,
            enable_pcp: false,
            enable_nat_pmp: true,
            protocol: Protocol::Udp,
        },
        PortMappingService::Pcp => portmapper::Config {
            enable_upnp: false,
            enable_pcp: true,
            enable_nat_pmp: false,
            protocol: Protocol::Udp,
        },
    };

    let pm = portmapper::Client::new(cfg);
    let test_port = utils::get_random_port();

    pm.update_local_port(std::num::NonZeroU16::new(test_port).unwrap());

    println!("trying to map udp port {test_port} using {service:?}..");

    let ok = match pm.probe().await {
        Ok(Ok(res)) => match service {
            PortMappingService::Upnp => res.upnp,
            PortMappingService::NatPmp => res.nat_pmp,
            PortMappingService::Pcp => res.pcp,
        },
        Ok(Err(e)) => {
            eprintln!("error: {e}");
            return;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    if ok {
        println!("{service:?} is available");
    } else {
        println!("{service:?} is not available");
        return;
    }

    let mut rx = pm.watch_external_address();
    match rx.changed().await {
        Ok(_) => {
            if let Some(mapping) = *rx.borrow() {
                println!("{service:?} has mapped port {test_port} to: {mapping:?}");
            }
        }
        Err(e) => {
            println!("error: {e}");
        }
    }
}

pub(crate) async fn probe() -> anyhow::Result<()> {
    let mut netinfo = NetInfo::detect("");
    let new_port = utils::get_random_port();
    match nat::detect_kind(new_port) {
        Ok(nat) => {
            if matches!(nat, nat::NatKind::Hard) {
                netinfo.hard_nat = true;
            }
        }
        Err(e) => {
            log::warn!("failed to perform NAT detection: {e}");
            return Ok(());
        }
    };
    println!("Network:");
    println!("{netinfo}");

    let res = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            try_portmapping(PortMappingService::NatPmp),
            try_portmapping(PortMappingService::Pcp),
            try_portmapping(PortMappingService::Upnp),
        )
    })
    .await;

    match res {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
