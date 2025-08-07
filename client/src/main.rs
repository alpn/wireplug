use clap::Parser;
use shared::TmpLogger;
use std::{thread, time::Duration};

mod announce;
mod config;
mod nat;
mod netstat;
mod utils;
mod wg_interface;

static LOGGER: TmpLogger = TmpLogger;

#[derive(Parser)]
#[command(version, name="Wireplug", about="", long_about = None)]
struct Cli {
    interface_name: String,
    #[arg(short, long)]
    config: Option<String>,
    #[arg(long)]
    no_nat: bool,
}

fn monitor_interface(ifname: &String, traverse_nat: bool) -> anyhow::Result<()> {
    let mut peers_activity = wg_interface::PeersActivity::new();
    let mut netmon = netstat::NetworkMonitor::new();
    log::info!("monitoring interface: {ifname} with NAT travesal={traverse_nat}");
    loop {
        let Some(listen_port) = wg_interface::get_port(ifname) else {
            todo!();
        };
        let inactive_peers = wg_interface::get_inactive_peers(ifname, &mut peers_activity)?;
        if !inactive_peers.is_empty() {
            log::info!("{ifname} has {} INACTIVE peers", inactive_peers.len());
            let port_to_announce = if netmon.has_changed() && traverse_nat {
                let new_listen_port = utils::get_random_port();
                let nat = nat::detect_kind(new_listen_port)?;
                log::debug!("NAT: {nat:?}");
                let observed_port = match nat {
                    nat::NatKind::Easy => new_listen_port,
                    nat::NatKind::FixedPortMapping(port_mapping_nat) => {
                        port_mapping_nat.obsereved_port
                    }
                    nat::NatKind::Hard => {
                        log::warn!("can't do much about Hard NAT atm, will try again in a bit .. ");
                        thread::sleep(Duration::from_secs(shared::protocol::MONITORING_INTERVAL));
                        continue;
                    }
                };
                log::debug!("updating listen port to {new_listen_port} ..");
                std::thread::sleep(Duration::from_secs(3));
                wg_interface::update_port(ifname, new_listen_port)?;
                observed_port
            } else {
                listen_port
            };
            let lan_addrs = utils::get_lan_addrs(ifname).ok();
            if announce::announce_and_update_peers(
                ifname,
                inactive_peers,
                port_to_announce,
                lan_addrs,
            )? {
                log::info!(
                    "some endpoints were updated, waiting for peers to attempt handshakes.."
                );
                thread::sleep(Duration::from_secs(shared::protocol::POST_UPDATE_INTERVAL));
            }
        }
        thread::sleep(Duration::from_secs(shared::protocol::MONITORING_INTERVAL));
    }
}

fn start(ifname: &String, config_file: Option<String>, traverse_nat: bool) -> anyhow::Result<()> {
    log::set_max_level(log::LevelFilter::Trace);
    log::set_logger(&LOGGER).map_err(|e| anyhow::Error::msg(format!("set_logger(): {e}")))?;
    log::info!("starting");
    wg_interface::show_config(ifname)?;

    let config = match config_file {
        Some(path) => Some(config::read_from_file(&path)?),
        None => None,
    };

    wg_interface::configure(ifname, config)?;
    log::info!("interface configured");
    wg_interface::show_config(ifname)?;
    log::info!("waiting for peers to attempt handshakes..");
    std::thread::sleep(Duration::from_secs(5));
    monitor_interface(ifname, traverse_nat)?;
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let ifname = &cli.interface_name;
    let traverse_nat = !cli.no_nat;
    if let Err(e) = start(ifname, cli.config, traverse_nat) {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}
