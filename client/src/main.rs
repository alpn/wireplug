use clap::Parser;
use std::{thread, time::Duration};

pub mod config;
pub mod nat;
pub mod protocol;
pub mod utils;
pub mod wg_interface;

#[derive(Parser)]
#[command(version, name="Wireplug", about="", long_about = None)]
struct Cli {
    interface_name: String,
    #[arg(short, long)]
    config: Option<String>,
    #[arg(long)]
    no_nat: bool,
}

fn main() -> Result<(), std::io::Error> {
    let cli = Cli::parse();
    let ifname = &cli.interface_name;
    wg_interface::show_config(ifname)?;

    if let Some(config_file) = cli.config {
        let config = config::read_from_file(&config_file)?;
        wg_interface::configure(ifname, &config)?;
        wg_interface::show_config(ifname)?;
        /*
        println!("waiting for peers to attempt handshakes..");
        std::thread::sleep(Duration::from_secs(shared::COMMON_PKA as u64 + 5));
         */
    }

    loop {
        let Some(listen_port) = wg_interface::get_port(ifname) else {
            todo!();
        };
        let inactive_peers = protocol::get_inactive_peers(ifname)?;
        if !inactive_peers.is_empty() {
            let port_to_announce = if !cli.no_nat {
                let new_listen_port = utils::get_random_port();
                let nat = nat::detect_kind(new_listen_port)?;
                println!("NAT: {:?}", nat);
                let observed_port = match nat {
                    nat::NatKind::Easy => new_listen_port,
                    nat::NatKind::Manageable(port_mapping_nat) => port_mapping_nat.obsereved_port,
                    nat::NatKind::Hard => {
                        println!("can't do much about Hard NAT atm, will try again in a bit .. ");
                        thread::sleep(Duration::from_secs(protocol::MONITORING_INTERVAL));
                        continue;
                    }
                };
                println!("updating port..");
                std::thread::sleep(Duration::from_secs(3));
                wg_interface::update_port(&ifname, new_listen_port)?;
                observed_port
            } else {
                listen_port
            };
            protocol::announce_and_update_peers(ifname, inactive_peers, port_to_announce)?;
        }
        thread::sleep(Duration::from_secs(protocol::MONITORING_INTERVAL));
    }
}
