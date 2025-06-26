use clap::Parser;
use std::{thread, time::Duration};

pub mod config;
pub mod protocol;
pub mod wg_interface;

#[derive(Parser)]
#[command(version, name="Wireplug", about="", long_about = None)]
struct Cli {
    interface_name: String,
    #[arg(short, long)]
    config_interface: bool,
}

fn main() {
    let cli = Cli::parse();
    let ifname = &cli.interface_name;
    wg_interface::show_config(ifname);

    if cli.config_interface {
        wg_interface::configure(ifname);
        wg_interface::show_config(ifname);
    }

    println!("attempting to monitor interface {}..", ifname);
    loop {
        if let Err(e) = protocol::monitor_interface(ifname) {
            eprintln!("Fatal Error: {e}");
            std::process::exit(1);
        }
        thread::sleep(Duration::from_secs(protocol::MONITORING_INTERVAL));
    }
}
