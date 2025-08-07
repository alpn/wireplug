use clap::Parser;
use shared::TmpLogger;
use std::time::Duration;

mod announce;
mod config;
mod daemon;
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
    daemon::monitor_interface(ifname, traverse_nat)?;
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
