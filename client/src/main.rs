use clap::{Parser, ValueEnum};
use log::Level;
use shared::TmpLogger;

mod announce;
mod config;
mod daemon;
mod nat;
mod netstat;
mod utils;
mod wg_interface;

static LOGGER: TmpLogger = TmpLogger;

#[derive(Clone, Debug, ValueEnum)]
enum LogLevelPicker {
    Default,
    Medium,
    High,
}

#[derive(Parser)]
#[command(version, name="Wireplug", about="", long_about = None)]
struct Cli {
    interface_name: String,
    #[arg(short, long)]
    config: Option<String>,
    #[arg(long)]
    no_nat: bool,
    #[arg(short, long)]
    log_level: Option<LogLevelPicker>,
}

fn start(
    ifname: &String,
    config_file: Option<String>,
    log_level: Level,
    traverse_nat: bool,
) -> anyhow::Result<()> {
    log::set_max_level(log_level.to_level_filter());
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
    daemon::monitor_interface(ifname, traverse_nat)?;
    Ok(())
}

fn main() {
    let cli = Cli::parse();
    let ifname = &cli.interface_name;
    let traverse_nat = !cli.no_nat;
    let log_level = match cli.log_level {
        Some(level) => match level {
            LogLevelPicker::Default => Level::Info,
            LogLevelPicker::Medium => Level::Debug,
            LogLevelPicker::High => Level::Trace,
        },
        None => Level::Info,
    };

    if let Err(e) = start(ifname, cli.config, log_level, traverse_nat) {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}
