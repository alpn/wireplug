use clap::{Parser, ValueEnum};
use log::Level;
use shared::TmpLogger;

mod announce;
mod config;
mod daemon;
mod nat;
mod net_probe;
#[cfg(target_os = "linux")]
mod netlink;
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
#[command(version, name="wireplugd", about="", long_about = None)]
struct Cli {
    #[arg(long)]
    generate_config: bool,
    #[arg(short, long, help = "Preform network probing and exit")]
    net_probe: bool,
    #[arg(required_unless_present = "net_probe")]
    interface_name: Option<String>,
    #[arg(long)]
    no_config: bool,
    #[arg(long, help = "Do not perform NAT traversal")]
    no_nat: bool,
    #[arg(short, long)]
    log_level: Option<LogLevelPicker>,
}

fn start_net_probe() -> anyhow::Result<()> {
    log::set_max_level(Level::Warn.to_level_filter());
    log::set_logger(&LOGGER).map_err(|e| anyhow::Error::msg(format!("set_logger(): {e}")))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(net_probe::probe())?;

    Ok(())
}

fn start(
    ifname: &String,
    no_config: bool,
    log_level: Level,
    traverse_nat: bool,
) -> anyhow::Result<()> {
    log::set_max_level(log_level.to_level_filter());
    log::set_logger(&LOGGER).map_err(|e| anyhow::Error::msg(format!("set_logger(): {e}")))?;
    log::info!("starting");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    #[cfg(not(target_os = "macos"))]
    wg_interface::show_config(ifname)?;

    let config = match no_config {
        #[cfg(not(target_os = "openbsd"))]
        false => Some(config::read_from_file(ifname)?),
        _ => None,
    };

    wg_interface::configure(ifname, config)?;
    log::info!("interface configured");
    wg_interface::show_config(ifname)?;

    rt.block_on(daemon::monitor_interface(ifname, traverse_nat))?;

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    if cli.net_probe {
        if let Err(e) = start_net_probe() {
            eprintln!("fatal: {e}");
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    let ifname = &cli
        .interface_name
        .expect("interface_name is required when net_probe is absent");

    if cli.generate_config {
        match config::generate_example_to_file(ifname) {
            Ok(_) => println!("new config created!"),
            Err(e) => eprintln!("failed to create config file: {e}"),
        }
        return;
    }

    let log_level = match cli.log_level {
        Some(level) => match level {
            LogLevelPicker::Default => Level::Info,
            LogLevelPicker::Medium => Level::Debug,
            LogLevelPicker::High => Level::Trace,
        },
        None => Level::Info,
    };

    let traverse_nat = !cli.no_nat;
    if let Err(e) = start(ifname, cli.no_config, log_level, traverse_nat) {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}
