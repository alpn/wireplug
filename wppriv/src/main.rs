use clap::Parser;

#[cfg(target_os = "openbsd")]
use openbsd::{pledge, unveil};

#[derive(Parser)]
#[command(version, name="wppriv", about="", long_about = None)]
struct Cli {
    #[arg(short, long, help = "do not daemonize")]
    debug: bool,
}

async fn start(_cli: Cli) -> std::io::Result<()>{
    Ok(())
}

fn main() {
    #[cfg(target_os = "openbsd")]
    if let Err(e) = openbsd::pledge!("stdio rpath unix exec", "") {
        eprintln!("{}", e);
        std::process::exit(1);
    }

    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("could not build tokio runtime");

    if let Err(e) = rt.block_on(start(cli)) {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}
