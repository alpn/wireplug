use bincode::config::Configuration;
use colored::Colorize;
use log::{Level, Log, Metadata, Record};

pub mod protocol;

pub const BINCODE_CONFIG: Configuration<
    bincode::config::LittleEndian,
    bincode::config::Fixint,
    bincode::config::Limit<4096>,
> = bincode::config::standard()
    .with_fixed_int_encoding()
    .with_limit::<4096>();

pub struct TmpLogger;

impl Log for TmpLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level_str = match record.level() {
                Level::Error => "[E]".red(),
                Level::Warn => "[!]".yellow(),
                Level::Info => "[*]".dimmed(),
                Level::Debug => "[D]".blue(),
                Level::Trace => "[T]".purple(),
            };
            println!("{level_str} {}", record.args());
        }
    }

    fn flush(&self) {}
}