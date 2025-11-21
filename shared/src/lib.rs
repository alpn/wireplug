use bincode::config::Configuration;
use chrono::Local;
use colored::Colorize;
use log::{Level, Log, Metadata, Record};

pub mod protocol;

pub const WIREPLUG_STUN_PORT: u16 = 4455;
pub const WIREPLUG_ORG_STUN1: &str = "stun1.wireplug.org";
pub const WIREPLUG_ORG_STUN2: &str = "stun2.wireplug.org";
pub const WIREPLUG_ORG_WP: &str = "a.wireplug.org";

pub const MAX_MESSAGE_SIZE: usize = 4096;
pub const BINCODE_CONFIG: Configuration<
    bincode::config::LittleEndian,
    bincode::config::Fixint,
    bincode::config::Limit<MAX_MESSAGE_SIZE>,
> = bincode::config::standard()
    .with_fixed_int_encoding()
    .with_limit::<MAX_MESSAGE_SIZE>();

pub struct TmpLogger;

impl Log for TmpLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
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
            //let now = Local::now().format("%Y-%m-%dT%H:%M:%S%.3f");
            let now = Local::now().to_rfc2822();
            println!("{now} {level_str} {}", record.args());
            /*
            if let Some(p) = record.module_path() && log::max_level() ==  Level::Trace {
                println!("{level_str} {} {}", p.dimmed(), record.args());
            } else {
                println!("{level_str} {}", record.args());
            }
             */
        }
    }

    fn flush(&self) {}
}
