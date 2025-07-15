use bincode::config::Configuration;

pub mod protocol;

pub const BINCODE_CONFIG: Configuration<
    bincode::config::LittleEndian,
    bincode::config::Fixint,
    bincode::config::Limit<256>,
> = bincode::config::standard()
    .with_fixed_int_encoding()
    .with_limit::<256>();
