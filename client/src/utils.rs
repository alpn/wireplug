use rand::Rng;

pub(crate) fn get_random_port() -> u16 {
    let mut rng = rand::rng();
    rng.random_range(1024..=u16::MAX)
}
