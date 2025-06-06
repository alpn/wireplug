use shared::{BINCODE_CONFIG, WireplugAnnounce, WireplugResponse};
use std::{
    env::{self},
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    thread,
    time::Duration,
};

fn send_announcement<T: ToSocketAddrs>(t: T) {
    //-> std::io::Result<()> {
    match TcpStream::connect(t) {
        Ok(mut s) => {
            let hello = WireplugAnnounce::new(
                "alicealicealicealicealicealicealicealicealic",
                "bobbobbobbobbobbobbobbobbobbobbobbobbobbobbo",
            );
            let v = bincode::encode_to_vec(&hello, BINCODE_CONFIG).unwrap();
            s.write_all(&v).unwrap();
            let mut res = [0u8; 1024];
            s.read(&mut res).ok().unwrap();
            let (response, _): (WireplugResponse, usize) =
                bincode::decode_from_slice(&res[..], BINCODE_CONFIG).unwrap();
            println!("response: {:?}", response);
        }
        Err(e) => eprintln!("{:?}", e),
    }
}
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 2 {
        loop {
            println!("sending announcement..");
            send_announcement(&args[1]);
            println!("waiting..");
            thread::sleep(Duration::from_secs(3));
        }
    } else {
        eprintln!("usage");
    }
}
