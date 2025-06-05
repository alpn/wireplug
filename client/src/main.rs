use std::{io::{Read, Write}, net::TcpStream, thread, time::Duration};
use shared::{WireplugAnnounce, WireplugResponse};

fn send_announcement() {
    match TcpStream::connect("10.0.0.1:4455"){
        Ok(mut s) => {
                let hello = WireplugAnnounce::new("alicealicealicealicealicealicealicealicealic", "bobbobbobbobbobbobbobbobbobbobbobbobbobbobbo");
                let config = bincode::config::standard();
                let v = bincode::encode_to_vec(&hello, config).unwrap();
                s.write_all(&v).unwrap();
                let mut res = [0u8;1024];
                s.read(&mut res).ok().unwrap();
                let (response, _): (WireplugResponse, usize)= bincode::decode_from_slice(&res[..], config).unwrap();
                println!("response: {:?}" ,response);
            },
        Err(e) => eprintln!("{:?}" ,e)
    }
}
fn main() {
    loop {
        println!("sending announcement..");
        send_announcement();
        println!("waiting..");
        thread::sleep(Duration::from_secs(3));
    }
}