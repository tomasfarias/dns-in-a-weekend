/// Executes a DNS query to Cloudflare's 1.1.1.1 DNS resolver.
use std::env;
use std::net;

use dns_in_a_weekend::build_query;

fn main() -> std::io::Result<()> {
    {
        let args: Vec<String> = env::args().collect();
        let query = build_query(&args[1], 1);

        let socket = net::UdpSocket::bind("0.0.0.0:34524").expect("couldn't bind to address");
        socket
            .send_to(&query, "1.1.1.1:53")
            .expect("couldn't send data");

        let mut buf = [0; 512];
        let (_, _) = socket.recv_from(&mut buf)?;

        println!("{:?}", buf);
    }

    Ok(())
}
