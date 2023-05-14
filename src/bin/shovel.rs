/// Resolves a DNS query.
use std::env;
use std::net::Ipv4Addr;

use dns_in_a_weekend::{resolve, DNSQuestionType};

fn main() -> Result<(), String> {
    {
        let args: Vec<String> = env::args().collect();

        let domain_name = &args[1];

        let question_type = match args.get(2) {
            Some(s) => match DNSQuestionType::try_from(s.as_str()) {
                Ok(q) => q,
                Err(_) => {
                    return Err(format!("Invalid DNS QTYPE: {s}"));
                }
            },
            None => DNSQuestionType::A,
        };

        let initial_nameserver = match args.get(3) {
            Some(s) => match s.parse::<Ipv4Addr>() {
                Ok(ip) => Some(ip),
                Err(e) => {
                    return Err(format!("Invalid initial nameserver ip {}: {}", s, e));
                }
            },
            None => None,
        };

        match resolve(domain_name, &question_type, initial_nameserver) {
            Ok(ip) => println!("Resolved {}: {}", domain_name, ip),
            Err(e) => eprintln!("Failed to resolve {}: {}", domain_name, e),
        };
    }

    Ok(())
}
