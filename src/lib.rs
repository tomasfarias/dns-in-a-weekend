/// Rust implementation of DNS in a Weekend.
/// See: https://implement-dns.wizardzines.com.
use rand::Rng;

const RECURSION_DESIRED: u16 = 1 << 8;
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

/// Represents the header of a DNS query.
pub struct DNSHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

impl DNSHeader {
    /// Returns a byte vec of this `DNSQuestion`'s contents.
    ///
    /// We use big-endian representation as that's used in networking.
    fn as_bytes(&self) -> Vec<u8> {
        let mut result = self.id.to_be_bytes().to_vec();
        result.extend(self.flags.to_be_bytes());
        result.extend(self.num_questions.to_be_bytes());
        result.extend(self.num_answers.to_be_bytes());
        result.extend(self.num_authorities.to_be_bytes());
        result.extend(self.num_additionals.to_be_bytes());
        result
    }
}

/// Represents the body of a DNS query.
pub struct DNSQuestion {
    name: Vec<u8>,
    type_: u16,
    class: u16,
}

impl DNSQuestion {
    /// Returns a byte vec of this `DNSQuestion`'s contents.
    ///
    /// We use big-endian representation as that's used in networking.
    fn as_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend(self.name.iter());
        result.extend(self.type_.to_be_bytes());
        result.extend(self.class.to_be_bytes());
        result
    }
}

/// Return an encoded representation of a domain name.
///
/// Starts with an empty Vec<u8>.
/// Splits domain name by '.'.
/// For each part, add the number of bytes in part to the encoded string as well as the part.
/// Finally, add a 0 byte to the end.
fn encode_dns_name(domain_name: &str) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::new();
    for part in domain_name.split('.') {
        let part_bytes = part.as_bytes();
        encoded.push(part_bytes.len() as u8);
        encoded.extend(part_bytes);
    }

    encoded.push(0);
    encoded
}

/// Build a DNS query for a given domain name.
pub fn build_query(domain_name: &str, record_type: u16) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let id: u16 = rng.gen();

    let header = DNSHeader {
        id,
        flags: RECURSION_DESIRED,
        num_questions: 1,
        num_answers: 0,
        num_authorities: 0,
        num_additionals: 0,
    };

    let name = encode_dns_name(domain_name);

    let question = DNSQuestion {
        name,
        type_: record_type,
        class: CLASS_IN,
    };

    let mut result = header.as_bytes();
    result.append(&mut question.as_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_header_as_bytes() {
        let header = DNSHeader {
            id: 0x1314,
            flags: 0,
            num_questions: 1,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        };
        let result = header.as_bytes();

        assert_eq!(result[0], 0x13);
        assert_eq!(result[1], 0x14);
        assert_eq!(result[2], 0x00);
        assert_eq!(result[3], 0x00);
        assert_eq!(result[4], 0x00);
        assert_eq!(result[5], 0x01);
    }

    #[test]
    fn test_encode_dns_name() {
        let test_domain = "tomasfarias.dev";
        let result = encode_dns_name(test_domain);

        assert_eq!(result[0], 11);
        assert_eq!(result[1], b't');
        assert_eq!(result[2], b'o');
        assert_eq!(result[3], b'm');
        assert_eq!(result[4], b'a');
        assert_eq!(result[5], b's');
        assert_eq!(result[6], b'f');
        assert_eq!(result[7], b'a');
        assert_eq!(result[8], b'r');
        assert_eq!(result[9], b'i');
        assert_eq!(result[10], b'a');
        assert_eq!(result[11], b's');
        assert_eq!(result[12], 3);
        assert_eq!(result[13], b'd');
        assert_eq!(result[14], b'e');
        assert_eq!(result[15], b'v');
        assert_eq!(result[16], 0);
    }

    #[test]
    fn test_build_query() {
        let query = build_query("example.com", TYPE_A);
        assert_eq!(query[12], 7);
        assert_eq!(query[13], b'e');
        assert_eq!(query[14], b'x');
        assert_eq!(query[15], b'a');
        assert_eq!(query[16], b'm');
        assert_eq!(query[17], b'p');
        assert_eq!(query[18], b'l');
        assert_eq!(query[19], b'e');
        assert_eq!(query[20], 3);
        assert_eq!(query[21], b'c');
        assert_eq!(query[22], b'o');
        assert_eq!(query[23], b'm');
        assert_eq!(query[24], 0);
        assert_eq!(query[25], 0);
        assert_eq!(query[26], 1);
    }
}
