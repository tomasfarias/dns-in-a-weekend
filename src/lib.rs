/// Rust implementation of DNS in a Weekend.
/// See: https://implement-dns.wizardzines.com.
use std::fmt;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::net::Ipv4Addr;
use std::str;

use rand::Rng;

const RECURSION_DESIRED: u16 = 1 << 8;
const CLASS_IN: u16 = 1;

/// Represents an entire DNS packet
#[derive(Debug, Eq, PartialEq)]
pub struct DNSPacket {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSRecord>,
    pub authorities: Vec<DNSRecord>,
    pub additionals: Vec<DNSRecord>,
}

impl DNSPacket {
    /// Returns a `DNSPacket` from bytes.
    ///
    /// This is intended to parse the buffer written to by a socket.
    pub fn from_bytes(response: &[u8]) -> Self {
        let mut reader = Cursor::new(response);
        DNSPacket::from_reader(&mut reader)
    }

    /// Returns a `DNSPacket` from a reader.
    fn from_reader<R: Read + Seek>(reader: &mut R) -> Self {
        let header = DNSHeader::from_reader(reader);
        let questions = (0..header.num_questions)
            .map(|_| DNSQuestion::from_reader(reader))
            .collect();
        let answers = (0..header.num_answers)
            .map(|_| DNSRecord::from_reader(reader))
            .collect();
        let authorities = (0..header.num_authorities)
            .map(|_| DNSRecord::from_reader(reader))
            .collect();
        let additionals = (0..header.num_additionals)
            .map(|_| DNSRecord::from_reader(reader))
            .collect();

        Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        }
    }
}

/// Represents the header of a DNS query.
#[derive(Debug, Eq, PartialEq)]
pub struct DNSHeader {
    id: u16,
    flags: u16,
    num_questions: u16,
    num_answers: u16,
    num_authorities: u16,
    num_additionals: u16,
}

impl DNSHeader {
    /// Returns a byte vec of this `DNSHeader`'s contents.
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

    /// Returns a `DNSHeader` from a reader.
    ///
    /// Notice each of the fields is a 2 byte integer (u16), so there are 12 bytes (u8)
    /// in total to read.
    fn from_reader<R: Read + Seek>(reader: &mut R) -> Self {
        let mut buf = [0; 2];

        reader.read(&mut buf).expect("couldn't read DNS response");
        let id = u16::from_be_bytes(buf);

        reader.read(&mut buf).expect("couldn't read DNS response");
        let flags = u16::from_be_bytes(buf);

        reader.read(&mut buf).expect("couldn't read DNS response");
        let num_questions = u16::from_be_bytes(buf);

        reader.read(&mut buf).expect("couldn't read DNS response");
        let num_answers = u16::from_be_bytes(buf);

        reader.read(&mut buf).expect("couldn't read DNS response");
        let num_authorities = u16::from_be_bytes(buf);

        reader.read(&mut buf).expect("couldn't read DNS response");
        let num_additionals = u16::from_be_bytes(buf);

        Self {
            id,
            flags,
            num_questions,
            num_answers,
            num_authorities,
            num_additionals,
        }
    }
}

/// Enum of `DNSQuestionType` types as defined in the DNS specification.
///
/// See: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.3
#[derive(Debug, Eq, PartialEq)]
pub enum DNSQuestionType {
    A,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
    AXFR,
    MAILB,
    MAILA,
    ALL,
}

impl TryFrom<u16> for DNSQuestionType {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DNSQuestionType::A),
            2 => Ok(DNSQuestionType::NS),
            3 => Ok(DNSQuestionType::MD),
            4 => Ok(DNSQuestionType::MF),
            5 => Ok(DNSQuestionType::CNAME),
            6 => Ok(DNSQuestionType::SOA),
            7 => Ok(DNSQuestionType::MB),
            8 => Ok(DNSQuestionType::MG),
            9 => Ok(DNSQuestionType::MR),
            10 => Ok(DNSQuestionType::NULL),
            11 => Ok(DNSQuestionType::WKS),
            12 => Ok(DNSQuestionType::PTR),
            13 => Ok(DNSQuestionType::HINFO),
            14 => Ok(DNSQuestionType::MINFO),
            15 => Ok(DNSQuestionType::MX),
            16 => Ok(DNSQuestionType::TXT),
            252 => Ok(DNSQuestionType::AXFR),
            253 => Ok(DNSQuestionType::MAILB),
            254 => Ok(DNSQuestionType::MAILA),
            255 => Ok(DNSQuestionType::ALL),
            n => Err(format!(
                "DNS question QTYPE must be in 1..16 or 252..255 ranges, not {n}"
            )),
        }
    }
}

impl Into<u16> for DNSQuestionType {
    fn into(self) -> u16 {
        match self {
            DNSQuestionType::A => 1,
            DNSQuestionType::NS => 2,
            DNSQuestionType::MD => 3,
            DNSQuestionType::MF => 4,
            DNSQuestionType::CNAME => 5,
            DNSQuestionType::SOA => 6,
            DNSQuestionType::MB => 7,
            DNSQuestionType::MG => 8,
            DNSQuestionType::MR => 9,
            DNSQuestionType::NULL => 10,
            DNSQuestionType::WKS => 11,
            DNSQuestionType::PTR => 12,
            DNSQuestionType::HINFO => 13,
            DNSQuestionType::MINFO => 14,
            DNSQuestionType::MX => 15,
            DNSQuestionType::TXT => 16,
            DNSQuestionType::AXFR => 252,
            DNSQuestionType::MAILB => 253,
            DNSQuestionType::MAILA => 254,
            DNSQuestionType::ALL => 255,
        }
    }
}

impl fmt::Display for DNSQuestionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DNSQuestionType::ALL => write!(f, "*"),
            _ => fmt::Debug::fmt(self, f),
        }
    }
}

/// Represents the body of a DNS query.
#[derive(Debug, Eq, PartialEq)]
pub struct DNSQuestion {
    name: Vec<u8>,
    type_: u16,
    class: u16,
}

impl DNSQuestion {
    fn new(domain_name: &str, question_type: DNSQuestionType) -> Self {
        Self {
            name: encode_dns_name(domain_name),
            type_: question_type.into(),
            class: CLASS_IN,
        }
    }

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

    /// Returns a `DNSQuestion` from a reader.
    ///
    /// Notice the type_ and class fields are a 2 byte integer (u16).
    fn from_reader<R: Read + Seek>(reader: &mut R) -> Self {
        let name = decode_dns_name(reader);
        let mut buf = [0; 2];

        reader
            .read(&mut buf)
            .expect("couldn't read DNS question data");
        let type_ = u16::from_be_bytes(buf);

        reader
            .read(&mut buf)
            .expect("couldn't read DNS question data");
        let class = u16::from_be_bytes(buf);

        Self {
            name: name.into_bytes(),
            type_,
            class,
        }
    }

    /// Returns this `DNSQuestion`'s QTYPE.
    pub fn record_type(&self) -> Option<DNSQuestionType> {
        match DNSQuestionType::try_from(self.type_) {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("invalid QTYPE: {}", e);
                None
            }
        }
    }
}

/// Enum of `DNSRecord` types as defined in the DNS specification.
///
/// See: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2.
#[derive(Debug, Eq, PartialEq)]
pub enum DNSRecordType {
    A,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
}

impl TryFrom<u16> for DNSRecordType {
    type Error = String;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DNSRecordType::A),
            2 => Ok(DNSRecordType::NS),
            3 => Ok(DNSRecordType::MD),
            4 => Ok(DNSRecordType::MF),
            5 => Ok(DNSRecordType::CNAME),
            6 => Ok(DNSRecordType::SOA),
            7 => Ok(DNSRecordType::MB),
            8 => Ok(DNSRecordType::MG),
            9 => Ok(DNSRecordType::MR),
            10 => Ok(DNSRecordType::NULL),
            11 => Ok(DNSRecordType::WKS),
            12 => Ok(DNSRecordType::PTR),
            13 => Ok(DNSRecordType::HINFO),
            14 => Ok(DNSRecordType::MINFO),
            15 => Ok(DNSRecordType::MX),
            16 => Ok(DNSRecordType::TXT),
            n => Err(format!("DNS record TYPE must be in 1..16 range, not {n}")),
        }
    }
}

impl Into<u16> for DNSRecordType {
    fn into(self) -> u16 {
        match self {
            DNSRecordType::A => 1,
            DNSRecordType::NS => 2,
            DNSRecordType::MD => 3,
            DNSRecordType::MF => 4,
            DNSRecordType::CNAME => 5,
            DNSRecordType::SOA => 6,
            DNSRecordType::MB => 7,
            DNSRecordType::MG => 8,
            DNSRecordType::MR => 9,
            DNSRecordType::NULL => 10,
            DNSRecordType::WKS => 11,
            DNSRecordType::PTR => 12,
            DNSRecordType::HINFO => 13,
            DNSRecordType::MINFO => 14,
            DNSRecordType::MX => 15,
            DNSRecordType::TXT => 16,
        }
    }
}

impl fmt::Display for DNSRecordType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Represents a DNS record.
#[derive(Debug, Eq, PartialEq)]
pub struct DNSRecord {
    name: Vec<u8>,
    type_: u16,
    class: u16,
    ttl: u16,
    data: Vec<u8>,
}

impl DNSRecord {
    /// Returns a `DNSRecord` from a reader.
    fn from_reader<R: Read + Seek>(reader: &mut R) -> Self {
        let name = decode_dns_name(reader);

        let mut bytes = [0; 10];
        reader
            .read(&mut bytes)
            .expect("couldn't read DNS record bytes");

        let type_ = u16::from_be_bytes(bytes[0..2].try_into().expect("slice with invalid length"));
        let class = u16::from_be_bytes(bytes[2..4].try_into().expect("slice with invalid length"));
        let ttl = u16::from_be_bytes(bytes[4..6].try_into().expect("slice with invalid length"));
        let data_len =
            u16::from_be_bytes(bytes[6..8].try_into().expect("slice with invalid length"));

        let mut handle = reader.take(data_len as u64);
        let mut data = Vec::new();
        handle
            .read_to_end(&mut data)
            .expect("couldn't read DNS record data");

        Self {
            name: name.into_bytes(),
            type_,
            class,
            ttl,
            data,
        }
    }

    /// Returns the `Ipv4Addr` contained in this `DNSRecord`'s data.
    pub fn ipv4_address(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.data[0], self.data[1], self.data[2], self.data[3])
    }

    /// Returns this `DNSRecord`'s TYPE.
    pub fn record_type(&self) -> Option<DNSRecordType> {
        match DNSRecordType::try_from(self.type_) {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("invalid TYPE: {}", e);
                None
            }
        }
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

fn decode_dns_name<R: Read + Seek>(reader: &mut R) -> String {
    let mut parts: Vec<String> = Vec::new();

    loop {
        let mut byte = [0; 1];

        if let Err(e) = reader.read(&mut byte) {
            eprintln!("Error reading DNS name bytes: {e}");
            break;
        };

        let length = byte[0];
        if length == 0 {
            break;
        }

        if length & 0b1100_0000 != 0 {
            parts.push(decode_compressed_dns_name(length, reader));
            break;
        } else {
            let mut handle = reader.take(length as u64);

            let mut buffer = String::new();
            handle
                .read_to_string(&mut buffer)
                .expect("couldn't read part to string");

            parts.push(buffer);
        }
    }

    parts.join(".")
}

fn decode_compressed_dns_name<R: Read + Seek>(length: u8, reader: &mut R) -> String {
    let mut next_byte = [0; 1];
    reader
        .read(&mut next_byte)
        .expect("couldn't read next byte");

    let current_position = reader
        .stream_position()
        .expect("couldn't read current seek position");

    let ptr: u8 = (length & 0b0011_1111)
        .checked_add(next_byte[0])
        .expect("overflow");

    reader
        .seek(SeekFrom::Start(ptr as u64))
        .expect("couldn't seek to pointer");
    let name = decode_dns_name(reader);

    reader
        .seek(SeekFrom::Start(current_position))
        .expect("couldn't seek to current position");

    name
}

/// Build a DNS query for a given domain name.
pub fn build_query(domain_name: &str, question_type: DNSQuestionType) -> Vec<u8> {
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

    let question = DNSQuestion::new(domain_name, question_type);

    let mut result = header.as_bytes();
    result.append(&mut question.as_bytes());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::str;

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
        let query = build_query("example.com", DNSQuestionType::A);

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

    #[test]
    fn test_dns_header_from_reader() {
        let response: &[u8] = &[
            213, 219, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 6, 103, 111, 111, 103, 108, 101, 3, 99,
            111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 0, 86, 0, 4, 172, 217, 18, 14, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        let mut reader = Cursor::new(response);
        let header = DNSHeader::from_reader(&mut reader);

        assert_eq!(header.flags, 33152);
        assert_eq!(header.num_questions, 1);
        assert_eq!(header.num_answers, 1);
        assert_eq!(header.num_authorities, 0);
        assert_eq!(header.num_additionals, 0);
    }

    #[test]
    fn test_dns_question_from_reader() {
        let response: &[u8] = &[
            213, 219, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 6, 103, 111, 111, 103, 108, 101, 3, 99,
            111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 0, 86, 0, 4, 172, 217, 18, 14, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        let mut reader = Cursor::new(response);
        let _ = DNSHeader::from_reader(&mut reader);
        let question = DNSQuestion::from_reader(&mut reader);

        assert_eq!(question.type_, 1);
        assert_eq!(question.class, 1);
        assert_eq!(
            str::from_utf8(&question.name).unwrap(),
            "google.com".to_owned()
        );
    }

    #[test]
    fn test_dns_record_from_reader() {
        let response: &[u8] = &[
            213, 219, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 6, 103, 111, 111, 103, 108, 101, 3, 99,
            111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 0, 86, 0, 4, 172, 217, 18, 14, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        let mut reader = Cursor::new(response);
        let _ = DNSHeader::from_reader(&mut reader);
        let _ = DNSQuestion::from_reader(&mut reader);
        let record = DNSRecord::from_reader(&mut reader);

        assert_eq!(record.type_, 1);
        assert_eq!(record.class, 1);
        assert_eq!(str::from_utf8(&record.name).unwrap(), "google.com");
    }

    #[test]
    fn test_dns_packet_from_bytes() {
        let response: &[u8] = &[
            213, 219, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 6, 103, 111, 111, 103, 108, 101, 3, 99,
            111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 0, 86, 0, 4, 172, 217, 18, 14, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        let packet = DNSPacket::from_bytes(response);

        assert_eq!(packet.header.flags, 33152);
        assert_eq!(packet.header.num_questions, 1);
        assert_eq!(packet.header.num_answers, 1);
        assert_eq!(packet.header.num_authorities, 0);
        assert_eq!(packet.header.num_additionals, 0);
        assert_eq!(packet.questions.len(), packet.header.num_questions as usize);
        assert_eq!(packet.answers.len(), packet.header.num_answers as usize);
        assert_eq!(
            packet.authorities.len(),
            packet.header.num_authorities as usize
        );
        assert_eq!(
            packet.additionals.len(),
            packet.header.num_additionals as usize
        );
        assert_eq!(packet.questions[0].type_, 1);
        assert_eq!(packet.questions[0].class, 1);
        assert_eq!(
            str::from_utf8(&packet.questions[0].name).unwrap(),
            "google.com"
        );
    }
}
