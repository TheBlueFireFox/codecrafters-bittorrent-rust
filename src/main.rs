use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use clap::Parser;
use serde::Serialize;
use sha1::Digest;

/// Simple program to greet a person
#[derive(clap::Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    Decode(Decode),
    Info(Info),
    Peers(Peers),
    Handshake(Handshake),
}

#[derive(clap::Args, Debug)]
struct Decode {
    /// The path to read from
    bencode: String,
}

#[derive(clap::Args, Debug)]
struct Handshake {
    /// The path to read from
    path: std::path::PathBuf,
    addr: SocketAddr,
}

#[derive(clap::Args, Debug)]
struct Info {
    /// The path to read from
    path: std::path::PathBuf,
}

#[derive(clap::Args, Debug)]
struct Peers {
    /// The path to read from
    path: std::path::PathBuf,
}

mod bencode {
    use core::panic;
    use std::collections::BTreeMap;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Value {
        Bytes(Vec<u8>),
        Int(i64),
        List(Vec<Value>),
        Dict(Mapping),
    }

    pub type Mapping = BTreeMap<String, Value>;

    fn decode_bytes(encoded_value: &[u8]) -> (Value, &[u8]) {
        let idx = encoded_value
            .iter()
            .position(|&a| a == b':')
            .expect("unable to find ':' in the string");
        let (number, rest) = &encoded_value.split_at(idx);
        let number = std::str::from_utf8(number)
            .expect("able to convert to utf8")
            .parse()
            .expect("able to parse string lenght");
        let (s, rest) = &rest[1..].split_at(number);
        (Value::Bytes(s.to_vec()), rest)
    }

    fn decode_int(encoded_value: &[u8]) -> (Value, &[u8]) {
        let idx = encoded_value
            .iter()
            .position(|&a| a == b'e')
            .expect("unable to find ':' in the string");
        let (v, rest) = encoded_value.split_at(idx + 1);
        // iXXXe => XXX
        let v = &v[1..idx];
        match v {
            [b'0'] => (Value::Int(0), rest),
            [b'-', b'0', ..] => panic!("invalid integer value"),
            [b'0', ..] => panic!("invalid integer value"),
            x => {
                let x = std::str::from_utf8(x)
                    .expect("invalid utf8")
                    .parse()
                    .expect("correct int");
                (Value::Int(x), rest)
            }
        }
    }

    pub fn decode_lst(encoded_value: &[u8]) -> (Value, &[u8]) {
        let mut lst = Vec::new();
        let mut l = &encoded_value[1..];
        loop {
            if l[0] == b'e' {
                break;
            }
            let (v, r) = decode(l);
            l = r;
            lst.push(v);
        }
        (Value::List(lst), &l[1..])
    }

    pub fn decode_dict(encoded_value: &[u8]) -> (Value, &[u8]) {
        let mut dict = Mapping::new();
        let mut l = &encoded_value[1..];
        loop {
            if l[0] == b'e' {
                break;
            }
            let (k, r) = decode(l);
            let k = if let Value::Bytes(b) = k {
                std::str::from_utf8(&b)
                    .expect("unable to cast to string")
                    .to_string()
            } else {
                panic!("Dict structure incorrect -- key has to be string/bytes");
            };

            l = r;
            let (v, r) = decode(l);
            l = r;

            dict.insert(k, v);
        }

        (Value::Dict(dict), &l[1..])
    }

    pub fn decode(encoded_value: &[u8]) -> (Value, &[u8]) {
        match encoded_value {
            [b'd', b'e', ..] => (Value::Dict(Default::default()), &encoded_value[2..]),
            [b'l', ..] => decode_lst(encoded_value),
            [b'd', ..] => decode_dict(encoded_value),
            [b'i', ..] => decode_int(encoded_value),
            [b'0'..=b'9', ..] => decode_bytes(encoded_value),
            _ => {
                unimplemented!("missing")
            }
        }
    }

    pub fn format_helper(curr: &Value) -> String {
        match curr {
            Value::Bytes(b) => {
                let s = match std::str::from_utf8(b) {
                    Ok(v) => v.to_string(),
                    Err(_) => format!("{:?}", b),
                };
                format!("\"{}\"", s,)
            }
            Value::Int(i) => format!("{i}"),
            Value::List(l) => {
                format!(
                    "[{}]",
                    l.iter().map(format_helper).collect::<Vec<_>>().join(",")
                )
            }
            Value::Dict(d) => {
                format!(
                    "{{{}}}",
                    d.iter()
                        .map(|(k, v)| format!("\"{}\":{}", k, format_helper(v)))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            }
        }
    }

    pub fn extract_dict(value: &Value) -> &Mapping {
        if let Value::Dict(d) = value {
            d
        } else {
            panic!("cannot extract dict from Value")
        }
    }

    pub fn extract_int(value: &Value) -> &i64 {
        if let Value::Int(d) = value {
            d
        } else {
            panic!("cannot extract int from Value")
        }
    }

    pub fn extract_bytes(value: &Value) -> &Vec<u8> {
        if let Value::Bytes(l) = value {
            l
        } else {
            panic!("cannot extract int from Value <{:?}>", value)
        }
    }

    pub fn encode(v: &Value) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_inner(v, &mut buf);
        buf
    }

    fn encode_inner(v: &Value, buf: &mut Vec<u8>) {
        match v {
            Value::Bytes(b) => encode_bytes(b, buf),
            Value::Int(i) => encode_int(*i, buf),
            Value::List(l) => encode_list(l, buf),
            Value::Dict(d) => encode_dict(d, buf),
        }
    }

    fn encode_dict(value: &Mapping, buf: &mut Vec<u8>) {
        buf.push(b'd');
        for (k, v) in value {
            let k = k.as_bytes();
            encode_bytes(k, buf);
            encode_inner(v, buf);
        }
        buf.push(b'e');
    }

    fn encode_list(value: &[Value], buf: &mut Vec<u8>) {
        buf.push(b'l');
        for v in value {
            encode_inner(v, buf);
        }
        buf.push(b'e');
    }

    fn encode_int(value: i64, buf: &mut Vec<u8>) {
        buf.extend_from_slice(format!("i{}e", value).as_bytes());
    }

    fn encode_bytes(value: &[u8], buf: &mut Vec<u8>) {
        buf.extend_from_slice(format!("{}", value.len()).as_bytes());
        buf.push(b':');
        buf.extend_from_slice(value);
    }

    #[cfg(test)]
    mod test {
        use super::*;
        #[test]
        fn test_decode_bytes() {
            let b = "5:hello".as_bytes();
            let (v, r) = decode(b);
            assert!(r.is_empty());
            assert_eq!(v, Value::Bytes("hello".as_bytes().to_vec()));
        }

        #[test]
        fn test_decode_int() {
            let i = "i52e".as_bytes();
            let (v, r) = decode(i);
            assert!(r.is_empty());
            assert_eq!(v, Value::Int(52));

            let b = "i-52e".as_bytes();
            let (v, r) = decode(b);
            assert!(r.is_empty());
            assert_eq!(v, Value::Int(-52));
        }

        #[test]
        fn test_decode_list() {
            let l = "l5:helloi52ee".as_bytes();
            let (v, r) = decode(l);
            assert!(r.is_empty());
            assert_eq!(
                v,
                Value::List(vec![
                    Value::Bytes("hello".as_bytes().to_vec()),
                    Value::Int(52)
                ])
            );
        }

        #[test]
        fn test_decode_dict() {
            let d = "d3:foo3:bar5:helloi52ee".as_bytes();
            let (v, r) = decode(d);
            assert!(r.is_empty());
            let mut d = Mapping::new();
            d.insert("foo".to_string(), Value::Bytes("bar".as_bytes().to_vec()));
            d.insert("hello".to_string(), Value::Int(52));

            assert_eq!(v, Value::Dict(d));
        }

        #[test]
        fn test_encode_bytes() {
            let input = Value::Bytes("hello".as_bytes().to_vec());
            let b = "5:hello".as_bytes();
            let v = encode(&input);
            assert_eq!(b, &v);
        }

        #[test]
        fn test_encode_int() {
            let val = Value::Int(52);
            let i = "i52e".as_bytes();
            let v = encode(&val);
            assert_eq!(v, i);

            let val = Value::Int(-52);
            let i = "i-52e".as_bytes();
            let v = encode(&val);
            assert_eq!(v, i);
        }

        #[test]
        fn test_encode_list() {
            let inp = Value::List(vec![
                Value::Bytes("hello".as_bytes().to_vec()),
                Value::Int(52),
            ]);
            let l = "l5:helloi52ee".as_bytes();
            let v = encode(&inp);
            assert_eq!(v, l);
        }

        #[test]
        fn test_encode_dict() {
            let mut d = Mapping::new();
            d.insert("foo".to_string(), Value::Bytes("bar".as_bytes().to_vec()));
            d.insert("hello".to_string(), Value::Int(52));
            let d = Value::Dict(d);
            let inp = "d3:foo3:bar5:helloi52ee";
            let v = encode(&d);
            let v = std::str::from_utf8(&v).unwrap();

            assert_eq!(v, inp);
        }
    }
}

fn decode(bencode: &[u8]) {
    let (s, _) = bencode::decode(bencode);
    println!("{}", bencode::format_helper(&s));
}

fn digest_to_str(digest: &[u8]) -> String {
    let mut f = String::new();
    for d in digest {
        f.push_str(&format!("{:0>2x}", d));
    }
    f
}

type Sha1Hash = [u8; 20];

#[derive(Debug, Clone)]
struct TorrentFile {
    announce: String,
    info: TorrentInfo,
}

impl TryFrom<bencode::Value> for TorrentFile {
    type Error = String;

    fn try_from(value: bencode::Value) -> Result<Self, Self::Error> {
        let d = if let bencode::Value::Dict(d) = value {
            d
        } else {
            return Err("Unable to convert as top level is not dict".to_string());
        };
        Ok(TorrentFile {
            announce: bencode::format_helper(&d["announce"])
                .trim_matches('"')
                .to_string(),
            info: d["info"].clone().try_into()?,
        })
    }
}

#[derive(Debug, Clone)]
struct TorrentInfo {
    length: usize,
    name: String,
    piece_length: usize,
    pieces: Vec<Sha1Hash>,
    value: bencode::Value,
}

impl TorrentInfo {
    pub fn hash(&self) -> String {
        let mut hasher = sha1::Sha1::default();
        hasher.update(&bencode::encode(&self.value));
        let digest = hasher.finalize();
        digest_to_str(digest.as_slice())
    }

    pub fn hash_raw(&self) -> Vec<u8> {
        let mut hasher = sha1::Sha1::default();
        hasher.update(&bencode::encode(&self.value));
        let digest = hasher.finalize();
        digest.as_slice().to_vec()
    }
}

impl TryFrom<bencode::Value> for TorrentInfo {
    type Error = String;

    fn try_from(value: bencode::Value) -> Result<Self, Self::Error> {
        let d = if let bencode::Value::Dict(d) = &value {
            d
        } else {
            return Err("Unable to convert as top level is not dict".to_string());
        };

        let len = bencode::extract_int(&d["length"]);
        let name = bencode::format_helper(&d["name"])
            .trim_matches('"')
            .to_string();

        let piece_length = bencode::extract_int(&d["piece length"]);

        let piece_hashes = bencode::extract_bytes(&d["pieces"]);
        let pieces: Vec<_> = piece_hashes
            .chunks_exact(20)
            .map(|c| c.try_into().unwrap())
            .collect();

        Ok(Self {
            length: *len as _,
            name,
            piece_length: *piece_length as _,
            pieces,
            value,
        })
    }
}

fn info(path: impl AsRef<std::path::Path>) {
    let bcode = std::fs::read(path).expect("file exists");
    let (s, _) = bencode::decode(&bcode);
    // Tracker URL: http://bittorrent-test-tracker.codecrafters.io/announce
    // Length: 92063

    let bcode: TorrentFile = s.try_into().expect("unable to covert into torrent file");
    let digest = bcode.info.hash();

    let pieces: Vec<_> = bcode.info.pieces.iter().map(|v| digest_to_str(v)).collect();
    let pieces = pieces.join("\n");

    println!(
        r#"Name: {}
Tracker URL: {}
Length: {}
Info Hash: {}
Piece Length: {}
Piece Hashes:
{}"#,
        bcode.info.name, bcode.announce, bcode.info.length, digest, bcode.info.piece_length, pieces
    );
}

#[derive(Debug, Clone, Serialize)]
struct QueryParams {
    #[serde(skip)]
    info_hash: Vec<u8>,
    peer_id: String,
    port: u16,
    uploaded: usize,
    downloaded: usize,
    left: usize,
    #[serde(serialize_with = "bool_to_int")]
    compact: bool,
}

impl QueryParams {
    fn hash_info_hash(&self) -> String {
        let mut v = String::new();
        for e in &self.info_hash {
            // compression to make sure that we can same some bytes
            match e {
                0x4c => v.push('L'),
                0x54 => v.push('T'),
                0x68 => v.push('h'),
                0x71 => v.push('q'),
                _ => v.push_str(&format!("%{:0>2x}", e)),
            }
        }
        v
    }
}

fn bool_to_int<S>(v: &bool, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let v = if *v { 1 } else { 0 };
    serializer.serialize_u8(v)
}

// {"complete": Int(3), "incomplete": Int(0), "interval": Int(60), "min interval": Int(60), "peers": Bytes([165, 232, 33, 77, 201, 42, 178, 62, 82, 89, 200, 248, 178, 62, 85, 20, 201, 33])}
#[derive(Debug, Clone)]
struct TrackerResponse {
    peers: Vec<SocketAddr>,
}

impl TryFrom<bencode::Value> for TrackerResponse {
    type Error = String;

    fn try_from(value: bencode::Value) -> Result<Self, Self::Error> {
        let d = match value {
            bencode::Value::Dict(d) => d,
            _ => return Err("unable to extract dict".into()),
        };

        let peers = match d.get("peers") {
            None => return Err("missing peers".into()),
            Some(bencode::Value::Bytes(b)) => b
                .chunks_exact(6)
                .map(|v| {
                    let ip = Ipv4Addr::new(v[0], v[1], v[2], v[3]);
                    let port = u16::from_be_bytes(v[4..].try_into().unwrap());
                    SocketAddrV4::new(ip, port).into()
                })
                .collect(),
            Some(_) => return Err("peers has the incorrect type".into()),
        };

        Ok(Self { peers })
    }
}

fn torrent_file(path: impl AsRef<std::path::Path>) -> TorrentFile {
    let bcode = std::fs::read(path).expect("file exists");
    let (s, _) = bencode::decode(&bcode);
    s.try_into().unwrap()
}

fn peers_load(torrent: TorrentFile) -> TrackerResponse {
    let params = QueryParams {
        info_hash: torrent.info.hash_raw(),
        peer_id: "00112233445566778899".to_string(),
        port: 6881,
        uploaded: 0,
        downloaded: 0,
        left: torrent.info.length,
        compact: true,
    };
    let url = torrent.announce;
    let ih = params.hash_info_hash();
    let url = format!(
        "{}?{}&info_hash={}",
        url,
        serde_urlencoded::to_string(params).expect("able to convert to url encoding"),
        ih
    );
    let body = reqwest::blocking::get(url).expect("able to load url tracker");
    let b = body
        .bytes()
        .expect("able to get bytes from tracker response");

    let (v_org, _) = bencode::decode(b.as_ref());
    let v = bencode::extract_dict(&v_org);
    let f = "failure reason";
    if let Some(b) = v.get(f) {
        let b = bencode::extract_bytes(b);
        panic!("{:?}", std::str::from_utf8(b).unwrap());
    }

    v_org.try_into().unwrap()
}

fn peers(path: impl AsRef<std::path::Path>) {
    let torrent = torrent_file(path);
    let tracker = peers_load(torrent);
    for peer in tracker.peers {
        println!("{}", peer);
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
struct HandshakePacket {
    // length of the protocol string (BitTorrent protocol) which is 19 (1 byte)
    length: u8,
    // the string BitTorrent protocol (19 bytes)
    protocol_string: [u8; 19], // BitTorrent protocol
    // eight reserved bytes, which are all set to zero (8 bytes)
    _reserved: [u8; 8],
    // sha1 infohash (20 bytes) (NOT the hexadecimal representation, which is 40 bytes long)
    info_hash: [u8; 20],
    // peer id (20 bytes) (you can use 00112233445566778899 for this challenge)
    peer_id: [u8; 20],
}

impl HandshakePacket {
    fn new(info_hash: [u8; 20], peer_id: [u8; 20]) -> Self {
        Self {
            length: 19,
            protocol_string: "BitTorrent protocol".as_bytes().try_into().unwrap(),
            _reserved: [0; 8],
            info_hash,
            peer_id,
        }
    }

    fn to_slice(&self) -> &[u8; std::mem::size_of::<Self>()] {
        unsafe { std::mem::transmute(self) }
    }

    fn from_slice(from: &[u8; std::mem::size_of::<Self>()]) -> &Self {
        unsafe { std::mem::transmute(from) }
    }
}

fn handshake(path: impl AsRef<std::path::Path>, addr: SocketAddr) {
    let torrent = torrent_file(path);
    let info_hash = torrent.info.hash_raw();

    let handshake = HandshakePacket::new(
        info_hash.as_slice().try_into().unwrap(),
        "00112233445566778899".as_bytes().try_into().unwrap(),
    );

    let buf = handshake.to_slice();
    let mut buf_in = [0; std::mem::size_of::<HandshakePacket>()];

    let mut tcp =
        std::net::TcpStream::connect(addr).expect("able to create TCP connection to peer");
    tcp.write_all(buf)
        .expect("able to write the buffer and the the data to the peer");

    tcp.read_exact(&mut buf_in)
        .expect("able to read the full response");

    let res = HandshakePacket::from_slice(&buf_in);

    println!(
        "Peer ID: {}",
        res.peer_id.map(|c| format!("{:0>2x}", c)).join("")
    );
}

fn main() {
    let args = Args::parse();
    match args.command {
        Commands::Decode(Decode { bencode }) => decode(bencode.as_bytes()),
        Commands::Info(Info { path }) => info(path),
        Commands::Peers(Peers { path }) => peers(path),
        Commands::Handshake(Handshake { path, addr }) => handshake(path, addr),
    }
}
