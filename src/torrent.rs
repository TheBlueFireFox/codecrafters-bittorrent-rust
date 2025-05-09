#![allow(dead_code)]
use std::{
    collections::HashMap,
    fmt::Write,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::Path,
};

use anyhow::Context;
use rand::distr::{Alphanumeric, SampleString};
use serde::Serialize;
use sha1::Digest as _;
use tokio::{io::Interest, net::TcpStream};

use crate::{
    bencode,
    message::{self, Message},
};

pub fn digest_to_str(digest: Sha1Hash) -> String {
    let mut f = String::with_capacity(40);
    for d in digest {
        let _ = write!(&mut f, "{:0>2x}", d);
    }
    f
}

pub type Sha1Hash = [u8; 20];

#[derive(Debug, Clone)]
pub struct TorrentMagnet {
    pub hash: Sha1Hash,
    pub name: String,
    pub tracker: String,
}

impl TryFrom<&str> for TorrentMagnet {
    type Error = String;

    fn try_from(link: &str) -> Result<Self, Self::Error> {
        let (magnet, url_encoded) = link
            .split_once(":?")
            .ok_or_else(|| "unable to split up the magnet link".to_string())?;

        assert_eq!("magnet", magnet);

        let parts: HashMap<String, String> =
            serde_urlencoded::from_str(url_encoded).map_err(|e| format!("foo {e}"))?;

        let hash_str = &parts["xt"];
        let name = &parts["dn"];
        let tracker = &parts["tr"];

        let (_, hash_str) = hash_str
            .rsplit_once(":")
            .ok_or_else(|| "unable to split up the magnet link".to_string())?;

        assert_eq!(40, hash_str.len());
        let mut hash = [0; 20];
        for i in (0..40).step_by(2) {
            hash[i / 2] = u8::from_str_radix(&hash_str[i..i + 2], 16)
                .map_err(|e| format!("while parsing from radix{e}"))?;
        }

        Ok(Self {
            hash,
            name: name.clone(),
            tracker: tracker.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct TorrentFile {
    pub announce: String,
    pub info: TorrentInfo,
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

pub fn sha1(buf: &[u8]) -> Sha1Hash {
    let mut hasher = sha1::Sha1::default();
    hasher.update(buf);
    let digest = hasher.finalize();
    digest
        .as_slice()
        .try_into()
        .expect("SHA1 should always be the same len")
}

#[derive(Debug, Clone)]
pub struct TorrentInfo {
    pub length: usize,
    pub name: String,
    pub piece_length: usize,
    pub pieces: Vec<Sha1Hash>,
    pub value: bencode::Value,
}

impl TorrentInfo {
    pub fn hash(&self) -> String {
        let digest = sha1(&bencode::encode(&self.value));
        digest_to_str(digest)
    }

    pub fn hash_raw(&self) -> Sha1Hash {
        sha1(&bencode::encode(&self.value))
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

#[derive(Debug, Clone, Serialize)]
struct QueryParams {
    #[serde(skip)]
    pub info_hash: Vec<u8>,
    pub peer_id: String,
    pub port: u16,
    pub uploaded: usize,
    pub downloaded: usize,
    pub left: usize,
    #[serde(serialize_with = "bool_to_int")]
    pub compact: bool,
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
pub struct TrackerResponse {
    pub peers: Vec<SocketAddr>,
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

pub async fn torrent_file(path: impl AsRef<Path>) -> anyhow::Result<TorrentFile> {
    let bcode = tokio::fs::read(path).await.context("file exists")?;

    let (s, _) = bencode::decode(&bcode);
    Ok(s.try_into().unwrap())
}

pub fn random_peer_id() -> [u8; 20] {
    Alphanumeric
        .sample_string(&mut rand::rng(), 20)
        .as_bytes()
        .try_into()
        .unwrap()
}

pub async fn peers_load(
    tracker_url: &str,
    tracker_hash: Sha1Hash,
    size: usize,
    my_peer_id: Sha1Hash,
) -> anyhow::Result<TrackerResponse> {
    let params = QueryParams {
        info_hash: tracker_hash.to_vec(),
        peer_id: String::from_utf8(my_peer_id.to_vec())?,
        port: 6881,
        uploaded: 0,
        downloaded: 0,
        left: size,
        compact: true,
    };
    let ih = params.hash_info_hash();
    let url = format!(
        "{}?{}&info_hash={}",
        tracker_url,
        serde_urlencoded::to_string(params).context("able to convert to url encoding")?,
        ih
    );

    let body = reqwest::get(url)
        .await
        .context("able to load url tracker")?;

    let b = body
        .bytes()
        .await
        .expect("able to get bytes from tracker response");

    let (v_org, _) = bencode::decode(b.as_ref());
    let v = bencode::extract_dict(&v_org);
    let f = "failure reason";
    if let Some(b) = v.get(f) {
        let b = bencode::extract_bytes(b);
        panic!("{:?}", std::str::from_utf8(b).unwrap());
    }

    Ok(v_org.try_into().unwrap())
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct HandshakePacket {
    // length of the protocol string (BitTorrent protocol) which is 19 (1 byte)
    pub length: u8,
    // the string BitTorrent protocol (19 bytes)
    pub protocol_string: [u8; 19], // BitTorrent protocol
    // eight reserved bytes, which are all set to zero (8 bytes)
    pub _reserved: [u8; 8],
    // sha1 infohash (20 bytes) (NOT the hexadecimal representation, which is 40 bytes long)
    pub info_hash: [u8; 20],
    // peer id (20 bytes) (you can use 00112233445566778899 for this challenge)
    pub peer_id: [u8; 20],
}

// Extension handshake a client must set the 20th bit from the right
const HANDSHAKE_RESERVED: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00];

impl HandshakePacket {
    pub fn new(info_hash: Sha1Hash, peer_id: Sha1Hash) -> Self {
        Self {
            length: 19,
            protocol_string: *b"BitTorrent protocol",
            _reserved: [0; 8],
            info_hash,
            peer_id,
        }
    }

    pub fn new_extension(info_hash: Sha1Hash, peer_id: Sha1Hash) -> Self {
        Self {
            length: 19,
            protocol_string: *b"BitTorrent protocol",
            _reserved: HANDSHAKE_RESERVED,
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

async fn read_from_stream(stream: &TcpStream, mut buf: &mut [u8]) -> anyhow::Result<usize> {
    let mut size = 0;
    loop {
        let ready = stream
            .ready(Interest::READABLE)
            .await
            .context("while waiting for readable")?;

        if !ready.is_readable() {
            continue;
        }

        match stream.try_read(buf) {
            Ok(0) => break Ok(0),
            Ok(n) => {
                size += n;
                if n == buf.len() {
                    break Ok(size);
                }
                // move buffer forward
                buf = &mut buf[n..];
            }
            Err(ref e) if e.kind() == tokio::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(err) => break Err(err).context("while trying to read from the wire")?,
        }
    }
}

async fn write_to_stream(stream: &TcpStream, buf: &[u8]) -> anyhow::Result<()> {
    let mut written = 0;
    loop {
        let ready = stream
            .ready(Interest::WRITABLE)
            .await
            .context("while waiting for readable")?;

        if !ready.is_writable() {
            continue;
        }

        match stream.try_write(&buf[written..]) {
            Ok(n) => {
                written += n;
                if written == buf.len() {
                    break Ok(());
                }
            }
            Err(ref e) if e.kind() == tokio::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => Err(e).context("while trying to write to wire")?,
        }
    }
}

pub async fn do_handshake(
    addr: SocketAddr,
    packet: HandshakePacket,
) -> anyhow::Result<(TcpStream, HandshakePacket)> {
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .context("able to create TCP connection to peer during the handshake")?;

    let buf = packet.to_slice();
    let mut buf_in = [0; std::mem::size_of::<HandshakePacket>()];

    write_to_stream(&stream, buf)
        .await
        .context("able to write to stream duirng the handshake")?;

    let read_count = read_from_stream(&stream, &mut buf_in)
        .await
        .context("able to read from stream during the handshake period")?;

    assert_eq!(read_count, buf_in.len());

    Ok((stream, HandshakePacket::from_slice(&buf_in).clone()))
}

const UT_METADATA_ID: i64 = 42;

fn create_extension_handshake() -> Vec<u8> {
    let mut buf = Vec::with_capacity(100);

    let extention_id = [("ut_metadata".to_string(), UT_METADATA_ID)].into();
    let msg = Message::Extension(message::Extension::Handshake(message::ExtensionHandshake {
        extention_id,
    }));

    msg.write(&mut buf);

    buf
}

async fn handle_extention_handshake(stream: &TcpStream) -> anyhow::Result<u8> {
    let cm = create_extension_handshake();
    write_to_stream(stream, &cm).await?;

    let msg = read_peer_message(stream).await?;
    let msg = Message::read(&msg);
    match msg {
        Message::Extension(message::Extension::Handshake(e)) => {
            Ok(e.extention_id["ut_metadata"] as _)
        }
        _ => Err(anyhow::anyhow!("Invalid extention handshake format")),
    }
}

pub async fn magnet_create_peer_connect(
    info_hash: Sha1Hash,
    addr: SocketAddr,
    my_peer_id: Sha1Hash,
) -> anyhow::Result<(TcpStream, HandshakePacket, u8)> {
    let (tcp, _bit_field, handshake) =
        create_peer_connect_extension(info_hash, addr, my_peer_id).await?;

    let t = handshake
        ._reserved
        .iter()
        .zip(HANDSHAKE_RESERVED)
        .all(|(r, e)| (r & e) == e);

    assert!(t, "peer does not support the magnet extention");

    let id = handle_extention_handshake(&tcp).await?;

    Ok((tcp, handshake, id))
}

pub async fn magnet_load_meta_data(
    stream: &TcpStream,
    ext_id_peer: u8,
    piece: i64,
) -> anyhow::Result<TorrentInfo> {
    use message::*;
    let req = message::ExtensionMetadata::Request { piece };
    let req = Extension::Extention(ext_id_peer, req);
    let req = Message::Extension(req);

    let mut buf = vec![];
    req.write(&mut buf);

    write_to_stream(stream, &buf).await?;

    let buf = read_peer_message(stream).await?;

    let msg = Message::read(&buf);
    match msg {
        Message::Extension(Extension::Extention(_, ExtensionMetadata::Data { torrent })) => {
            Ok(torrent)
        }
        _ => Err(anyhow::anyhow!("Unsupported msg type")),
    }
}

const LENGHT_PREFIX: usize = 4;

async fn read_peer_message(stream: &TcpStream) -> anyhow::Result<Vec<u8>> {
    // Peer messages consist of a message length prefix (4 bytes), message id (1 byte) and a payload (variable size).
    // we are going to load everything upto the payload size in the first run and after that the
    // payload behind it

    // read message length + message id
    let mut buf = vec![0; LENGHT_PREFIX];
    match read_from_stream(stream, &mut buf).await {
        Err(err) => return Err(anyhow::anyhow!("while reading a peer message {}", err)),
        Ok(0) => return Err(anyhow::anyhow!("peer closed connection")),
        Ok(LENGHT_PREFIX) => {}
        Ok(n) => {
            return Err(anyhow::anyhow!(
                "unexpected prefix read size {} -- {:?} -- {}",
                n,
                buf,
                buf.len()
            ));
        }
    }

    let size = u32::from_be_bytes(buf[..4].try_into().expect("able to cast to u32"));
    let size = size as usize;

    buf.resize(LENGHT_PREFIX + size, 0);
    match read_from_stream(stream, &mut buf[LENGHT_PREFIX..]).await {
        Err(err) => panic!("while reading a peer message {}", err),
        Ok(0) => panic!("peer closed connection"),
        Ok(n) => assert_eq!(
            n,
            size,
            "unexpected read size {} -- {} -- {:?}",
            n,
            size,
            buf.len()
        ),
    }

    Ok(buf)
}

async fn inner_create_peer_connect(
    peer: SocketAddr,
    packet: HandshakePacket,
) -> anyhow::Result<(tokio::net::TcpStream, Vec<u8>, HandshakePacket)> {
    // 3) Establish a TCP connection with a peer, and perform a handshake
    eprintln!("starting the handshake for peer <{peer}>");

    let (stream, handshake_response) = do_handshake(peer, packet)
        .await
        .context("while handshake")?;

    // 4) Exchange multiple peer messages to download the file
    // 4.1) Wait for a bitfield message from the peer indicating which pieces it has
    eprintln!("waiting for bitfield of peer <{peer}>");
    let bf = wait_for_bitfield(&stream)
        .await
        .context("waiting for bitfield")?;

    Ok((stream, bf, handshake_response))
}

pub async fn create_peer_connect(
    torrent: Sha1Hash,
    peer: SocketAddr,
    my_peer_id: Sha1Hash,
) -> anyhow::Result<(tokio::net::TcpStream, Vec<u8>, HandshakePacket)> {
    let packet = HandshakePacket::new(torrent, my_peer_id);
    inner_create_peer_connect(peer, packet).await
}

pub async fn create_peer_connect_extension(
    torrent: Sha1Hash,
    peer: SocketAddr,
    my_peer_id: Sha1Hash,
) -> anyhow::Result<(tokio::net::TcpStream, Vec<u8>, HandshakePacket)> {
    let packet = HandshakePacket::new_extension(torrent, my_peer_id);
    inner_create_peer_connect(peer, packet).await
}

// The first byte of the bitfield corresponds to indices 0 - 7 from high bit to low bit,
// respectively. The next one 8-15, etc. Spare bits at the end are set to zero.
pub async fn wait_for_bitfield(stream: &TcpStream) -> anyhow::Result<Vec<u8>> {
    let bitfield_buf = read_peer_message(stream)
        .await
        .context("reading bitfield message")?;

    let msg = Message::read(&bitfield_buf);

    assert!(matches!(msg, Message::BitField(_)));

    Ok(bitfield_buf[5..].to_vec())
}

pub async fn send_interested(stream: &TcpStream) -> anyhow::Result<()> {
    let mut buf = vec![];
    Message::Interested.write(&mut buf);

    write_to_stream(stream, &buf)
        .await
        .context("while writing to stream")?;
    Ok(())
}

pub async fn wait_for_unchoke(stream: &TcpStream) -> anyhow::Result<()> {
    let unchoke = read_peer_message(stream).await?;

    let msg = Message::read(&unchoke);

    assert!(
        matches!(msg, Message::Unchoke),
        "unexpected unchoke type {:?}",
        msg
    );
    Ok(())
}

pub async fn send_request_message(
    stream: &TcpStream,
    piece_nr: usize,
    offset: usize,
    length: usize,
) -> anyhow::Result<()> {
    let mut buf = Vec::with_capacity(100);

    let msg = message::Message::Request(message::Request {
        index: piece_nr as _,
        offset: offset as _,
        length: length as _,
    });

    msg.write(&mut buf);

    write_to_stream(stream, &buf)
        .await
        .context("writing to stream during a request message")?;
    Ok(())
}

pub async fn wait_for_piece(stream: &TcpStream) -> anyhow::Result<Vec<u8>> {
    let pm = read_peer_message(stream).await?;

    assert_eq!(pm[4], 7);

    Ok(pm)
}

pub async fn download_piece(
    stream: &TcpStream,
    piece_nr: usize,
    piece_length: usize,
    piece_hash: &[u8; 20],
) -> anyhow::Result<Vec<u8>> {
    // 4.4) Break the piece into blocks of 16 kiB (16 * 1024 bytes)
    let mut storage = Vec::with_capacity(piece_length);
    let step = 16 * 1024;
    for offset in (0..piece_length).step_by(step) {
        // 4.5) Send a request message for each block
        let length = if offset + step < piece_length {
            step
        } else {
            piece_length - offset
        };

        send_request_message(stream, piece_nr, offset, length).await?;

        // 4.6) Wait for a piece message for each block you've requested
        let block = wait_for_piece(stream).await?;

        // 5) Combine all loaded pieces,
        let msg = message::Message::read(&block);

        let piece = if let message::Message::Piece(piece) = msg {
            piece
        } else {
            panic!("not expected message type received");
        };

        assert_eq!(piece.index as usize, piece_nr);
        assert_eq!(piece.offset as usize, offset);

        storage.extend_from_slice(&piece.piece);
    }
    // 6) Check the integrity of each piece by comparing it's hash with the piece hash value found in the torrent file.
    let digest = sha1(&storage);

    assert_eq!(storage.len(), piece_length);
    assert_eq!(digest, &piece_hash[..], "incorrect digest");

    Ok(storage)
}
