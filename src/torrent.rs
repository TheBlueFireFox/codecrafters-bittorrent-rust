use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::Path,
};

use anyhow::Context;
use bytes::{Buf as _, BufMut};
use serde::Serialize;
use sha1::Digest as _;
use tokio::{io::Interest, net::TcpStream};

use crate::bencode;

pub fn digest_to_str(digest: &[u8]) -> String {
    let mut f = String::new();
    for d in digest {
        f.push_str(&format!("{:0>2x}", d));
    }
    f
}

type Sha1Hash = [u8; 20];

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

pub fn sha1(buf: &[u8]) -> Vec<u8> {
    let mut hasher = sha1::Sha1::default();
    hasher.update(buf);
    let digest = hasher.finalize();
    digest.as_slice().to_vec()
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
        digest_to_str(digest.as_slice())
    }

    pub fn hash_raw(&self) -> Vec<u8> {
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
    eprintln!("{}", hex::encode(&bcode));

    let (s, _) = bencode::decode(&bcode);
    Ok(s.try_into().unwrap())
}

pub async fn peers_load(torrent: &TorrentFile) -> anyhow::Result<TrackerResponse> {
    let params = QueryParams {
        info_hash: torrent.info.hash_raw(),
        peer_id: "00112233445566778899".to_string(),
        port: 6881,
        uploaded: 0,
        downloaded: 0,
        left: torrent.info.length,
        compact: true,
    };
    let url = &torrent.announce;
    let ih = params.hash_info_hash();
    let url = format!(
        "{}?{}&info_hash={}",
        url,
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

async fn read_from_stream(stream: &TcpStream, mut buf: &mut [u8]) -> tokio::io::Result<usize> {
    let mut size = 0;
    loop {
        let ready = stream
            .ready(Interest::READABLE | Interest::WRITABLE)
            .await?;

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
            Err(err) => break Err(err),
        }
    }
}

async fn write_to_stream(stream: &mut TcpStream, buf: &[u8]) -> anyhow::Result<()> {
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
    info_hash: &[u8],
    addr: SocketAddr,
) -> anyhow::Result<(TcpStream, HandshakePacket)> {
    let handshake = HandshakePacket::new(
        info_hash.try_into().unwrap(),
        "00112233445566778899".as_bytes().try_into().unwrap(),
    );

    let buf = handshake.to_slice();
    let mut buf_in = [0; std::mem::size_of::<HandshakePacket>()];

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .context("able to create TCP connection to peer during the handshake")?;

    write_to_stream(&mut stream, buf)
        .await
        .context("able to write to stream duirng the handshake")?;

    let read_count = read_from_stream(&stream, &mut buf_in)
        .await
        .context("able to read from stream during the handshake period")?;

    assert_eq!(read_count, buf_in.len());

    Ok((stream, HandshakePacket::from_slice(&buf_in).clone()))
}

async fn read_peer_message(stream: &TcpStream) -> anyhow::Result<Vec<u8>> {
    // Peer messages consist of a message length prefix (4 bytes), message id (1 byte) and a payload (variable size).
    // we are going to load everything upto the payload size in the first run and after that the
    // payload behind it
    const LENGHT_PREFIX: usize = 4;

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

pub async fn create_peer_connect(
    torrent: &TorrentInfo,
    peer: SocketAddr,
) -> anyhow::Result<(tokio::net::TcpStream, Vec<u8>)> {
    // 3) Establish a TCP connection with a peer, and perform a handshake
    eprintln!("handshake for peer 0");
    let (stream, _handshake_response) = do_handshake(&torrent.hash_raw(), peer)
        .await
        .context("while handshake")?;

    // 4) Exchange multiple peer messages to download the file
    // 4.1) Wait for a bitfield message from the peer indicating which pieces it has
    eprintln!("waiting for bitfield of peer");
    let bf = wait_for_bitfield(&stream)
        .await
        .context("waiting for bitfield")?;

    Ok((stream, bf))
}

// The first byte of the bitfield corresponds to indices 0 - 7 from high bit to low bit,
// respectively. The next one 8-15, etc. Spare bits at the end are set to zero.
pub async fn wait_for_bitfield(stream: &TcpStream) -> anyhow::Result<Vec<u8>> {
    let bitfield_buf = read_peer_message(stream)
        .await
        .context("reading bitfield message")?;

    assert_eq!(bitfield_buf[4], 5);

    Ok(bitfield_buf[5..].to_vec())
}

pub async fn send_interested(stream: &mut TcpStream) -> anyhow::Result<()> {
    let buf = [0, 0, 0, 5, 2];
    write_to_stream(stream, &buf)
        .await
        .context("while writing to stream")?;
    Ok(())
}

pub async fn wait_for_unchoke(stream: &TcpStream) -> anyhow::Result<()> {
    let unchoke = read_peer_message(stream).await?;

    assert_eq!(unchoke[4], 1);
    Ok(())
}

pub async fn send_request_message(
    stream: &mut TcpStream,
    piece_nr: usize,
    offset: usize,
    length: usize,
) -> anyhow::Result<()> {
    // we can use BytesMut while using a constant buffer :)
    const SIZE: usize = 4 + 1 + 4 + 4 + 4;
    let mut mbuf = [0; SIZE];
    let mut buf = &mut mbuf[..];

    // message length prefix (4 bytes)
    buf.put_u32(SIZE as _);
    // The message id for request is 6
    buf.put_u8(6);
    // index: the zero-based piece index
    buf.put_u32(piece_nr as _);
    // begin: the zero-based byte offset within the piece
    buf.put_u32(offset as _);
    // length: the length of the block in bytes
    buf.put_u32(length as _);

    write_to_stream(stream, &mbuf)
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
    stream: &mut TcpStream,
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
        eprintln!(
            "downloading {} -- {} -- {}",
            piece_nr,
            offset,
            length + offset
        );
        send_request_message(stream, piece_nr, offset, length).await?;
        // 4.6) Wait for a piece message for each block you've requested
        let block = wait_for_piece(stream).await?;

        let mut b = &block[..];
        let _l_msg_len = b.get_u32();
        let l_id = b.get_u8();
        let l_piece = b.get_u32();
        let l_offset = b.get_u32();

        assert_eq!(l_id, 7);
        assert_eq!(l_piece as usize, piece_nr);
        assert_eq!(l_piece as usize, piece_nr);
        assert_eq!(l_offset as usize, offset);

        // 5) Combine all loaded pieces,
        let f = &block[5 + 8..];
        assert_eq!(
            f.len(),
            length,
            "foo {} -- {} -- {} -- {:?}",
            f.len(),
            length,
            step,
            block
        );
        storage.extend_from_slice(f);
    }
    // 6) Check the integrity of each piece by comparing it's hash with the piece hash value found in the torrent file.
    let digest = sha1(&storage);

    assert_eq!(storage.len(), piece_length);
    assert_eq!(digest, &piece_hash[..], "incorrect digest");

    Ok(storage)
}
