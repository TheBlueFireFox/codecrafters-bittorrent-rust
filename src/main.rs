mod bencode;
mod message;
mod torrent;

use std::{
    collections::{BinaryHeap, HashMap},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, Context};
use clap::Parser;
use tokio::io::AsyncWriteExt;
use torrent::{
    digest_to_str, random_peer_id, HandshakePacket, Sha1Hash, TorrentInfo, TrackerResponse,
};

/// Simple program to greet a person
#[derive(clap::Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
#[clap(rename_all = "snake_case")]
enum Commands {
    Decode(Decode),
    Info(Info),
    Peers(Peers),
    Handshake(Handshake),
    DownloadPiece(DownloadPiece),
    Download(Download),
    MagnetParse(MagnetParse),
    MagnetHandshake(MagnetHandshake),
    MagnetInfo(MagnetInfo),
    MagnetDownloadPiece(MagnetDownloadPiece),
    MagnetDownload(MagnetDownload),
}

#[derive(clap::Args, Debug)]
struct Decode {
    /// The path to read from
    bencode: String,
}

#[derive(clap::Args, Debug)]
struct Handshake {
    /// The path to read from
    path: PathBuf,
    addr: SocketAddr,
}

#[derive(clap::Args, Debug)]
struct Info {
    /// The path to read from
    path: PathBuf,
}

#[derive(clap::Args, Debug)]
struct Peers {
    /// The path to read from
    path: PathBuf,
}

#[derive(clap::Args, Debug)]
struct DownloadPiece {
    #[clap(short = 'o', long = "to", default_value = ".")]
    out_path: std::path::PathBuf,
    /// The path to read from
    path: PathBuf,
    piece: usize,
}

#[derive(clap::Args, Debug)]
struct Download {
    #[clap(short = 'o', long = "to", default_value = ".")]
    out_path: std::path::PathBuf,
    /// The path to read from
    path: PathBuf,
}

#[derive(clap::Args, Debug)]
struct MagnetParse {
    str: String,
}

#[derive(clap::Args, Debug)]
pub struct MagnetHandshake {
    str: String,
}

#[derive(clap::Args, Debug)]
pub struct MagnetInfo {
    str: String,
}

#[derive(clap::Args, Debug)]
pub struct MagnetDownloadPiece {
    #[clap(short = 'o', long = "to", default_value = ".")]
    out_path: std::path::PathBuf,
    /// The link to process from
    link: String,
    piece: usize,
}

#[derive(clap::Args, Debug)]
struct MagnetDownload {
    #[clap(short = 'o', long = "to", default_value = ".")]
    out_path: std::path::PathBuf,
    /// The path to read from
    link: String,
}

fn decode(bencode: &[u8]) {
    let (s, _) = bencode::decode(bencode);
    println!("{}", bencode::format_helper(&s));
}

fn info(path: impl AsRef<Path>) {
    let bcode = std::fs::read(path).expect("file exists");
    let (s, _) = bencode::decode(&bcode);
    // Tracker URL: http://bittorrent-test-tracker.codecrafters.io/announce
    // Length: 92063

    let bcode: torrent::TorrentFile = s.try_into().expect("unable to covert into torrent file");
    let digest = bcode.info.hash();

    let pieces: Vec<_> = bcode
        .info
        .pieces
        .iter()
        .copied()
        .map(torrent::digest_to_str)
        .collect();
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

async fn peers(path: impl AsRef<Path>, my_peer_id: [u8; 20]) -> anyhow::Result<()> {
    let torrent = torrent::torrent_file(path).await?;
    let tracker = torrent::peers_load(
        &torrent.announce,
        torrent.info.hash_raw(),
        torrent.info.length,
        my_peer_id,
    )
    .await?;
    for peer in tracker.peers {
        println!("{}", peer);
    }

    Ok(())
}

async fn handshake(
    path: impl AsRef<Path>,
    addr: SocketAddr,
    my_peer_id: Sha1Hash,
) -> anyhow::Result<()> {
    let torrent = torrent::torrent_file(path).await?;
    let info_hash = torrent.info.hash_raw();
    let packet = HandshakePacket::new(info_hash, my_peer_id);
    let (_, res) = torrent::do_handshake(addr, packet).await?;

    println!("Peer ID: {}", digest_to_str(res.peer_id));

    Ok(())
}

async fn download_piece(
    out_path: impl AsRef<Path>,
    path: impl AsRef<Path>,
    piece_nr: usize,
    my_peer_id: Sha1Hash,
) -> anyhow::Result<()> {
    // 1) Read the torrent file to get the tracker URL
    eprintln!("reading torrent file");
    let torrent = torrent::torrent_file(path).await?;

    assert!(
        torrent.info.pieces.len() > piece_nr,
        "piece number larger then actual count"
    );

    // 2) Perform the tracker GET request to get a list of peers
    eprintln!("loading peers");
    let tracker = torrent::peers_load(
        &torrent.announce,
        torrent.info.hash_raw(),
        torrent.info.length,
        my_peer_id,
    )
    .await?;

    // 3) Establish a TCP connection with a peer, and perform a handshake
    // 4) Exchange multiple peer messages to download the file
    // 4.1) Wait for a bitfield message from the peer indicating which pieces it has
    let mut s = None;
    for peer in tracker.peers {
        eprintln!("using peer nr {}", peer);
        match torrent::create_peer_connect(torrent.info.hash_raw(), peer, my_peer_id)
            .await
            .context("while creating a peer connection during a downlaod")
        {
            Ok(e) => {
                s = Some(Ok(e));
                break;
            }
            Err(err) => {
                s = Some(Err(err));
            }
        }
    }

    let (stream, _bf, _) = s.unwrap()?;

    // 4.2) Send an interested message
    eprintln!("sending interested packet");
    torrent::send_interested(&stream).await?;

    // 4.3) Wait until you receive an unchoke message back
    eprintln!("waiting for unchoke packet");
    torrent::wait_for_unchoke(&stream).await?;

    eprintln!("downlading");

    let piece_length = if torrent.info.pieces.len() - 1 == piece_nr {
        // last piece
        eprintln!("last piece");
        torrent.info.length % torrent.info.piece_length
    } else {
        torrent.info.piece_length
    };

    // 4.4 - 6)
    let storage = torrent::download_piece(
        &stream,
        piece_nr,
        piece_length,
        &torrent.info.pieces[piece_nr],
    )
    .await
    .context("able to download a piece")?;

    tokio::fs::write(&out_path, storage)
        .await
        .context("able to write content")?;

    println!(
        "Piece {} downloaded to {}.",
        piece_nr,
        out_path.as_ref().display()
    );

    Ok(())
}

type TaskQueue = Arc<Mutex<BinaryHeap<Piece>>>;

#[derive(Debug, Clone)]
struct Piece {
    nr: usize,
    len: usize,
    hash: Sha1Hash,
}

impl PartialEq for Piece {
    fn eq(&self, other: &Self) -> bool {
        self.nr == other.nr
    }
}

impl Eq for Piece {}

impl PartialOrd for Piece {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Piece {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.nr.cmp(&self.nr)
    }
}

async fn handle_peer(
    peer: SocketAddr,
    torrent_info: torrent::TorrentInfo,
    task_queue: TaskQueue,
    send_res: tokio::sync::mpsc::Sender<(Piece, Vec<u8>)>,
    my_peer_id: [u8; 20],
) -> anyhow::Result<()> {
    let mut s = None;
    const MAX_TRY: usize = 3;

    for i in 0..MAX_TRY {
        eprintln!("trying to connect to peer <{peer}> try <{i}>");
        match torrent::create_peer_connect(torrent_info.hash_raw(), peer, my_peer_id).await {
            Ok(e) => {
                s = Some(e);
                eprintln!("connection to peer {peer} successful");
                break;
            }
            Err(err) => {
                eprintln!("on try {i} error <{err}> happend");
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    let (stream, _, _) = match s {
        Some(s) => s,
        None => {
            eprintln!("given up in {}", peer);
            return Err(anyhow::anyhow!("peer not responsive"));
        }
    };

    // 4.2) Send an interested message
    eprintln!("sending interested packet for {peer}");
    torrent::send_interested(&stream).await?;

    // 4.3) Wait until you receive an unchoke message back
    eprintln!("waiting for unchoke packet from {peer}");
    torrent::wait_for_unchoke(&stream).await?;

    eprintln!("processing for {peer}");
    loop {
        // download piece
        let piece = {
            let mut queue = task_queue
                .lock()
                .map_err(|_| anyhow::anyhow!("poisoned lock"))?;

            match queue.pop() {
                Some(task) => task,
                None => break,
            }
        };

        match torrent::download_piece(&stream, piece.nr, piece.len, &piece.hash).await {
            Ok(v) => send_res.send((piece, v)).await?,
            Err(err) => {
                // try to download it again next round
                eprintln!("error {err}");
                let mut queue = task_queue
                    .lock()
                    .map_err(|_| anyhow::anyhow!("poisoned lock"))?;
                queue.push(piece);
            }
        }
    }

    Ok(())
}

async fn inner_download(
    out_path: impl AsRef<Path>,
    tracker: &TrackerResponse,
    torrent: &TorrentInfo,
    my_peer_id: Sha1Hash,
) -> anyhow::Result<()> {
    let piece_count = torrent.pieces.len();

    let (send_res, mut recv_res) = tokio::sync::mpsc::channel(10);
    let mut task_queue = BinaryHeap::with_capacity(piece_count);

    // prepare all parts to be downloaded
    for piece_nr in 0..torrent.pieces.len() {
        let mut piece_length = torrent.piece_length;
        if piece_nr == torrent.pieces.len() - 1 {
            // last piece
            piece_length = torrent.length % torrent.piece_length
        };
        let p = Piece {
            nr: piece_nr,
            len: piece_length,
            hash: torrent.pieces[piece_nr],
        };

        task_queue.push(p);
    }

    let task_queue = Arc::new(Mutex::new(task_queue));

    for peer in tracker.peers.iter().copied() {
        let torrent_info = torrent.clone();
        let task_queue = task_queue.clone();
        let send_res = send_res.clone();
        tokio::spawn(async move {
            let res = handle_peer(peer, torrent_info, task_queue, send_res, my_peer_id).await;
            if let Err(err) = res {
                eprintln!("error {err}");
            }
        });
    }

    // make sure that the slate is clean
    if out_path.as_ref().exists() {
        tokio::fs::remove_file(out_path.as_ref()).await?;
    } else if let Some(parent) = out_path.as_ref().parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&out_path)
        .await
        .context("while opening the result file")?;

    let mut map = HashMap::new();
    let mut needed = 0;
    let mut loaded = 0;
    while needed < piece_count {
        eprintln!(
            "waiting for a piece {} of {} -- head at {}",
            loaded + 1,
            piece_count,
            needed + 1
        );

        match recv_res.recv().await {
            Some((piece, section)) => {
                map.insert(piece.nr, section);
                loaded += 1;
            }
            None => {
                eprintln!("unexpected error while wating to piece");
                return Err(anyhow::anyhow!("unexpected error while wating to piece"));
            }
        }

        while let Some(v) = map.remove(&needed) {
            file.write_all(&v).await?;
            needed += 1;
        }
    }

    Ok(())
}

async fn download(
    out_path: impl AsRef<Path>,
    path: impl AsRef<Path>,
    my_peer_id: [u8; 20],
) -> anyhow::Result<()> {
    // 1) Read the torrent file to get the tracker URL
    eprintln!("reading torrent file");
    let torrent = torrent::torrent_file(&path).await?;

    // 2) Perform the tracker GET request to get a list of peers
    eprintln!("loading peers");

    let tracker = torrent::peers_load(
        &torrent.announce,
        torrent.info.hash_raw(),
        torrent.info.length,
        my_peer_id,
    )
    .await?;

    inner_download(&out_path, &tracker, &torrent.info, my_peer_id).await?;

    println!(
        "Downloaded {} to {}.",
        path.as_ref().display(),
        out_path.as_ref().display()
    );

    Ok(())
}

async fn magnet_parse(link: &str) -> anyhow::Result<()> {
    let link = torrent::TorrentMagnet::try_from(link).map_err(|e| anyhow!("{e}"))?;

    println!(
        "Tracker URL: {}\nInfo Hash: {}",
        link.tracker,
        digest_to_str(link.hash)
    );

    Ok(())
}

async fn magnet_handshake(link: &str, my_peer_id: Sha1Hash) -> anyhow::Result<()> {
    let link = torrent::TorrentMagnet::try_from(link).map_err(|e| anyhow!("{e}"))?;

    let tracker = torrent::peers_load(
        &link.tracker,
        link.hash,
        999, // random value as the "left" (lenght) value is required by the tracker
        my_peer_id,
    )
    .await?;

    // random one
    let peer = tracker.peers[0];

    let (_, res, ext_id) = torrent::magnet_create_peer_connect(link.hash, peer, my_peer_id).await?;

    println!(
        "Peer ID: {}\nPeer Metadata Extension ID: {}",
        digest_to_str(res.peer_id),
        ext_id
    );

    Ok(())
}

async fn magnet_info(link: &str, my_peer_id: Sha1Hash) -> anyhow::Result<()> {
    let link = torrent::TorrentMagnet::try_from(link).map_err(|e| anyhow!("{e}"))?;

    let tracker = torrent::peers_load(
        &link.tracker,
        link.hash,
        999, // random value as the "left" (lenght) value is required by the tracker
        my_peer_id,
    )
    .await?;

    // random one
    let peer = tracker.peers[0];

    let (stream, _res, ext_id) =
        torrent::magnet_create_peer_connect(link.hash, peer, my_peer_id).await?;
    let torrent = torrent::magnet_load_meta_data(&stream, ext_id, 0).await?;

    let hash = torrent.hash();

    let pieces: Vec<_> = torrent
        .pieces
        .into_iter()
        .map(torrent::digest_to_str)
        .collect();
    let pieces = pieces.join("\n");

    print!(
        r#"Tracker URL: {}
Peer Metadata Extension ID: {}
Length: {}
Info Hash: {}
Piece Length: {}
Piece Hashes:
{}
"#,
        link.tracker, ext_id, torrent.length, hash, torrent.piece_length, pieces
    );

    Ok(())
}

async fn magnet_download_piece(
    out_path: impl AsRef<Path>,
    link: &str,
    piece_nr: usize,
    my_peer_id: Sha1Hash,
) -> anyhow::Result<()> {
    let link = torrent::TorrentMagnet::try_from(link).map_err(|e| anyhow!("{e}"))?;

    let tracker = torrent::peers_load(
        &link.tracker,
        link.hash,
        999, // random value as the "left" (lenght) value is required by the tracker
        my_peer_id,
    )
    .await?;

    // random one
    let peer = tracker.peers[0];

    let (stream, _res, ext_id) =
        torrent::magnet_create_peer_connect(link.hash, peer, my_peer_id).await?;
    // we only use pice 0 here as that meta data contains all the block we require
    let torrent = torrent::magnet_load_meta_data(&stream, ext_id, 0).await?;

    // 4.2) Send an interested message
    eprintln!("sending interested packet for {peer}");
    torrent::send_interested(&stream).await?;

    // 4.3) Wait until you receive an unchoke message back
    eprintln!("waiting for unchoke packet from {peer}");
    torrent::wait_for_unchoke(&stream).await?;

    eprintln!("processing for {peer}");
    let piece_length = if torrent.pieces.len() - 1 == piece_nr {
        // last piece
        eprintln!("last piece");
        torrent.length % torrent.piece_length
    } else {
        torrent.piece_length
    };

    // 4.4 - 6)
    let storage =
        torrent::download_piece(&stream, piece_nr, piece_length, &torrent.pieces[piece_nr])
            .await
            .context("able to download a piece")?;

    // make sure that the slate is clean
    if out_path.as_ref().exists() {
        tokio::fs::remove_file(out_path.as_ref()).await?;
    } else if let Some(parent) = out_path.as_ref().parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    tokio::fs::write(&out_path, storage)
        .await
        .context("able to write content")?;

    println!(
        "Piece {} downloaded to {}.",
        piece_nr,
        out_path.as_ref().display()
    );

    Ok(())
}

async fn magnet_download(
    out_path: impl AsRef<Path>,
    link: &str,
    my_peer_id: Sha1Hash,
) -> anyhow::Result<()> {
    let link = torrent::TorrentMagnet::try_from(link).map_err(|e| anyhow!("{e}"))?;

    let tracker = torrent::peers_load(
        &link.tracker,
        link.hash,
        999, // random value as the "left" (lenght) value is required by the tracker
        my_peer_id,
    )
    .await?;

    // random one
    let peer = tracker.peers[0];

    let (stream, _res, ext_id) =
        torrent::magnet_create_peer_connect(link.hash, peer, my_peer_id).await?;
    // we only use pice 0 here as that meta data contains all the block we require
    let torrent = torrent::magnet_load_meta_data(&stream, ext_id, 0).await?;
    drop(stream);

    inner_download(&out_path, &tracker, &torrent, my_peer_id).await?;

    println!("Downloaded magnet to {}.", out_path.as_ref().display());

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let my_peer_id = random_peer_id();
    match args.command {
        Commands::Decode(Decode { bencode }) => decode(bencode.as_bytes()),
        Commands::Info(Info { path }) => info(path),
        Commands::Peers(Peers { path }) => peers(path, my_peer_id).await?,
        Commands::Handshake(Handshake { path, addr }) => handshake(path, addr, my_peer_id).await?,
        Commands::DownloadPiece(DownloadPiece {
            out_path,
            path,
            piece,
        }) => download_piece(out_path, path, piece, my_peer_id).await?,
        Commands::Download(Download { out_path, path }) => {
            download(out_path, path, my_peer_id).await?
        }
        Commands::MagnetParse(mp) => magnet_parse(&mp.str).await?,
        Commands::MagnetHandshake(mh) => magnet_handshake(&mh.str, my_peer_id).await?,
        Commands::MagnetInfo(mi) => magnet_info(&mi.str, my_peer_id).await?,
        Commands::MagnetDownloadPiece(mdp) => {
            magnet_download_piece(mdp.out_path, &mdp.link, mdp.piece, my_peer_id).await?
        }
        Commands::MagnetDownload(md) => magnet_download(md.out_path, &md.link, my_peer_id).await?,
    }

    Ok(())
}
