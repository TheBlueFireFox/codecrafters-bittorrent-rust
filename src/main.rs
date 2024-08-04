mod bencode;
mod torrent;

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use clap::Parser;

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
        .map(|v| torrent::digest_to_str(v))
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

async fn peers(path: impl AsRef<Path>) {
    let torrent = torrent::torrent_file(path).await;
    let tracker = torrent::peers_load(&torrent).await;
    for peer in tracker.peers {
        println!("{}", peer);
    }
}

async fn handshake(path: impl AsRef<Path>, addr: SocketAddr) {
    let torrent = torrent::torrent_file(path).await;
    let info_hash = torrent.info.hash_raw();
    let (_, res) = torrent::do_handshake(&info_hash, addr).await;

    println!(
        "Peer ID: {}",
        res.peer_id.map(|c| format!("{:0>2x}", c)).join("")
    );
}

async fn download_piece(out_path: impl AsRef<Path>, path: impl AsRef<Path>, piece_nr: usize) {
    // 1) Read the torrent file to get the tracker URL
    eprintln!("reading torrent file");
    let torrent = torrent::torrent_file(path).await;

    assert!(
        torrent.info.pieces.len() > piece_nr,
        "piece number larger then actual count"
    );

    // 2) Perform the tracker GET request to get a list of peers
    eprintln!("loading peers");
    let tracker = torrent::peers_load(&torrent).await;

    // 3) Establish a TCP connection with a peer, and perform a handshake
    // 4) Exchange multiple peer messages to download the file
    // 4.1) Wait for a bitfield message from the peer indicating which pieces it has
    let peer = tracker.peers[0];
    let (mut stream, _bf) = torrent::create_peer_connect(&torrent.info, peer).await;

    // 4.2) Send an interested message
    eprintln!("sending interesed packet");
    torrent::send_interested(&mut stream).await;

    // 4.3) Wait until you receive an unchoke message back
    eprintln!("waiting for unchoke packet");
    torrent::wait_for_unchoke(&stream).await;

    let piece_length = if torrent.info.pieces.len() - 1 == piece_nr {
        // last piece
        eprintln!("last piece");
        torrent.info.length % torrent.info.piece_length
    } else {
        torrent.info.piece_length
    };

    // 4.4 - 6)
    let storage = torrent::download_piece(
        &mut stream,
        piece_nr,
        piece_length,
        &torrent.info.pieces[piece_nr],
    )
    .await;

    tokio::fs::write(&out_path, storage)
        .await
        .expect("able to write content");

    println!(
        "Piece {} downloaded to {}.",
        piece_nr,
        out_path.as_ref().display()
    );
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    match args.command {
        Commands::Decode(Decode { bencode }) => decode(bencode.as_bytes()),
        Commands::Info(Info { path }) => info(path),
        Commands::Peers(Peers { path }) => peers(path).await,
        Commands::Handshake(Handshake { path, addr }) => handshake(path, addr).await,
        Commands::DownloadPiece(DownloadPiece {
            out_path,
            path,
            piece,
        }) => download_piece(out_path, path, piece).await,
    }
}
