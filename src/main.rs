mod bencode;
mod torrent;

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, Context};
use clap::Parser;
use tokio::io::AsyncWriteExt;
use torrent::digest_to_str;

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
    MagnetParse(MagnetParse),
    DownloadPiece(DownloadPiece),
    Download(Download),
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
struct MagnetParse {
    str: String,
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

async fn peers(path: impl AsRef<Path>) -> anyhow::Result<()> {
    let torrent = torrent::torrent_file(path).await?;
    let tracker = torrent::peers_load(&torrent).await?;
    for peer in tracker.peers {
        println!("{}", peer);
    }

    Ok(())
}

async fn handshake(path: impl AsRef<Path>, addr: SocketAddr) -> anyhow::Result<()> {
    let torrent = torrent::torrent_file(path).await?;
    let info_hash = torrent.info.hash_raw();
    let (_, res) = torrent::do_handshake(&info_hash, addr).await?;

    println!(
        "Peer ID: {}",
        res.peer_id.map(|c| format!("{:0>2x}", c)).join("")
    );

    Ok(())
}

async fn magnet_parse(link: &str) -> anyhow::Result<()> {
    let link = torrent::TorrentMagnet::try_from(link).map_err(|e| anyhow!("{e}"))?;

    println!(
        "Tracker URL: {}\nInfo Hash: {}",
        link.tracker,
        digest_to_str(&link.hash)
    );

    Ok(())
}

async fn download_piece(
    out_path: impl AsRef<Path>,
    path: impl AsRef<Path>,
    piece_nr: usize,
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
    let tracker = torrent::peers_load(&torrent).await?;

    // 3) Establish a TCP connection with a peer, and perform a handshake
    // 4) Exchange multiple peer messages to download the file
    // 4.1) Wait for a bitfield message from the peer indicating which pieces it has
    let mut s = None;
    for peer in tracker.peers {
        eprintln!("using peer nr {}", peer);
        match torrent::create_peer_connect(&torrent.info, peer)
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

    let (mut stream, _bf) = s.unwrap()?;

    // 4.2) Send an interested message
    eprintln!("sending interested packet");
    torrent::send_interested(&mut stream).await?;

    // 4.3) Wait until you receive an unchoke message back
    eprintln!("waiting for unchoke packet");
    torrent::wait_for_unchoke(&stream).await?;

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

async fn download(out_path: impl AsRef<Path>, path: impl AsRef<Path>) -> anyhow::Result<()> {
    // 1) Read the torrent file to get the tracker URL
    eprintln!("reading torrent file");
    let torrent = torrent::torrent_file(&path).await?;

    // 2) Perform the tracker GET request to get a list of peers
    eprintln!("loading peers");
    let tracker = torrent::peers_load(&torrent).await?;

    // 3) Establish a TCP connection with a peer, and perform a handshake
    // 4) Exchange multiple peer messages to download the file
    // 4.1) Wait for a bitfield message from the peer indicating which pieces it has
    let mut s = None;
    'outer: for i in 0..3 {
        eprintln!("trying to connect to any peer try <{}>", i);
        for peer in &tracker.peers {
            eprintln!("using peer nr {}", peer);
            match torrent::create_peer_connect(&torrent.info, *peer)
                .await
                .context("while creating a peer connection during a downlaod")
            {
                Ok(e) => {
                    s = Some(Ok(e));
                    break 'outer;
                }
                Err(err) => {
                    s = Some(Err(err));
                }
            }
        }

        tokio::time::sleep(Duration::from_secs_f64(0.5)).await;
    }

    let (mut stream, _bf) = s.unwrap()?;

    // 4.2) Send an interested message
    eprintln!("sending interested packet");
    torrent::send_interested(&mut stream).await?;

    // 4.3) Wait until you receive an unchoke message back
    eprintln!("waiting for unchoke packet");
    torrent::wait_for_unchoke(&stream).await?;

    // make sure that the slate is clean
    if out_path.as_ref().exists() {
        tokio::fs::remove_file(out_path.as_ref()).await?;
    }

    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&out_path)
        .await
        .context("while opening the result file")?;

    for piece_nr in 0..torrent.info.pieces.len() {
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
        .await
        .context("able to download a piece")?;

        file.write_all(&storage).await?;
    }

    println!(
        "Downloaded {} to {}.",
        path.as_ref().display(),
        out_path.as_ref().display()
    );

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.command {
        Commands::Decode(Decode { bencode }) => decode(bencode.as_bytes()),
        Commands::Info(Info { path }) => info(path),
        Commands::Peers(Peers { path }) => peers(path).await?,
        Commands::Handshake(Handshake { path, addr }) => handshake(path, addr).await?,
        Commands::DownloadPiece(DownloadPiece {
            out_path,
            path,
            piece,
        }) => download_piece(out_path, path, piece).await?,
        Commands::Download(Download { out_path, path }) => download(out_path, path).await?,
        Commands::MagnetParse(mp) => magnet_parse(&mp.str).await?,
    }

    Ok(())
}
