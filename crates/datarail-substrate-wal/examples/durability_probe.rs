use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

use datarail_cofre::seal;
use datarail_core::Substrate;
use datarail_core::{AeadAlg, Etiqueta};
use datarail_substrate_wal::DurableLog;

const RECORDS: u64 = 256;
const FIXTURE_SEED: [u8; 32] = [7; 32];

fn cofre_seq(seq: u64) -> datarail_core::Cofre {
    let etiqueta = Etiqueta {
        route_id: [1; 16],
        stream_id: [2; 16],
        seq,
        cofre_id: [0; 32],
        idempotency_key: [4; 32],
        contract_fp: [5; 32],
        aead_alg: AeadAlg::Gcmsiv256,
        nonce: [6; 12],
        signer_key_id: [0; 32],
        eph_pk: [7; 32],
        sender_present: false,
        ts: 0,
    };
    seal(
        etiqueta,
        format!("opaque-ciphertext-{seq:03}").into_bytes(),
        &FIXTURE_SEED,
    )
}

fn write_status(path: &Path, acked: u64) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    writeln!(file, "{acked}")?;
    file.sync_all()
}

fn write_probe(dir: &Path, status: &Path) -> io::Result<()> {
    let mut log = DurableLog::open(dir).map_err(|error| io::Error::other(error.to_string()))?;
    for seq in 0..RECORDS {
        log.send(&cofre_seq(seq))
            .map_err(|error| io::Error::other(error.to_string()))?;
        log.flush()
            .map_err(|error| io::Error::other(error.to_string()))?;
        write_status(status, seq + 1)?;
        println!("ACK {seq}");
        io::stdout().flush()?;
        thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn verify_probe(dir: &Path, status: &Path) -> io::Result<()> {
    let mut status_file = File::open(status)?;
    let mut status_text = String::new();
    status_file.read_to_string(&mut status_text)?;
    let acked: u64 = status_text
        .trim()
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if acked == 0 || acked >= RECORDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("fault did not interrupt writer at a valid ack boundary: {acked}"),
        ));
    }

    let mut log = DurableLog::open(dir).map_err(|error| io::Error::other(error.to_string()))?;
    let mut seen =
        vec![false; usize::try_from(acked).map_err(|_| io::Error::other("ack overflow"))?];
    while let Some(cofre) = log
        .recv()
        .map_err(|error| io::Error::other(error.to_string()))?
    {
        let seq = cofre.etiqueta.seq;
        if seq < acked {
            let slot = usize::try_from(seq).map_err(|_| io::Error::other("sequence overflow"))?;
            if seen[slot] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("acked sequence duplicated after fault: {seq}"),
                ));
            }
            seen[slot] = true;
        }
        log.ack(cofre.etiqueta.cofre_id)
            .map_err(|error| io::Error::other(error.to_string()))?;
    }
    if seen.iter().any(|present| !present) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "an acknowledged record was lost after fault",
        ));
    }
    println!("verified {acked} acknowledged records");
    Ok(())
}

fn run() -> io::Result<()> {
    let mut args = env::args_os().skip(1);
    let mode = args
        .next()
        .ok_or_else(|| io::Error::other("usage: write|verify DIR STATUS"))?;
    let dir = args.next().ok_or_else(|| io::Error::other("missing DIR"))?;
    let status = args
        .next()
        .ok_or_else(|| io::Error::other("missing STATUS"))?;
    if args.next().is_some() {
        return Err(io::Error::other("usage: write|verify DIR STATUS"));
    }
    let dir = Path::new(&dir);
    let status = Path::new(&status);
    match mode.to_str() {
        Some("write") => write_probe(dir, status),
        Some("verify") => verify_probe(dir, status),
        _ => Err(io::Error::other("usage: write|verify DIR STATUS")),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("probe error: {error}");
        std::process::exit(2);
    }
}
