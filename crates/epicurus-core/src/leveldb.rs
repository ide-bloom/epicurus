//! Minimal LevelDB directory writer.
//!
//! Discord, Chromium extensions (MetaMask) and Electron wallets keep secrets
//! in LevelDB. Stealers either regex the raw `*.log`/`*.ldb` files or open the
//! database properly, so the decoy is a genuine LevelDB directory: a
//! write-ahead log made of CRC32C-checksummed records holding a WriteBatch,
//! plus `CURRENT`, `LOCK`, `LOG` and a `MANIFEST`.

/// Block size of the LevelDB log format.
const BLOCK_SIZE: usize = 32 * 1024;
const HEADER_SIZE: usize = 7;
const FULL: u8 = 1;
const FIRST: u8 = 2;
const MIDDLE: u8 = 3;
const LAST: u8 = 4;
const TYPE_VALUE: u8 = 1;

/// CRC32C (Castagnoli), bitwise implementation.
pub fn crc32c(data: &[u8]) -> u32 {
    crc32c_extend(0, data)
}

fn crc32c_extend(init: u32, data: &[u8]) -> u32 {
    let mut crc = !init;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
        }
    }
    !crc
}

/// LevelDB stores masked CRCs so a CRC of data containing CRCs stays robust.
pub fn mask_crc(crc: u32) -> u32 {
    crc.rotate_right(15).wrapping_add(0xa282_ead8)
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn put_slice(out: &mut Vec<u8>, s: &[u8]) {
    put_varint(out, s.len() as u64);
    out.extend_from_slice(s);
}

/// Serializes a WriteBatch of puts starting at `sequence`.
pub fn write_batch(sequence: u64, entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&sequence.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (k, v) in entries {
        out.push(TYPE_VALUE);
        put_slice(&mut out, k);
        put_slice(&mut out, v);
    }
    out
}

/// Frames `payload` as log records, splitting across 32 KiB blocks.
pub fn log_records(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 64);
    let mut rest = payload;
    let mut first = true;
    loop {
        let block_left = BLOCK_SIZE - (out.len() % BLOCK_SIZE);
        if block_left < HEADER_SIZE {
            out.extend(std::iter::repeat_n(0u8, block_left));
            continue;
        }
        let avail = block_left - HEADER_SIZE;
        let take = rest.len().min(avail);
        let last = take == rest.len();
        let kind = match (first, last) {
            (true, true) => FULL,
            (true, false) => FIRST,
            (false, true) => LAST,
            (false, false) => MIDDLE,
        };
        let chunk = &rest[..take];
        let crc = mask_crc(crc32c_extend(crc32c(&[kind]), chunk));
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(take as u16).to_le_bytes());
        out.push(kind);
        out.extend_from_slice(chunk);
        rest = &rest[take..];
        first = false;
        if last {
            break;
        }
    }
    out
}

/// The files of a fresh LevelDB directory whose log holds `entries`.
/// Returns `(file name, bytes)` pairs.
pub fn directory(entries: &[(Vec<u8>, Vec<u8>)], log_line_time: &str) -> Vec<(String, Vec<u8>)> {
    let log = log_records(&write_batch(1, entries));
    // A minimal MANIFEST: a VersionEdit with comparator, log number, next
    // file number and last sequence, framed as a log record.
    let mut edit = Vec::new();
    edit.push(1); // kComparator
    put_slice(&mut edit, b"leveldb.BytewiseComparator");
    edit.push(2); // kLogNumber
    put_varint(&mut edit, 3);
    edit.push(3); // kNextFileNumber
    put_varint(&mut edit, 4);
    edit.push(4); // kLastSequence
    put_varint(&mut edit, entries.len() as u64);
    let manifest = log_records(&edit);
    vec![
        ("CURRENT".to_string(), b"MANIFEST-000001\n".to_vec()),
        ("LOCK".to_string(), Vec::new()),
        (
            "LOG".to_string(),
            format!("{log_line_time} 4f1c Delete type=3 #1\n").into_bytes(),
        ),
        ("MANIFEST-000001".to_string(), manifest),
        ("000003.log".to_string(), log),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_matches_reference_vectors() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
    }

    #[test]
    fn small_payload_is_one_full_record() {
        let rec = log_records(b"hello");
        assert_eq!(rec.len(), HEADER_SIZE + 5);
        assert_eq!(rec[6], FULL);
        assert_eq!(u16::from_le_bytes([rec[4], rec[5]]), 5);
        let crc = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
        assert_eq!(crc, mask_crc(crc32c_extend(crc32c(&[FULL]), b"hello")));
    }

    #[test]
    fn large_payload_spans_blocks() {
        let payload = vec![7u8; BLOCK_SIZE + 100];
        let rec = log_records(&payload);
        assert_eq!(rec[6], FIRST);
        assert_eq!(rec[BLOCK_SIZE + 6], LAST);
    }

    #[test]
    fn batch_contains_keys_and_values() {
        let b = write_batch(1, &[(b"k".to_vec(), b"secret".to_vec())]);
        assert_eq!(&b[..8], &1u64.to_le_bytes());
        assert_eq!(&b[8..12], &1u32.to_le_bytes());
        assert!(b.windows(6).any(|w| w == b"secret"));
    }

    #[test]
    fn directory_has_expected_files() {
        let files = directory(
            &[(b"a".to_vec(), b"b".to_vec())],
            "2025/01/01-00:00:00.000000",
        );
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            ["CURRENT", "LOCK", "LOG", "MANIFEST-000001", "000003.log"]
        );
    }
}
