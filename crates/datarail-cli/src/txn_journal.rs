//! Durable transaction intent journal used by the broker recovery path.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use datarail_crypto::blake3_256;
use datarail_kafka::produce::crc32c;

const MAGIC: [u8; 4] = *b"DRTJ";
const VERSION: u16 = 1;
const PREPARE: u8 = 1;
const COMMIT: u8 = 2;
const ABORT: u8 = 3;
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;
const MAX_ITEMS: usize = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct TxnId {
    pub(crate) journal_id: u64,
    pub(crate) transactional_id: String,
    pub(crate) producer_id: i64,
    pub(crate) epoch: i16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParticipantBoundary {
    pub(crate) topic: String,
    pub(crate) partition: i32,
    pub(crate) byte_end: u64,
    pub(crate) logical_end: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OffsetChange {
    pub(crate) group: String,
    pub(crate) before: Option<u64>,
    pub(crate) after: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedTxn {
    pub(crate) id: TxnId,
    pub(crate) participants: Vec<ParticipantBoundary>,
    pub(crate) offsets: Vec<OffsetChange>,
    pub(crate) digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum JournalState {
    Prepared(PreparedTxn),
    Committed {
        prepared: PreparedTxn,
        participants: Vec<ParticipantBoundary>,
    },
    Aborted(PreparedTxn),
}

pub(crate) struct TxnJournal {
    path: PathBuf,
    file: File,
}

impl TxnJournal {
    /// Open or create a transaction journal.
    ///
    /// # Errors
    /// Returns an I/O error when the parent directory or journal cannot be opened.
    pub(crate) fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        let mut journal = Self { path, file };
        journal.repair_torn_tail()?;
        Ok(journal)
    }

    pub(crate) fn prepare(
        &mut self,
        transactional_id: &str,
        producer_id: i64,
        epoch: i16,
        participants: Vec<ParticipantBoundary>,
        offsets: Vec<OffsetChange>,
    ) -> io::Result<PreparedTxn> {
        validate_items(participants.len())?;
        validate_items(offsets.len())?;
        let journal_id = self.next_id()?;
        let id = TxnId {
            journal_id,
            transactional_id: transactional_id.to_owned(),
            producer_id,
            epoch,
        };
        let payload = encode_prepare(&id, &participants, &offsets)?;
        let digest = blake3_256(&payload);
        self.append_frame(PREPARE, &payload)?;
        Ok(PreparedTxn {
            id,
            participants,
            offsets,
            digest,
        })
    }

    pub(crate) fn commit(
        &mut self,
        prepared: &PreparedTxn,
        participants: &[ParticipantBoundary],
    ) -> io::Result<()> {
        validate_items(participants.len())?;
        if participants.len() != prepared.participants.len() {
            return Err(invalid("commit participant count mismatch"));
        }
        let mut payload = encode_id(&prepared.id)?;
        payload.extend_from_slice(&prepared.digest);
        put_u32(
            &mut payload,
            u32::try_from(participants.len()).map_err(|_| invalid("too many participants"))?,
        );
        for participant in participants {
            encode_participant(&mut payload, participant)?;
        }
        put_u32(
            &mut payload,
            u32::try_from(prepared.offsets.len()).map_err(|_| invalid("too many offsets"))?,
        );
        for offset in &prepared.offsets {
            put_string(&mut payload, &offset.group)?;
            put_u64(&mut payload, offset.after);
        }
        self.append_frame(COMMIT, &payload)
    }

    pub(crate) fn abort(&mut self, prepared: &PreparedTxn) -> io::Result<()> {
        let mut payload = encode_id(&prepared.id)?;
        payload.extend_from_slice(&prepared.digest);
        self.append_frame(ABORT, &payload)
    }

    pub(crate) fn states(&mut self) -> io::Result<Vec<JournalState>> {
        let mut bytes = Vec::new();
        File::open(&self.path)?.read_to_end(&mut bytes)?;
        let mut states = HashMap::new();
        let mut pos = 0usize;
        while pos < bytes.len() {
            let Some((kind, payload, next)) = decode_frame(&bytes, pos)? else {
                break;
            };
            pos = next;
            match kind {
                PREPARE => {
                    let prepared = decode_prepare(&payload)?;
                    if states
                        .insert(prepared.id.clone(), JournalState::Prepared(prepared))
                        .is_some()
                    {
                        return Err(invalid("duplicate transaction prepare"));
                    }
                }
                COMMIT => apply_commit(&mut states, &payload)?,
                ABORT => apply_abort(&mut states, &payload)?,
                _ => return Err(invalid("unknown transaction journal record")),
            }
        }
        let mut out: Vec<_> = states.into_values().collect();
        out.sort_by_key(|state| state_id(state).journal_id);
        Ok(out)
    }

    fn next_id(&mut self) -> io::Result<u64> {
        Ok(self
            .states()?
            .iter()
            .map(|state| state_id(state).journal_id)
            .max()
            .unwrap_or(0)
            .saturating_add(1))
    }

    fn repair_torn_tail(&mut self) -> io::Result<()> {
        let mut bytes = Vec::new();
        File::open(&self.path)?.read_to_end(&mut bytes)?;
        let mut pos = 0usize;
        while pos < bytes.len() {
            let Some((_, _, next)) = decode_frame(&bytes, pos)? else {
                self.file
                    .set_len(u64::try_from(pos).map_err(|_| invalid("journal offset overflow"))?)?;
                self.file.sync_all()?;
                break;
            };
            pos = next;
        }
        Ok(())
    }

    fn append_frame(&mut self, kind: u8, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_PAYLOAD {
            return Err(invalid("transaction journal payload too large"));
        }
        let len = u32::try_from(payload.len())
            .map_err(|_| invalid("transaction journal payload too large"))?;
        let mut frame = Vec::with_capacity(11 + payload.len() + 4);
        frame.extend_from_slice(&MAGIC);
        frame.extend_from_slice(&VERSION.to_le_bytes());
        frame.push(kind);
        frame.extend_from_slice(&len.to_le_bytes());
        frame.extend_from_slice(payload);
        frame.extend_from_slice(&crc32c(&frame).to_le_bytes());
        self.file.write_all(&frame)?;
        self.file.sync_all()
    }
}

fn state_id(state: &JournalState) -> &TxnId {
    match state {
        JournalState::Prepared(prepared)
        | JournalState::Aborted(prepared)
        | JournalState::Committed { prepared, .. } => &prepared.id,
    }
}

fn apply_commit(states: &mut HashMap<TxnId, JournalState>, payload: &[u8]) -> io::Result<()> {
    let (id, mut pos) = decode_id(payload)?;
    let digest = take_array::<32>(payload, &mut pos)?;
    let count = take_count(payload, &mut pos)?;
    let mut participants = Vec::with_capacity(count);
    for _ in 0..count {
        participants.push(decode_participant(payload, &mut pos)?);
    }
    let offset_count = take_count(payload, &mut pos)?;
    let mut offsets = Vec::with_capacity(offset_count);
    for _ in 0..offset_count {
        offsets.push((
            take_string(payload, &mut pos)?,
            take_u64(payload, &mut pos)?,
        ));
    }
    if pos != payload.len() {
        return Err(invalid("trailing commit journal bytes"));
    }
    let Some(JournalState::Prepared(prepared)) = states.remove(&id) else {
        return Err(invalid("commit without matching prepare"));
    };
    let expected_offsets: Vec<_> = prepared
        .offsets
        .iter()
        .map(|offset| (&offset.group, offset.after))
        .collect();
    if prepared.digest != digest
        || participants.len() != prepared.participants.len()
        || offsets
            .iter()
            .map(|(group, offset)| (group, *offset))
            .collect::<Vec<_>>()
            != expected_offsets
        || participants
            .iter()
            .zip(&prepared.participants)
            .any(|(post, pre)| {
                post.topic != pre.topic
                    || post.partition != pre.partition
                    || post.byte_end < pre.byte_end
                    || post.logical_end < pre.logical_end
            })
    {
        return Err(invalid("transaction commit digest or participant mismatch"));
    }
    states.insert(
        id,
        JournalState::Committed {
            prepared,
            participants,
        },
    );
    Ok(())
}

fn apply_abort(states: &mut HashMap<TxnId, JournalState>, payload: &[u8]) -> io::Result<()> {
    let (id, mut pos) = decode_id(payload)?;
    let digest = take_array::<32>(payload, &mut pos)?;
    if pos != payload.len() {
        return Err(invalid("trailing abort journal bytes"));
    }
    let Some(JournalState::Prepared(prepared)) = states.remove(&id) else {
        return Err(invalid("abort without matching prepare"));
    };
    if prepared.digest != digest {
        return Err(invalid("transaction abort digest mismatch"));
    }
    states.insert(id, JournalState::Aborted(prepared));
    Ok(())
}

fn encode_prepare(
    id: &TxnId,
    participants: &[ParticipantBoundary],
    offsets: &[OffsetChange],
) -> io::Result<Vec<u8>> {
    let mut payload = encode_id(id)?;
    put_u32(
        &mut payload,
        u32::try_from(participants.len()).map_err(|_| invalid("too many participants"))?,
    );
    for participant in participants {
        encode_participant(&mut payload, participant)?;
    }
    put_u32(
        &mut payload,
        u32::try_from(offsets.len()).map_err(|_| invalid("too many offsets"))?,
    );
    for offset in offsets {
        put_string(&mut payload, &offset.group)?;
        payload.push(u8::from(offset.before.is_some()));
        if let Some(before) = offset.before {
            put_u64(&mut payload, before);
        }
        put_u64(&mut payload, offset.after);
    }
    Ok(payload)
}

fn decode_prepare(payload: &[u8]) -> io::Result<PreparedTxn> {
    let (id, mut pos) = decode_id(payload)?;
    let participant_count = take_count(payload, &mut pos)?;
    let mut participants = Vec::with_capacity(participant_count);
    for _ in 0..participant_count {
        participants.push(decode_participant(payload, &mut pos)?);
    }
    let offset_count = take_count(payload, &mut pos)?;
    let mut offsets = Vec::with_capacity(offset_count);
    for _ in 0..offset_count {
        let group = take_string(payload, &mut pos)?;
        let before = match take_u8(payload, &mut pos)? {
            0 => None,
            1 => Some(take_u64(payload, &mut pos)?),
            _ => return Err(invalid("invalid offset presence flag")),
        };
        offsets.push(OffsetChange {
            group,
            before,
            after: take_u64(payload, &mut pos)?,
        });
    }
    if pos != payload.len() {
        return Err(invalid("trailing prepare journal bytes"));
    }
    Ok(PreparedTxn {
        id,
        participants,
        offsets,
        digest: blake3_256(payload),
    })
}

fn encode_id(id: &TxnId) -> io::Result<Vec<u8>> {
    let mut payload = Vec::new();
    put_u64(&mut payload, id.journal_id);
    put_string(&mut payload, &id.transactional_id)?;
    put_i64(&mut payload, id.producer_id);
    put_i16(&mut payload, id.epoch);
    Ok(payload)
}

fn decode_id(bytes: &[u8]) -> io::Result<(TxnId, usize)> {
    let mut pos = 0;
    let id = TxnId {
        journal_id: take_u64(bytes, &mut pos)?,
        transactional_id: take_string(bytes, &mut pos)?,
        producer_id: take_i64(bytes, &mut pos)?,
        epoch: take_i16(bytes, &mut pos)?,
    };
    Ok((id, pos))
}

fn encode_participant(payload: &mut Vec<u8>, participant: &ParticipantBoundary) -> io::Result<()> {
    put_string(payload, &participant.topic)?;
    put_i32(payload, participant.partition);
    put_u64(payload, participant.byte_end);
    put_u64(payload, participant.logical_end);
    Ok(())
}

fn decode_participant(bytes: &[u8], pos: &mut usize) -> io::Result<ParticipantBoundary> {
    Ok(ParticipantBoundary {
        topic: take_string(bytes, pos)?,
        partition: take_i32(bytes, pos)?,
        byte_end: take_u64(bytes, pos)?,
        logical_end: take_u64(bytes, pos)?,
    })
}

fn decode_frame(bytes: &[u8], pos: usize) -> io::Result<Option<(u8, Vec<u8>, usize)>> {
    const HEADER: usize = 11;
    if bytes.len() - pos < HEADER {
        return Ok(None);
    }
    if bytes[pos..pos + 4] != MAGIC {
        return Err(invalid("invalid transaction journal magic"));
    }
    if u16::from_le_bytes(
        bytes[pos + 4..pos + 6]
            .try_into()
            .map_err(|_| invalid("invalid journal version"))?,
    ) != VERSION
    {
        return Err(invalid("unsupported transaction journal version"));
    }
    let kind = bytes[pos + 6];
    let len = usize::try_from(u32::from_le_bytes(
        bytes[pos + 7..pos + 11]
            .try_into()
            .map_err(|_| invalid("invalid journal length"))?,
    ))
    .map_err(|_| invalid("journal length overflow"))?;
    if len > MAX_PAYLOAD {
        return Err(invalid("transaction journal payload too large"));
    }
    let end = pos
        .checked_add(HEADER)
        .and_then(|n| n.checked_add(len))
        .and_then(|n| n.checked_add(4))
        .ok_or_else(|| invalid("journal frame overflow"))?;
    if end > bytes.len() {
        return Ok(None);
    }
    let stored = u32::from_le_bytes(
        bytes[end - 4..end]
            .try_into()
            .map_err(|_| invalid("invalid journal crc"))?,
    );
    if stored != crc32c(&bytes[pos..end - 4]) {
        return Err(invalid("transaction journal crc mismatch"));
    }
    Ok(Some((
        kind,
        bytes[pos + HEADER..pos + HEADER + len].to_vec(),
        end,
    )))
}

fn validate_items(count: usize) -> io::Result<()> {
    if count > MAX_ITEMS {
        Err(invalid("too many transaction journal items"))
    } else {
        Ok(())
    }
}

fn take_count(bytes: &[u8], pos: &mut usize) -> io::Result<usize> {
    let count =
        usize::try_from(take_u32(bytes, pos)?).map_err(|_| invalid("journal count overflow"))?;
    validate_items(count)?;
    Ok(count)
}

fn put_string(out: &mut Vec<u8>, value: &str) -> io::Result<()> {
    let len = u32::try_from(value.len()).map_err(|_| invalid("journal string too long"))?;
    put_u32(out, len);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn take_string(bytes: &[u8], pos: &mut usize) -> io::Result<String> {
    let len = usize::try_from(take_u32(bytes, pos)?)
        .map_err(|_| invalid("journal string length overflow"))?;
    let end = pos
        .checked_add(len)
        .ok_or_else(|| invalid("journal string overflow"))?;
    let value = String::from_utf8(
        bytes
            .get(*pos..end)
            .ok_or_else(|| invalid("truncated journal string"))?
            .to_vec(),
    )
    .map_err(|_| invalid("invalid journal utf-8"))?;
    *pos = end;
    Ok(value)
}

fn take_array<const N: usize>(bytes: &[u8], pos: &mut usize) -> io::Result<[u8; N]> {
    let end = pos
        .checked_add(N)
        .ok_or_else(|| invalid("journal array overflow"))?;
    let value = bytes
        .get(*pos..end)
        .ok_or_else(|| invalid("truncated journal array"))?
        .try_into()
        .map_err(|_| invalid("invalid journal array"))?;
    *pos = end;
    Ok(value)
}

fn take_u8(bytes: &[u8], pos: &mut usize) -> io::Result<u8> {
    let value = *bytes
        .get(*pos)
        .ok_or_else(|| invalid("truncated journal u8"))?;
    *pos += 1;
    Ok(value)
}

fn take_i16(bytes: &[u8], pos: &mut usize) -> io::Result<i16> {
    Ok(i16::from_le_bytes(take_array(bytes, pos)?))
}

fn take_u32(bytes: &[u8], pos: &mut usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(take_array(bytes, pos)?))
}

fn take_i32(bytes: &[u8], pos: &mut usize) -> io::Result<i32> {
    Ok(i32::from_le_bytes(take_array(bytes, pos)?))
}

fn take_u64(bytes: &[u8], pos: &mut usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(take_array(bytes, pos)?))
}

fn take_i64(bytes: &[u8], pos: &mut usize) -> io::Result<i64> {
    Ok(i64::from_le_bytes(take_array(bytes, pos)?))
}

fn put_i16(out: &mut Vec<u8>, value: i16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_i32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::{JournalState, OffsetChange, ParticipantBoundary, TxnJournal};

    fn path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("datarail-txn-journal-{tag}-{}", std::process::id()))
    }

    #[test]
    fn prepare_commit_and_reopen_round_trip() {
        let path = path("commit");
        let _ = std::fs::remove_file(&path);
        let mut journal = TxnJournal::open(&path).expect("open");
        let prepared = journal
            .prepare(
                "tx",
                7,
                2,
                vec![ParticipantBoundary {
                    topic: "events".to_owned(),
                    partition: 0,
                    byte_end: 12,
                    logical_end: 1,
                }],
                vec![OffsetChange {
                    group: "g".to_owned(),
                    before: None,
                    after: 4,
                }],
            )
            .expect("prepare");
        journal
            .commit(
                &prepared,
                &[ParticipantBoundary {
                    topic: "events".to_owned(),
                    partition: 0,
                    byte_end: 20,
                    logical_end: 2,
                }],
            )
            .expect("commit");
        drop(journal);
        let mut reopened = TxnJournal::open(&path).expect("reopen");
        assert!(matches!(
            reopened.states().expect("states").as_slice(),
            [JournalState::Committed { .. }]
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn abort_resolves_intent_and_torn_tail_is_ignored() {
        let path = path("abort");
        let _ = std::fs::remove_file(&path);
        let mut journal = TxnJournal::open(&path).expect("open");
        let prepared = journal
            .prepare("tx", 9, 0, Vec::new(), Vec::new())
            .expect("prepare");
        journal.abort(&prepared).expect("abort");
        drop(journal);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append torn tail");
        file.write_all(&super::MAGIC[..2]).expect("write torn tail");
        drop(file);
        let mut reopened = TxnJournal::open(&path).expect("reopen");
        assert!(matches!(
            reopened.states().expect("states").as_slice(),
            [JournalState::Aborted(_)]
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn every_partial_prepare_or_commit_tail_is_repaired() {
        let source = path("partial-source");
        let _ = std::fs::remove_file(&source);
        let mut journal = TxnJournal::open(&source).expect("open");
        let prepared = journal
            .prepare(
                "tx",
                11,
                0,
                vec![ParticipantBoundary {
                    topic: "events".to_owned(),
                    partition: 0,
                    byte_end: 12,
                    logical_end: 1,
                }],
                vec![OffsetChange {
                    group: "g".to_owned(),
                    before: None,
                    after: 4,
                }],
            )
            .expect("prepare");
        let prepare_len = std::fs::metadata(&source).expect("prepare metadata").len();
        journal
            .commit(
                &prepared,
                &[ParticipantBoundary {
                    topic: "events".to_owned(),
                    partition: 0,
                    byte_end: 20,
                    logical_end: 2,
                }],
            )
            .expect("commit");
        drop(journal);
        let bytes = std::fs::read(&source).expect("read complete journal");
        let total_len = u64::try_from(bytes.len()).expect("journal length");

        for cut in 0..total_len {
            let partial = path(&format!("partial-{cut}"));
            std::fs::write(&partial, &bytes).expect("write partial source");
            std::fs::OpenOptions::new()
                .write(true)
                .open(&partial)
                .expect("open partial source")
                .set_len(cut)
                .expect("truncate partial source");
            let mut reopened = TxnJournal::open(&partial).expect("reopen partial journal");
            let states = reopened.states().expect("states");
            if cut < prepare_len {
                assert!(states.is_empty(), "partial prepare became visible at {cut}");
            } else {
                assert!(matches!(states.as_slice(), [JournalState::Prepared(_)]));
            }
            assert_eq!(
                std::fs::metadata(&partial).expect("partial metadata").len(),
                if cut < prepare_len { 0 } else { prepare_len }
            );
            let _ = std::fs::remove_file(partial);
        }

        let mut reopened = TxnJournal::open(&source).expect("reopen complete journal");
        assert!(matches!(
            reopened.states().expect("complete states").as_slice(),
            [JournalState::Committed { .. }]
        ));
        assert_eq!(
            total_len,
            std::fs::metadata(&source).expect("source metadata").len()
        );
        let _ = std::fs::remove_file(source);
    }
}
