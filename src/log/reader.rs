use crate::log::record::{
    DecodedPayload, FILE_HEADER_SIZE, FileHeader, FlushCommitPayload, LogEntryDelta, OpCode, RECORD_HEADER_SIZE,
    RecordHeader, SealPayload,
};
use crate::storage::{Storage, StorageReader};
use std::io;
use std::sync::Arc;
use std::time::SystemTime;

/// Represents a single deserialized log record read from a `.log` file.
#[derive(Debug, Clone)]
pub struct LogRecord {
    pub header: RecordHeader,
    pub payload: Vec<u8>,
    pub record_log_offset: u64,
}

impl LogRecord {
    /// Decodes the raw binary payload into a strongly-typed `DecodedPayload`.
    pub fn decode(&self) -> Result<DecodedPayload<'_>, bincode::Error> {
        match self.header.op_code {
            OpCode::Data | OpCode::DataZstd => Ok(DecodedPayload::Data(&self.payload)),
            OpCode::InodeDelta => {
                crate::wire::deserialize::<LogEntryDelta>(&self.payload).map(DecodedPayload::InodeDelta)
            }
            OpCode::FlushCommit => {
                crate::wire::deserialize::<FlushCommitPayload>(&self.payload).map(DecodedPayload::FlushCommit)
            }
            OpCode::Seal => crate::wire::deserialize::<SealPayload>(&self.payload).map(DecodedPayload::Seal),
        }
    }

    /// Extracts the timestamp associated with this record.
    pub fn op_time(&self) -> Option<SystemTime> {
        self.decode().ok().and_then(|d| d.op_time())
    }
}

use crate::crypto::{LogFileKey, VolumeKey};

/// Iterator for sequentially reading records from a `.log` generation file.
pub struct LogReader {
    reader: Arc<dyn StorageReader>,
    header: FileHeader,
    current_offset: u64,
    /// Key for this file's records, derived from the salt in its header.
    file_key: LogFileKey,
    md5_hasher: md5::Context,
    /// Sequence number of the last record read, which the next one must exceed.
    last_sequence: Option<u64>,
}

impl LogReader {
    /// Opens a `.log` file from a `Storage` instance, verifies its `FileHeader`, and initializes the iterator.
    pub fn open(storage: &dyn Storage, filename: &str, volume_key: Arc<VolumeKey>) -> io::Result<Self> {
        let reader = storage.open_reader(filename)?;

        let mut header_buf = [0u8; FILE_HEADER_SIZE];
        reader.read_exact_at(0, &mut header_buf)?;

        let header = FileHeader::from_bytes(&header_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut md5_hasher = md5::Context::new();
        md5_hasher.consume(header_buf);

        Ok(Self {
            reader,
            header,
            current_offset: FILE_HEADER_SIZE as u64,
            file_key: volume_key.log_file_key(&header.key_salt),
            md5_hasher,
            last_sequence: None,
        })
    }

    /// Returns the parsed `FileHeader` of this log file.
    pub fn file_header(&self) -> &FileHeader {
        &self.header
    }

    /// Consumes any remaining bytes up to physical EOF (e.g. truncated/torn trailing bytes
    /// from a crash mid-write, or unread records past an early recovery cutoff) and computes
    /// the streaming MD5 digest over the entire physical log file.
    pub fn finish_md5(&mut self) -> io::Result<[u8; 16]> {
        let file_len = self.reader.len()?;
        if self.current_offset < file_len {
            let mut buf = vec![0u8; 64 * 1024];
            let mut offset = self.current_offset;
            while offset < file_len {
                let to_read = (buf.len() as u64).min(file_len - offset) as usize;
                self.reader.read_exact_at(offset, &mut buf[..to_read])?;
                self.md5_hasher.consume(&buf[..to_read]);
                offset += to_read as u64;
            }
            self.current_offset = file_len;
        }
        Ok(self.md5_hasher.clone().compute().0)
    }

    /// Returns the current physical byte offset in the log file reached by the reader.
    pub fn current_offset(&self) -> u64 {
        self.current_offset
    }
}

impl Iterator for LogReader {
    type Item = io::Result<LogRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        let record_offset = self.current_offset;
        let file_len = match self.reader.len() {
            Ok(l) => l,
            Err(e) => return Some(Err(e)),
        };

        if record_offset >= file_len {
            return None;
        }

        let mut header_buf = [0u8; RECORD_HEADER_SIZE];
        match self.reader.read_exact_at(record_offset, &mut header_buf) {
            Ok(()) => {}
            Err(e) => {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    return None;
                }
                return Some(Err(e));
            }
        }

        let header = match RecordHeader::from_bytes(&header_buf) {
            Ok(h) => h,
            Err(e) => return Some(Err(io::Error::new(io::ErrorKind::InvalidData, e))),
        };

        let mut raw_payload = vec![0u8; header.payload_len as usize];
        if let Err(e) = self
            .reader
            .read_exact_at(record_offset + RECORD_HEADER_SIZE as u64, &mut raw_payload)
        {
            return Some(Err(e));
        }

        // The writer only ever advances the sequence, so a record that does not exceed its
        // predecessor means two records may share a nonce - a writer bug that would leak the
        // XOR of their plaintexts. Refused loudly rather than read past.
        if let Some(last) = self.last_sequence
            && header.sequence <= last
        {
            return Some(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "record at offset {} in generation {} has sequence {}, not above its predecessor's {}",
                    record_offset, self.header.generation, header.sequence, last
                ),
            )));
        }
        self.last_sequence = Some(header.sequence);

        self.md5_hasher.consume(header_buf);
        self.md5_hasher.consume(&raw_payload);
        self.current_offset += RECORD_HEADER_SIZE as u64 + header.payload_len as u64;

        let decrypted_payload = match crate::log::codec::decode(
            &self.file_key,
            crate::log::codec::RecordId {
                sequence: header.sequence,
                op_code: header.op_code as u8,
                inode: header.inode,
            },
            &raw_payload,
            &header.auth_tag,
        ) {
            Ok(p) => p,
            Err(e) => return Some(Err(e)),
        };

        Some(Ok(LogRecord {
            header,
            payload: decrypted_payload,
            record_log_offset: record_offset,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::crypto::VolumeKey;
    use crate::log::record::OpCode;
    use crate::log::writer::LogWriter;
    use crate::storage::MemoryStorage;

    #[test]
    fn test_log_reader_iteration() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(
            storage.clone(),
            1,
            &clock,
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        writer.append_data(2, b"payload1").unwrap();
        writer.append_raw_for_test(OpCode::InodeDelta, 3, b"payload22").unwrap();
        writer.flush().unwrap();

        let mut reader = LogReader::open(&storage, &writer.filename(), VolumeKey::plaintext_arc()).unwrap();
        assert_eq!(reader.file_header().generation, 1);

        let records: Vec<LogRecord> = (&mut reader).map(|r| r.unwrap()).collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].header.op_code, OpCode::Data);
        assert_eq!(records[0].payload, b"payload1");
        assert_eq!(records[1].header.op_code, OpCode::InodeDelta);
        assert_eq!(records[1].payload, b"payload22");
        assert_eq!(records[0].header.sequence, 0);
        assert_eq!(records[1].header.sequence, 1);

        let computed_md5 = reader.finish_md5().unwrap();
        let expected_md5 = *md5::compute(storage.get_file_bytes(&writer.filename()).unwrap());
        assert_eq!(computed_md5, expected_md5);
    }

    #[test]
    fn test_log_reader_finish_md5_with_trailing_torn_bytes() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(
            storage.clone(),
            1,
            &clock,
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        writer.append_data(2, b"payload1").unwrap();
        writer.flush().unwrap();
        let filename = writer.filename();
        drop(writer);

        let mut bytes = storage.get_file_bytes(&filename).unwrap();
        bytes.extend_from_slice(b"0123456789");
        storage.insert_file(&filename, bytes);

        let mut reader = LogReader::open(&storage, &filename, VolumeKey::plaintext_arc()).unwrap();
        let records: Vec<LogRecord> = (&mut reader).map(|r| r.unwrap()).collect();
        assert_eq!(records.len(), 1);

        let computed_md5 = reader.finish_md5().unwrap();
        let expected_md5 = *md5::compute(storage.get_file_bytes(&filename).unwrap());
        assert_eq!(computed_md5, expected_md5);
    }

    /// A record that does not advance the sequence is refused even though it authenticates:
    /// the writer never produces one, so it means two records may share a nonce.
    #[test]
    fn test_log_reader_rejects_a_sequence_that_does_not_increase() {
        let storage = Arc::new(MemoryStorage::new());
        let writer = LogWriter::create(
            storage.clone(),
            1,
            &SystemClock,
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        writer.append_data(2, b"payload1").unwrap();
        writer.append_data(2, b"payload2").unwrap();
        writer.flush().unwrap();
        let filename = writer.filename();
        drop(writer);

        // Append an intact copy of the first record, sequence 0 and all.
        let mut bytes = storage.get_file_bytes(&filename).unwrap();
        let first_record = bytes[FILE_HEADER_SIZE..FILE_HEADER_SIZE + RECORD_HEADER_SIZE + 8].to_vec();
        bytes.extend_from_slice(&first_record);
        storage.insert_file(&filename, bytes);

        let mut reader = LogReader::open(&storage, &filename, VolumeKey::plaintext_arc()).unwrap();
        assert!(reader.next().unwrap().is_ok());
        assert!(reader.next().unwrap().is_ok());
        let err = reader.next().unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string()
                .contains("has sequence 0, not above its predecessor's 1"),
            "{}",
            err
        );
    }
}
