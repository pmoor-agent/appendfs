use crate::log::record::{FILE_HEADER_SIZE, FileHeader, RECORD_HEADER_SIZE, RecordHeader};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// Represents a single deserialized log record read from a `.log` file.
#[derive(Debug, Clone)]
pub struct LogRecord {
    pub header: RecordHeader,
    pub payload: Vec<u8>,
    pub record_log_offset: u64,
}

/// Iterator for sequentially reading records from a `.log` generation file.
pub struct LogReader {
    file: File,
    header: FileHeader,
    current_offset: u64,
}

impl LogReader {
    /// Opens a `.log` file, verifies its 24-byte `FileHeader`, and initializes the reader iterator.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let mut file = File::open(path)?;

        let mut header_buf = [0u8; FILE_HEADER_SIZE];
        file.read_exact(&mut header_buf)?;

        let header = FileHeader::from_bytes(&header_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(Self {
            file,
            header,
            current_offset: FILE_HEADER_SIZE as u64,
        })
    }

    /// Returns the parsed `FileHeader` of this log file.
    pub fn file_header(&self) -> &FileHeader {
        &self.header
    }
}

impl Iterator for LogReader {
    type Item = io::Result<LogRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        let record_offset = self.current_offset;
        if self.file.seek(SeekFrom::Start(record_offset)).is_err() {
            return None;
        }

        let mut header_buf = [0u8; RECORD_HEADER_SIZE];
        match self.file.read_exact(&mut header_buf) {
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

        let mut payload = vec![0u8; header.payload_len as usize];
        if let Err(e) = self.file.read_exact(&mut payload) {
            return Some(Err(e));
        }

        self.current_offset += RECORD_HEADER_SIZE as u64 + header.payload_len as u64;

        // Checksum mismatch means this record's content no longer matches what was
        // actually written - bitrot, not a torn/incomplete write (those fail as a
        // clean UnexpectedEof instead). Still advances current_offset above so this
        // reader stays resumable for any future caller that wants to continue past a
        // single bad record; recover_fs itself does not - see its module docs.
        let actual_checksum = crate::log::record::checksum_payload(&payload);
        if actual_checksum != header.checksum {
            return Some(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "checksum mismatch at offset {}: expected {:?}, computed {:?} (possible bitrot)",
                    record_offset, header.checksum, actual_checksum
                ),
            )));
        }

        Some(Ok(LogRecord {
            header,
            payload,
            record_log_offset: record_offset,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::log::record::OpCode;
    use crate::log::writer::LogWriter;
    use tempfile::tempdir;

    #[test]
    fn test_log_reader_iteration() {
        let dir = tempdir().unwrap();
        let clock = SystemClock;
        let writer = LogWriter::create(dir.path(), 1, &clock).unwrap();

        writer.append_record(OpCode::Mkdir, 2, b"payload1").unwrap();
        writer
            .append_record(OpCode::Write, 3, b"payload22")
            .unwrap();
        writer.sync().unwrap();

        let reader = LogReader::open(writer.path()).unwrap();
        assert_eq!(reader.file_header().generation, 1);

        let records: Vec<LogRecord> = reader.map(|r| r.unwrap()).collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].header.op_code, OpCode::Mkdir);
        assert_eq!(records[0].payload, b"payload1");
        assert_eq!(records[1].header.op_code, OpCode::Write);
        assert_eq!(records[1].payload, b"payload22");
    }
}
