pub mod check;
pub mod cli;
pub mod clock;
pub mod dump;
pub mod fs;
pub mod log;
pub mod node;
pub mod operations;
pub mod range_map;
pub mod shim;
pub mod stats;
pub mod storage;

pub use check::{
    IntegrityIssue, IntegrityReport, IssueLevel, check_fs_integrity, check_volume, check_volume_with_storage,
};
pub use cli::{
    CheckArgs, Cli, Commands, DumpArgs, InitArgs, MountArgs, MountRoArgs, StatsArgs, find_latest_generation,
    find_latest_generation_in_storage,
};
pub use clock::{AdvancingClock, Clock, MockClock, SystemClock, format_local_civil_time, parse_timestamp};
pub use dump::{
    dump_file, dump_file_with_storage, dump_log_file, dump_log_reader, dump_summary_file, dump_summary_reader,
};
pub use fs::InMemoryFS;
pub use log::{
    BackgroundFlusher, ExtentState, LogFileCache, LogReader, LogRecord, LogWriter, RecoveryTarget, SharedExtentState,
    SummaryFooter, SummaryHeader, SummaryReader, export_summary, export_summary_with_time,
    export_summary_with_time_to_storage, init_volume, init_volume_with_storage, recover_fs, recover_fs_to_target,
    recover_fs_to_target_with_clock, recover_fs_to_target_with_storage, recover_fs_with_clock, recover_fs_with_storage,
};
pub use node::{InodeMeta, Node, NodeDelta, NodeKind, SpecialDelta};
pub use range_map::{RangeEntry, RangeMap, RangeValue};
pub use stats::VolumeStats;
pub use storage::{FaultStorage, MemoryStorage, OsStorage, Storage, StorageReader, StorageWriter, WriteMode};

pub fn mount(args: Vec<String>, fs: InMemoryFS) -> Result<(), i32> {
    shim::mount(args, fs)
}

pub fn mount_arc(args: Vec<String>, fs: std::sync::Arc<InMemoryFS>) -> Result<(), i32> {
    shim::mount_arc(args, fs)
}

pub fn mount_ro(args: Vec<String>, fs: InMemoryFS) -> Result<(), i32> {
    shim::mount_ro(args, fs)
}

pub fn mount_ro_arc(args: Vec<String>, fs: std::sync::Arc<InMemoryFS>) -> Result<(), i32> {
    shim::mount_ro_arc(args, fs)
}
