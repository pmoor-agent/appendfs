pub mod cli;
pub mod clock;
pub mod dump;
pub mod fs;
pub mod lock_pool;
pub mod log;
pub mod node;
pub mod operations;
pub mod range_map;
pub mod shim;
pub mod stats;

pub use cli::{Cli, Commands, DumpArgs, InitArgs, MountArgs, StatsArgs, find_latest_generation};
pub use clock::{AdvancingClock, Clock, MockClock, SystemClock, format_local_civil_time};
pub use dump::{dump_file, dump_log_file, dump_summary_file};
pub use fs::InMemoryFS;
pub use log::{
    BackgroundFlusher, ExtentState, LogFileCache, LogReader, LogRecord, LogWriter,
    SharedExtentState, SummaryFooter, SummaryHeader, SummaryReader, export_summary, init_volume,
    recover_fs, recover_fs_with_clock,
};
pub use node::{Node, SyncNode};
pub use range_map::{RangeEntry, RangeMap, RangeValue};
pub use stats::VolumeStats;

pub fn mount(args: Vec<String>, fs: InMemoryFS) -> Result<(), i32> {
    shim::mount(args, fs)
}

pub fn mount_arc(args: Vec<String>, fs: std::sync::Arc<InMemoryFS>) -> Result<(), i32> {
    shim::mount_arc(args, fs)
}
