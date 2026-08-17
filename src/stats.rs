use crate::fs::InMemoryFS;
use crate::log::manifest::GenerationLiveStats;
use crate::node::Node;
use serde::{Deserialize, Serialize};
use std::fmt::Write as FmtWrite;

/// Aggregate statistics and fragmentation status for an appendfs volume.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VolumeStats {
    pub branch: String,
    pub next_generation: u64,
    pub next_filename: String,
    pub total_inodes: usize,
    pub directory_count: usize,
    pub file_count: usize,
    pub symlink_count: usize,
    pub total_logical_bytes: u64,
    pub total_disk_bytes: u64,
    pub total_data_bytes: u64,
    pub total_live_bytes: u64,
    pub overall_live_ratio: f64,
    pub generations: Vec<GenerationLiveStats>,
}

impl VolumeStats {
    /// Collects volume statistics from an in-memory filesystem state.
    pub fn collect(fs: &InMemoryFS) -> Self {
        let manifest = fs.manifest.read().unwrap().clone();
        let base = fs.base.read().unwrap();

        let mut directory_count = 0;
        let mut file_count = 0;
        let mut symlink_count = 0;
        let mut total_logical_bytes = 0;

        for node_arc in base.values() {
            let node = unsafe { node_arc.read() };
            match node {
                Node::Directory { .. } => directory_count += 1,
                Node::File { size, .. } => {
                    file_count += 1;
                    total_logical_bytes += *size;
                }
                Node::Symlink { .. } => symlink_count += 1,
            }
        }

        let generations = fs.calculate_generation_live_stats();
        let mut total_disk_bytes = 0;
        let mut total_data_bytes = 0;
        let mut total_live_bytes = 0;

        for g in &generations {
            total_disk_bytes += g.total_bytes;
            total_data_bytes += g.total_data_bytes;
            total_live_bytes += g.live_bytes;
        }

        let overall_live_ratio = if total_data_bytes > 0 {
            total_live_bytes as f64 / total_data_bytes as f64
        } else if generations.is_empty() {
            1.0
        } else {
            0.0
        };

        Self {
            branch: manifest.branch,
            next_generation: manifest.next_generation,
            next_filename: manifest.next_filename,
            total_inodes: base.len(),
            directory_count,
            file_count,
            symlink_count,
            total_logical_bytes,
            total_disk_bytes,
            total_data_bytes,
            total_live_bytes,
            overall_live_ratio,
            generations,
        }
    }

    /// Formats stats into a clean, human-readable terminal table.
    pub fn display_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "=== appendfs Volume Statistics ===").unwrap();
        writeln!(out, "Branch:              {}", self.branch).unwrap();
        writeln!(
            out,
            "Next Generation:     {} ({})",
            self.next_generation, self.next_filename
        )
        .unwrap();
        writeln!(
            out,
            "Total Inodes:        {} ({} directories, {} files, {} symlinks)",
            self.total_inodes, self.directory_count, self.file_count, self.symlink_count
        )
        .unwrap();
        writeln!(
            out,
            "Logical Data Size:   {}",
            format_bytes(self.total_logical_bytes)
        )
        .unwrap();
        writeln!(
            out,
            "Physical Log Size:   {}",
            format_bytes(self.total_disk_bytes)
        )
        .unwrap();
        writeln!(
            out,
            "Overall Live Ratio:  {:.1}%",
            self.overall_live_ratio * 100.0
        )
        .unwrap();
        writeln!(out).unwrap();

        if self.generations.is_empty() {
            writeln!(
                out,
                "No log generation files present (clean unmounted / fresh summary)."
            )
            .unwrap();
        } else {
            writeln!(
                out,
                "{:<14} {:<10} {:<12} {:<12} {:<12} {:<8} {:<12} {}",
                "LOG FILE",
                "RECORDS",
                "LOG SIZE",
                "DATA SIZE",
                "LIVE DATA",
                "EXTENTS",
                "LIVE RATIO",
                "STATUS"
            )
            .unwrap();
            writeln!(
                out,
                "{:-<14} {:-<10} {:-<12} {:-<12} {:-<12} {:-<8} {:-<12} {:-<20}",
                "", "", "", "", "", "", "", ""
            )
            .unwrap();

            for g in &self.generations {
                let status = if g.live_bytes == 0 && g.total_data_bytes > 0 {
                    "Dead (0% - Reclaimable)"
                } else if g.live_ratio < 0.30 && g.total_data_bytes > 0 {
                    "Compaction Candidate"
                } else if g.live_ratio < 0.70 {
                    "Fragmented"
                } else {
                    "Healthy"
                };

                writeln!(
                    out,
                    "{:<14} {:<10} {:<12} {:<12} {:<12} {:<8} {:<11.1}% {}",
                    g.filename,
                    g.record_count,
                    format_bytes(g.total_bytes),
                    format_bytes(g.total_data_bytes),
                    format_bytes(g.live_bytes),
                    g.live_extents,
                    g.live_ratio * 100.0,
                    status,
                )
                .unwrap();
            }
        }

        out
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.2} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_volume_stats_formatting() {
        let fs = InMemoryFS::new();
        let stats = VolumeStats::collect(&fs);
        assert_eq!(stats.branch, "main");
        assert_eq!(stats.total_inodes, 1);
        assert_eq!(stats.directory_count, 1);
        assert_eq!(stats.file_count, 0);

        let text = stats.display_text();
        assert!(text.contains("Branch:              main"));
        assert!(text.contains("Total Inodes:        1"));
    }
}
