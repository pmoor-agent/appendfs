use crate::log::SummaryReader;
use crate::remote::config::{RemoteRegistry, RemoteTargetConfig};
use crate::remote::{RemoteObject, RemoteStore};
use crate::storage::{Storage, WriteMode};
use std::io::{self, Write};

struct StorageWriterAdapter<'a>(&'a mut Box<dyn crate::storage::StorageWriter>);

impl<'a> Write for StorageWriterAdapter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.append(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.sync()
    }
}

/// Bootstraps a local volume directory from an existing remote object store (`appendfs init --from-remote`).
///
/// Downloads the latest `.summary` snapshot (and any unsealed active part files), verifying
/// headers and checksums. Saves the remote configuration into `remotes.toml` so subsequent
/// mounts immediately recognize the remote.
pub fn bootstrap_from_remote(
    remote: &dyn RemoteStore,
    storage: &dyn Storage,
    remote_name: &str,
    remote_cfg: RemoteTargetConfig,
) -> io::Result<String> {
    // 1. Discover all remote objects
    let objects = remote.list_objects("")?;
    if objects.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Remote store contains no objects (empty bucket/prefix)",
        ));
    }

    // 2. Find newest .summary file
    let mut latest_summary: Option<((u32, u32), String)> = None;
    for obj in &objects {
        if let Some((generation, rev)) = crate::log::parse_summary_filename(&obj.key)
            && latest_summary.as_ref().is_none_or(|(gr, _)| (generation, rev) > *gr)
        {
            latest_summary = Some(((generation, rev), obj.key.clone()));
        }
    }

    let ((summary_gen, summary_rev), summary_key) = latest_summary.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "No valid .summary checkpoint files found in remote store",
        )
    })?;

    let local_summary_name = crate::log::summary_filename_with_revision(summary_gen, summary_rev);
    let tmp_summary_name = format!("{}.tmp", local_summary_name);

    // 3. Download summary snapshot to tmp and verify
    {
        let mut writer = storage.open_writer(&tmp_summary_name, WriteMode::Overwrite)?;
        let mut adapter = StorageWriterAdapter(&mut writer);
        remote.get_object(&summary_key, &mut adapter)?;
        writer.sync()?;
    }

    // Verify summary header
    SummaryReader::read_volume_header(storage, &tmp_summary_name)?;
    storage.rename(&tmp_summary_name, &local_summary_name)?;
    log::info!(
        "Downloaded latest checkpoint {} from remote '{}'",
        local_summary_name,
        remote_name
    );

    // 4. Download any active intermediate parts for generation summary_gen + 1,
    // or the full sealed log if already consolidated on remote
    restore_next_generation_log(remote, storage, &objects, summary_gen + 1)?;

    // 5. Save remote configuration to remotes.toml in storage
    let mut registry = RemoteRegistry::load_from_storage(storage)?;
    registry.add_remote(remote_name, remote_cfg);
    registry.save_to_storage(storage)?;

    Ok(local_summary_name)
}

fn restore_next_generation_log(
    remote: &dyn RemoteStore,
    storage: &dyn Storage,
    objects: &[RemoteObject],
    next_gen: u32,
) -> io::Result<()> {
    let sealed_log_name = crate::log::log_filename(next_gen);
    if let Some(sealed_obj) = objects.iter().find(|o| o.key == sealed_log_name) {
        log::info!(
            "Found sealed generation {} ({}, {} bytes) on remote; downloading...",
            next_gen,
            sealed_log_name,
            sealed_obj.size
        );
        let mut log_writer = storage.open_writer(&sealed_log_name, WriteMode::Overwrite)?;
        let mut adapter = StorageWriterAdapter(&mut log_writer);
        remote.get_object(&sealed_log_name, &mut adapter)?;
        log_writer.sync()?;
        return Ok(());
    }

    let part_prefix = format!("{:06}.part", next_gen);
    let mut part_objects: Vec<_> = objects
        .iter()
        .filter(|o| o.key.starts_with(&part_prefix) && o.key.ends_with(".log"))
        .cloned()
        .collect();

    if !part_objects.is_empty() {
        part_objects.sort_by(|a, b| a.key.cmp(&b.key));
        let active_log_name = crate::log::log_filename(next_gen);
        log::info!(
            "Found {} active unsealed part(s) for generation {}; reconstructing {}...",
            part_objects.len(),
            next_gen,
            active_log_name
        );

        let mut log_writer = storage.open_writer(&active_log_name, WriteMode::Overwrite)?;
        let header = crate::log::record::FileHeader::new(next_gen, std::time::SystemTime::now());
        log_writer.append(&header.to_bytes())?;

        for part in part_objects {
            let mut adapter = StorageWriterAdapter(&mut log_writer);
            remote.get_object(&part.key, &mut adapter)?;
        }
        log_writer.sync()?;
    }

    Ok(())
}
