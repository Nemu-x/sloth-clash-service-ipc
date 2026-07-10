use std::sync::Arc;

use anyhow::Result;
use flexi_logger::{Cleanup, FileSpec, Naming, writers::FileLogWriter};

use once_cell::sync::OnceCell;
use tokio::sync::Mutex;

use crate::core::structure::WriterConfig;

type SharedWriter = Arc<Mutex<FileLogWriter>>;
static GLOBAL_WRITER: OnceCell<SharedWriter> = OnceCell::new();

pub fn service_writer(config: &WriterConfig) -> Result<FileLogWriter> {
    // HIGH-3: the GUI reads logs back from its own per-user directory
    // (%APPDATA%\SlothClash\runtime\<profile>\logs), so honor the client path
    // rather than pinning — but validate it the same way as config paths so a
    // caller cannot make the SYSTEM/root process create/write under %SystemRoot%,
    // %ProgramFiles%, /etc, the service dir, etc. Empty falls back to a safe dir.
    crate::core::security::validate_config_location(&config.directory, "log directory")?;
    let directory = if config.directory.trim().is_empty() {
        crate::core::security::pinned_log_dir()
    } else {
        std::path::PathBuf::from(&config.directory)
    };
    let _ = std::fs::create_dir_all(&directory);

    // Clamp caller-controlled sizing to bound disk-fill DoS.
    let max_log_size = config.max_log_size.clamp(1 * 1024 * 1024, 100 * 1024 * 1024);
    let max_log_files = config.max_log_files.clamp(1, 32);

    Ok(FileLogWriter::builder(
        FileSpec::default()
            .directory(directory)
            .basename("service")
            .suppress_timestamp(),
    )
    .format(clash_verge_logger::file_format_without_level)
    .rotate(
        flexi_logger::Criterion::Size(max_log_size),
        Naming::TimestampsCustomFormat {
            current_infix: Some("latest"),
            format: "%Y-%m-%d_%H-%M-%S",
        },
        Cleanup::KeepLogFiles(max_log_files),
    )
    .try_build()?)
}

pub async fn set_or_update_writer(config: &WriterConfig) -> Result<()> {
    let new_writer = service_writer(config)?;

    if let Some(shared) = GLOBAL_WRITER.get() {
        *shared.lock().await = new_writer;
        Ok(())
    } else {
        GLOBAL_WRITER
            .set(Arc::new(Mutex::new(new_writer)))
            .map_err(|_| anyhow::anyhow!("failed to init writer"))
    }
}

pub fn get_writer() -> Option<&'static SharedWriter> {
    GLOBAL_WRITER.get()
}
