use std::path::PathBuf;

use zenith_sync::config::Config;
use zenith_sync::source::smb::SmbSource;
use zenith_sync::source::{ReadAt, RemotePath, Source};

fn enabled() -> bool {
    std::env::var_os("ZS_TEST_SMB").is_some()
}

fn var_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

async fn connect() -> SmbSource {
    let config_path = std::env::var_os("ZS_TEST_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| Config::default_path().unwrap());
    let config = Config::load(&config_path).unwrap();
    let remote = config
        .remote(&std::env::var("ZS_TEST_REMOTE").expect("set ZS_TEST_REMOTE"))
        .unwrap();
    let auth = config.auth(remote).unwrap();
    let password = auth.password.resolve().unwrap();
    SmbSource::connect(&remote.url, &auth.principal(), &password)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn lists_and_stats_share_read_only() {
    if !enabled() {
        return;
    }
    let source = connect().await;

    let root = source.stat(&RemotePath::root()).await.unwrap();
    assert!(root.is_dir);

    let path: RemotePath = var_or("ZS_TEST_PATH", "").parse().unwrap();
    let entries = source.list(&path).await.unwrap();
    assert!(!entries.is_empty(), "{path} is empty");

    let first = &entries[0];
    assert_eq!(
        first.path.components().count(),
        path.components().count() + 1
    );
    let stat = source.stat(&first.path).await.unwrap();
    assert_eq!(stat.is_dir, first.is_dir);
    assert_eq!(stat.file_id, first.file_id);
    assert_eq!(stat.mtime, first.mtime);

    if let Some(file) = entries.iter().find(|e| !e.is_dir && e.size > 0) {
        let reader = source.open_read(&file.path).await.unwrap();
        let mut buf = [0u8; 16];
        let read = reader.read_at(&mut buf, 0).await.unwrap();
        assert_eq!(read as u64, file.size.min(16));
    }

    assert!(source.list(&RemotePath::root()).await.is_ok());
}
