use std::str::FromStr;
use std::sync::Arc;

use futures_util::StreamExt;
use secrecy::{ExposeSecret, SecretString};
use smb::{
    Client, ClientConfig, Dialect, DirAccessMask, Directory, File, FileAccessMask, FileCreateArgs,
    FileIdBothDirectoryInformation, FileInternalInformation, FileNetworkOpenInformation, Resource,
    ResourceHandle, UncPath,
};

use super::{Entry, Error, FileId, ReadAt, RemotePath, Source};
use crate::config::SmbUrl;

pub struct SmbSource {
    client: Client,
    share: UncPath,
}

impl SmbSource {
    pub async fn connect(
        url: &SmbUrl,
        principal: &str,
        password: &SecretString,
    ) -> Result<Self, Error> {
        let connect_err = |source| Error::Connect {
            url: url.to_string(),
            source,
        };
        let mut config = ClientConfig::default();
        config.connection.min_dialect = Some(Dialect::Smb030);
        let client = Client::new(config);
        let share = UncPath::from_str(&url.to_unc()).map_err(connect_err)?;
        client
            .share_connect(&share, principal, password.expose_secret().to_owned())
            .await
            .map_err(connect_err)?;
        Ok(Self { client, share })
    }

    fn unc(&self, path: &RemotePath) -> UncPath {
        if path.is_root() {
            self.share.clone()
        } else {
            self.share.clone().with_path(path.as_str())
        }
    }

    async fn open(&self, path: &RemotePath, access: FileAccessMask) -> Result<Resource, Error> {
        self.client
            .create_file(&self.unc(path), &FileCreateArgs::make_open_existing(access))
            .await
            .map_err(|source| smb_err(path, source))
    }
}

impl Source for SmbSource {
    type Reader = SmbReader;

    async fn list(&self, path: &RemotePath) -> Result<Vec<Entry>, Error> {
        let access = DirAccessMask::new()
            .with_list_directory(true)
            .with_synchronize(true)
            .into();
        let dir = match self.open(path, access).await? {
            Resource::Directory(dir) => Arc::new(dir),
            other => {
                close(other).await;
                return Err(Error::NotADirectory(path.clone()));
            }
        };
        let entries = list_dir(&dir, path).await;
        if let Err(source) = dir.close().await {
            tracing::debug!("cannot close {path}: {source}");
        }
        entries
    }

    async fn stat(&self, path: &RemotePath) -> Result<Entry, Error> {
        let access = FileAccessMask::new()
            .with_file_read_attributes(true)
            .with_synchronize(true);
        let resource = self.open(path, access).await?;
        let entry = match &resource {
            Resource::File(file) => stat_handle(file, path).await,
            Resource::Directory(dir) => stat_handle(dir, path).await,
            Resource::Pipe(_) => Err(Error::NotAFile(path.clone())),
        };
        close(resource).await;
        entry
    }

    async fn open_read(&self, path: &RemotePath) -> Result<SmbReader, Error> {
        let access = FileAccessMask::new().with_generic_read(true);
        match self.open(path, access).await? {
            Resource::File(file) => Ok(SmbReader {
                file,
                path: path.clone(),
            }),
            other => {
                close(other).await;
                Err(Error::NotAFile(path.clone()))
            }
        }
    }
}

pub struct SmbReader {
    file: File,
    path: RemotePath,
}

impl ReadAt for SmbReader {
    async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize, Error> {
        smb::ReadAt::read_at(&self.file, buf, offset)
            .await
            .map_err(|source| smb_err(&self.path, source))
    }
}

async fn list_dir(dir: &Arc<Directory>, path: &RemotePath) -> Result<Vec<Entry>, Error> {
    let mut stream = Directory::query::<FileIdBothDirectoryInformation>(dir, "*")
        .await
        .map_err(|source| smb_err(path, source))?;
    let mut entries = Vec::new();
    while let Some(info) = stream.next().await {
        let info = info.map_err(|source| smb_err(path, source))?;
        let name = info.file_name.to_string();
        if name == "." || name == ".." {
            continue;
        }
        entries.push(Entry {
            path: path.join(&name)?,
            size: info.end_of_file,
            mtime: info.last_write_time.into(),
            file_id: FileId(info.file_id),
            is_dir: info.file_attributes.directory(),
        });
    }
    Ok(entries)
}

async fn stat_handle(handle: &ResourceHandle, path: &RemotePath) -> Result<Entry, Error> {
    let err = |source| smb_err(path, source);
    let info = handle
        .query_info::<FileNetworkOpenInformation>()
        .await
        .map_err(err)?;
    let internal = handle
        .query_info::<FileInternalInformation>()
        .await
        .map_err(err)?;
    Ok(Entry {
        path: path.clone(),
        size: info.end_of_file,
        mtime: info.last_write_time.into(),
        file_id: FileId(internal.index_number),
        is_dir: info.file_attributes.directory(),
    })
}

async fn close(resource: Resource) {
    let result = match &resource {
        Resource::File(file) => file.close().await,
        Resource::Directory(dir) => dir.close().await,
        Resource::Pipe(pipe) => pipe.close().await,
    };
    if let Err(source) = result {
        tracing::debug!("cannot close smb handle: {source}");
    }
}

fn smb_err(path: &RemotePath, source: smb::Error) -> Error {
    Error::Smb {
        path: path.clone(),
        source,
    }
}
