//! A directory-backed [`Blob`] adapter (issue #105): small media on the local
//! filesystem for a self-hosted deployment. Each object is a file under a base
//! directory, and its content type is a sibling `.__ct` file. There are no
//! presigned URLs, so `signed_url` reports [`BlobError::Unsupported`] — serve
//! the bytes through the harness with [`Blob::get`], or reach for an
//! S3-compatible adapter when direct downloads matter.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cratefield_core::{Blob, BlobError, BlobObject, check_blob_size};

/// Stores blobs as files under `base`.
pub struct DirBlob {
    base: PathBuf,
}

impl DirBlob {
    /// A store rooted at `base`. The directory is created on first write.
    #[must_use]
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    /// The store as an `Arc<dyn Blob>`, for `Native::blob_arc`.
    #[must_use]
    pub fn arc(base: impl Into<PathBuf>) -> Arc<dyn Blob> {
        Arc::new(Self::new(base))
    }

    /// The object path for `key`, refusing an empty, absolute, or escaping key
    /// (defence in depth — the harness's `ScopedBlob` already prefixes and
    /// checks, but the adapter must be safe on its own).
    fn object_path(&self, key: &str) -> Result<PathBuf, BlobError> {
        if key.is_empty() {
            return Err(BlobError::BadKey("a blob key cannot be empty".to_owned()));
        }
        if key.starts_with('/') {
            return Err(BlobError::BadKey(format!("key `{key}` must be relative")));
        }
        if key
            .split('/')
            .any(|segment| segment == ".." || segment == ".")
        {
            return Err(BlobError::BadKey(format!(
                "key `{key}` must not contain `.` or `..` segments"
            )));
        }
        Ok(self.base.join(key))
    }

    fn content_type_path(path: &std::path::Path) -> PathBuf {
        PathBuf::from(format!("{}.__ct", path.display()))
    }

    fn io_err(err: &std::io::Error) -> BlobError {
        BlobError::Operation(err.to_string())
    }
}

#[async_trait]
impl Blob for DirBlob {
    async fn put(&self, key: &str, bytes: &[u8], content_type: &str) -> Result<(), BlobError> {
        check_blob_size(bytes)?;
        let path = self.object_path(key)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|err| Self::io_err(&err))?;
        }
        tokio::fs::write(&path, bytes)
            .await
            .map_err(|err| Self::io_err(&err))?;
        tokio::fs::write(Self::content_type_path(&path), content_type.as_bytes())
            .await
            .map_err(|err| Self::io_err(&err))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<BlobObject>, BlobError> {
        let path = self.object_path(key)?;
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(Self::io_err(&err)),
        };
        let content_type = tokio::fs::read_to_string(Self::content_type_path(&path))
            .await
            .unwrap_or_else(|_| "application/octet-stream".to_owned());
        Ok(Some(BlobObject {
            bytes,
            content_type,
        }))
    }

    async fn delete(&self, key: &str) -> Result<(), BlobError> {
        let path = self.object_path(key)?;
        for target in [path.clone(), Self::content_type_path(&path)] {
            match tokio::fs::remove_file(&target).await {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(Self::io_err(&err)),
            }
        }
        Ok(())
    }

    async fn signed_url(&self, _key: &str, _ttl: Duration) -> Result<String, BlobError> {
        Err(BlobError::Unsupported(
            "a directory store has no presigned URLs; serve the bytes through the harness \
             or use an S3-compatible adapter"
                .to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("cf-blob-{}", uuid_like()))
    }

    fn uuid_like() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        format!(
            "{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    #[tokio::test]
    async fn round_trips_bytes_and_content_type() {
        let base = temp_dir();
        let blob = DirBlob::new(&base);
        blob.put("cms/hero.png", b"\x89PNG", "image/png")
            .await
            .unwrap();
        let got = blob.get("cms/hero.png").await.unwrap().expect("present");
        assert_eq!(got.bytes, b"\x89PNG");
        assert_eq!(got.content_type, "image/png");
        assert!(blob.get("cms/missing.png").await.unwrap().is_none());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn delete_is_idempotent_and_removes_both_files() {
        let base = temp_dir();
        let blob = DirBlob::new(&base);
        blob.put("a/b.txt", b"hi", "text/plain").await.unwrap();
        blob.delete("a/b.txt").await.unwrap();
        assert!(blob.get("a/b.txt").await.unwrap().is_none());
        // A second delete is a no-op, not an error.
        blob.delete("a/b.txt").await.unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn an_escaping_key_is_refused() {
        let blob = DirBlob::new(temp_dir());
        for bad in ["", "/etc/passwd", "../x", "a/../../b", "."] {
            assert!(matches!(
                blob.get(bad).await.unwrap_err(),
                BlobError::BadKey(_)
            ));
        }
    }
}
