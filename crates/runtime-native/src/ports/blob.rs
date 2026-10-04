//! A directory-backed [`Blob`] adapter (issue #105): small media on the local
//! filesystem for a self-hosted deployment. Each object is a file under a base
//! directory, and its content type is a sibling `.__ct` file. There are no
//! presigned URLs, so `signed_url` reports [`BlobError::Unsupported`] and
//! `signed_put_url` inherits the trait default, which reports the same — serve
//! the bytes through the harness with [`Blob::get`], or reach for an
//! S3-compatible adapter when direct downloads matter.
//!
//! The large-object methods (issue #586) live here too: [`Blob::put_stream`]
//! and [`Blob::get_stream`] move an object past [`MAX_BLOB_BYTES`] through a
//! hidden staging directory without buffering it, and the multipart methods
//! assemble one from parts. Those staging directories start with `.__`, which
//! no module key can: keys arrive as `<module>/…` and a module name is
//! `[a-z0-9-]+` (checked by the harness, `is_module_name`), so its first path
//! segment never begins with a dot.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_core::Stream;
use tokio::io::AsyncWriteExt as _;
use tokio_util::io::ReaderStream;

use cratefield_core::{
    Blob, BlobError, BlobMeta, BlobObject, BlobPage, BlobStream, BoxStream, MAX_LIST_LIMIT,
    MIN_MULTIPART_PART_BYTES, PartReceipt, PendingUpload, StreamError, UploadId,
    blob_error_from_stream, check_blob_size, check_part_number, limit_stream,
};

/// The hidden directory a streamed put writes its temp file in before the
/// atomic rename into place.
const TMP_DIR: &str = ".__tmp";

/// The hidden directory holding one directory per multipart upload in flight.
const MULTIPART_DIR: &str = ".__multipart";

/// The file inside a multipart upload directory naming its target key.
const MULTIPART_KEY_FILE: &str = "key";

/// The file inside a multipart upload directory holding its content type.
const MULTIPART_CONTENT_TYPE_FILE: &str = "content_type";

/// The suffix of the sidecar file an object's content type is stored in.
const CONTENT_TYPE_SUFFIX: &str = ".__ct";

/// The chunk size a streamed read is broken into.
const READ_CHUNK: usize = 64 * 1024;

/// The content type read back when the sidecar is missing, so an object
/// written before the sidecar existed still serves.
const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

/// The part file's name: the part number zero-padded to a fixed width so the
/// files also sort in part order on disk.
fn part_file(part_number: u16) -> String {
    format!("part-{part_number:05}")
}

/// The `ETag` the store hands back for a stored part: deterministic from the
/// part number and the bytes written, so `complete_multipart` can recompute
/// it from the part file's length and catch a wrong or forged receipt.
fn part_etag(part_number: u16, len: u64) -> String {
    format!("part-{part_number}-{len}")
}

/// A unique token for a temp file or an upload id: the wall clock in
/// nanoseconds, the process id, and a process-wide counter, so two calls in
/// the same nanosecond still differ and two processes writing the same base
/// do not collide. No RNG dependency for a name that only has to be unique
/// within one store.
fn unique_token() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    format!("{nanos:x}-{:x}-{seq:x}", std::process::id())
}

/// Validates the parts of a multipart upload before they are assembled: every
/// receipt names a part that was uploaded, its `ETag` matches the bytes on
/// disk, and every part but the last is at least [`MIN_MULTIPART_PART_BYTES`]
/// (issue #586). Checks the on-disk state without removing it, so a refused
/// complete leaves the upload intact for a retry, as a real store does.
async fn validate_parts(dir: &Path, ordered: &[PartReceipt]) -> Result<(), BlobError> {
    for (index, receipt) in ordered.iter().enumerate() {
        let path = dir.join(part_file(receipt.part_number));
        let meta = match tokio::fs::metadata(&path).await {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(BlobError::Operation(format!(
                    "part {} was never uploaded",
                    receipt.part_number
                )));
            }
            Err(err) => return Err(DirBlob::io_err(&err)),
        };
        if part_etag(receipt.part_number, meta.len()) != receipt.etag {
            return Err(BlobError::Operation(format!(
                "part {} etag mismatch",
                receipt.part_number
            )));
        }
        let is_last = index + 1 == ordered.len();
        if !is_last && meta.len() < MIN_MULTIPART_PART_BYTES {
            return Err(BlobError::Operation(format!(
                "part {} is below the {MIN_MULTIPART_PART_BYTES}-byte minimum for a non-final part",
                receipt.part_number,
            )));
        }
    }
    Ok(())
}

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

    fn content_type_path(path: &Path) -> PathBuf {
        PathBuf::from(format!("{}{CONTENT_TYPE_SUFFIX}", path.display()))
    }

    /// The content type stored beside `path`, or the default when the sidecar
    /// is absent.
    async fn read_content_type(path: &Path) -> String {
        tokio::fs::read_to_string(Self::content_type_path(path))
            .await
            .unwrap_or_else(|_| DEFAULT_CONTENT_TYPE.to_owned())
    }

    fn io_err(err: &std::io::Error) -> BlobError {
        BlobError::Operation(err.to_string())
    }

    /// The hidden staging directory temp files are written under.
    fn tmp_dir(&self) -> PathBuf {
        self.base.join(TMP_DIR)
    }

    /// The directory one multipart upload's parts live in. The id arrives
    /// from `create_multipart` (or a caller), so it is validated as a single
    /// path segment before it names a directory — a caller must not be able
    /// to walk out of the store with it.
    fn upload_dir(&self, upload_id: &UploadId) -> Result<PathBuf, BlobError> {
        let raw = upload_id.as_str();
        if raw.is_empty() || raw == "." || raw == ".." || raw.contains('/') || raw.contains('\\') {
            return Err(BlobError::Operation(format!(
                "invalid multipart upload id `{raw}`"
            )));
        }
        Ok(self.base.join(MULTIPART_DIR).join(raw))
    }

    /// Reads a multipart upload's target key, or reports the upload unknown.
    async fn read_upload_key(dir: &Path, upload_id: &UploadId) -> Result<String, BlobError> {
        match tokio::fs::read_to_string(dir.join(MULTIPART_KEY_FILE)).await {
            Ok(key) => Ok(key),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err(BlobError::Operation(
                format!("no multipart upload `{}`", upload_id.as_str()),
            )),
            Err(err) => Err(Self::io_err(&err)),
        }
    }

    /// Streams `body` into `path`, capped at `max_bytes` through
    /// [`limit_stream`], and returns the bytes written. On any error —
    /// ceiling breach, transport, IO — the partial file is removed, so a
    /// refused write leaves nothing behind.
    async fn stream_to_file(
        path: &Path,
        body: BoxStream<'static, Result<Bytes, StreamError>>,
        max_bytes: u64,
    ) -> Result<u64, BlobError> {
        let mut file = tokio::fs::File::create(path)
            .await
            .map_err(|err| Self::io_err(&err))?;
        let mut limited = limit_stream(body, max_bytes);
        let result: Result<u64, BlobError> = async {
            let mut written: u64 = 0;
            while let Some(chunk) = std::future::poll_fn(|cx| limited.as_mut().poll_next(cx)).await
            {
                let chunk = chunk.map_err(blob_error_from_stream)?;
                file.write_all(&chunk)
                    .await
                    .map_err(|err| Self::io_err(&err))?;
                written = written.saturating_add(chunk.len() as u64);
            }
            file.flush().await.map_err(|err| Self::io_err(&err))?;
            Ok(written)
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(path).await;
        }
        result
    }

    /// Writes `tmp` into place at `path` with `content_type`: the parent
    /// directory, the content-type sidecar, then the atomic rename. Shared by
    /// [`Blob::put_stream`] and [`Blob::complete_multipart`].
    async fn place_object(tmp: &Path, path: &Path, content_type: &str) -> Result<(), BlobError> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|err| Self::io_err(&err))?;
        }
        tokio::fs::write(Self::content_type_path(path), content_type.as_bytes())
            .await
            .map_err(|err| Self::io_err(&err))?;
        tokio::fs::rename(tmp, path)
            .await
            .map_err(|err| Self::io_err(&err))
    }

    /// The metadata of an object without reading its body, or `None` if there
    /// is none.
    async fn meta_for(&self, key: &str) -> Result<Option<BlobMeta>, BlobError> {
        let path = self.object_path(key)?;
        let meta = match tokio::fs::metadata(&path).await {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(Self::io_err(&err)),
        };
        if !meta.is_file() {
            return Ok(None);
        }
        Ok(Some(BlobMeta {
            key: key.to_owned(),
            size: meta.len(),
            content_type: Self::read_content_type(&path).await,
        }))
    }

    /// Walks `base` recursively, returning the keys of the objects whose key
    /// starts with `prefix`, in lexicographic order. Skips the hidden staging
    /// directories and the `.__ct` sidecar files, so neither ever surfaces as
    /// an object.
    async fn collect_keys(&self, prefix: &str) -> Result<Vec<String>, BlobError> {
        let mut keys = Vec::new();
        let mut stack = vec![self.base.clone()];
        while let Some(dir) = stack.pop() {
            let mut entries = match tokio::fs::read_dir(&dir).await {
                Ok(entries) => entries,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => return Err(Self::io_err(&err)),
            };
            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(|err| Self::io_err(&err))?
            {
                let file_type = entry.file_type().await.map_err(|err| Self::io_err(&err))?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if file_type.is_dir() {
                    if name == TMP_DIR || name == MULTIPART_DIR {
                        continue;
                    }
                    stack.push(entry.path());
                } else if file_type.is_file() {
                    if name.ends_with(CONTENT_TYPE_SUFFIX) {
                        continue;
                    }
                    if let Ok(rel) = entry.path().strip_prefix(&self.base) {
                        let key = rel
                            .components()
                            .map(|part| part.as_os_str().to_string_lossy().into_owned())
                            .collect::<Vec<_>>()
                            .join("/");
                        if key.starts_with(prefix) {
                            keys.push(key);
                        }
                    }
                }
            }
        }
        keys.sort();
        Ok(keys)
    }

    /// Reads a multipart upload's content type, defaulting when it is absent.
    async fn read_upload_content_type(dir: &Path) -> String {
        tokio::fs::read_to_string(dir.join(MULTIPART_CONTENT_TYPE_FILE))
            .await
            .unwrap_or_else(|_| DEFAULT_CONTENT_TYPE.to_owned())
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
        Ok(Some(BlobObject {
            bytes,
            content_type: Self::read_content_type(&path).await,
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

    /// A directory store has no presigned URLs: neither a `GET` nor (through
    /// the trait default) a `PUT`.
    async fn signed_url(&self, _key: &str, _ttl: Duration) -> Result<String, BlobError> {
        Err(BlobError::Unsupported(
            "a directory store has no presigned URLs; serve the bytes through the harness \
             or use an S3-compatible adapter"
                .to_owned(),
        ))
    }

    async fn put_stream(
        &self,
        key: &str,
        body: BoxStream<'static, Result<Bytes, StreamError>>,
        content_type: &str,
        max_bytes: u64,
    ) -> Result<u64, BlobError> {
        let path = self.object_path(key)?;
        let tmp_dir = self.tmp_dir();
        tokio::fs::create_dir_all(&tmp_dir)
            .await
            .map_err(|err| Self::io_err(&err))?;
        let tmp = tmp_dir.join(unique_token());
        let written = Self::stream_to_file(&tmp, body, max_bytes).await?;
        if let Err(err) = Self::place_object(&tmp, &path, content_type).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(err);
        }
        Ok(written)
    }

    async fn get_stream(&self, key: &str) -> Result<Option<BlobStream>, BlobError> {
        let path = self.object_path(key)?;
        let file = match tokio::fs::File::open(&path).await {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(Self::io_err(&err)),
        };
        let size = file
            .metadata()
            .await
            .map_err(|err| Self::io_err(&err))?
            .len();
        let content_type = Self::read_content_type(&path).await;
        Ok(Some(BlobStream {
            content_type,
            size,
            body: Box::pin(MapIoError {
                inner: ReaderStream::with_capacity(file, READ_CHUNK),
            }),
        }))
    }

    async fn head(&self, key: &str) -> Result<Option<BlobMeta>, BlobError> {
        self.meta_for(key).await
    }

    async fn list(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<BlobPage, BlobError> {
        let limit = limit.clamp(1, MAX_LIST_LIMIT);
        let keys = self.collect_keys(prefix).await?;
        let start = cursor.map_or(0, |cursor| {
            keys.partition_point(|key| key.as_str() <= cursor)
        });
        let take = (keys.len() - start).min(limit);
        let selected = &keys[start..start + take];
        let mut objects = Vec::with_capacity(selected.len());
        for key in selected {
            if let Some(meta) = self.meta_for(key).await? {
                objects.push(meta);
            }
        }
        let cursor = if start + take < keys.len() {
            selected.last().cloned()
        } else {
            None
        };
        Ok(BlobPage { objects, cursor })
    }

    async fn create_multipart(&self, key: &str, content_type: &str) -> Result<UploadId, BlobError> {
        // Validate the key before creating anything, so a bad key leaves no
        // directory behind.
        let _ = self.object_path(key)?;
        let upload_id = UploadId::new(unique_token());
        let dir = self.upload_dir(&upload_id)?;
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|err| Self::io_err(&err))?;
        tokio::fs::write(dir.join(MULTIPART_KEY_FILE), key.as_bytes())
            .await
            .map_err(|err| Self::io_err(&err))?;
        tokio::fs::write(
            dir.join(MULTIPART_CONTENT_TYPE_FILE),
            content_type.as_bytes(),
        )
        .await
        .map_err(|err| Self::io_err(&err))?;
        Ok(upload_id)
    }

    async fn upload_part(
        &self,
        key: &str,
        upload_id: &UploadId,
        part_number: u16,
        body: BoxStream<'static, Result<Bytes, StreamError>>,
        max_part_bytes: u64,
    ) -> Result<PartReceipt, BlobError> {
        check_part_number(part_number)?;
        let dir = self.upload_dir(upload_id)?;
        let stored = Self::read_upload_key(&dir, upload_id).await?;
        if stored != key {
            return Err(BlobError::Operation(
                "multipart upload belongs to a different key".to_owned(),
            ));
        }
        let tmp_dir = self.tmp_dir();
        tokio::fs::create_dir_all(&tmp_dir)
            .await
            .map_err(|err| Self::io_err(&err))?;
        let tmp = tmp_dir.join(unique_token());
        let written = Self::stream_to_file(&tmp, body, max_part_bytes).await?;
        tokio::fs::rename(&tmp, dir.join(part_file(part_number)))
            .await
            .map_err(|err| {
                // The rename is the only step after the stream succeeded; a
                // failure here leaves the temp file, so sweep it up.
                let _ = std::fs::remove_file(&tmp);
                Self::io_err(&err)
            })?;
        Ok(PartReceipt {
            part_number,
            etag: part_etag(part_number, written),
        })
    }

    async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &UploadId,
        parts: &[PartReceipt],
    ) -> Result<(), BlobError> {
        let dir = self.upload_dir(upload_id)?;
        let stored = Self::read_upload_key(&dir, upload_id).await?;
        if stored != key {
            return Err(BlobError::Operation(
                "multipart upload belongs to a different key".to_owned(),
            ));
        }
        let mut ordered = parts.to_vec();
        ordered.sort_by_key(|receipt| receipt.part_number);
        validate_parts(&dir, &ordered).await?;

        let content_type = Self::read_upload_content_type(&dir).await;
        let path = self.object_path(key)?;
        let tmp_dir = self.tmp_dir();
        tokio::fs::create_dir_all(&tmp_dir)
            .await
            .map_err(|err| Self::io_err(&err))?;
        let tmp = tmp_dir.join(unique_token());
        let assembled = async {
            let mut dst = tokio::fs::File::create(&tmp)
                .await
                .map_err(|err| Self::io_err(&err))?;
            for receipt in &ordered {
                let mut src = tokio::fs::File::open(dir.join(part_file(receipt.part_number)))
                    .await
                    .map_err(|err| Self::io_err(&err))?;
                tokio::io::copy(&mut src, &mut dst)
                    .await
                    .map_err(|err| Self::io_err(&err))?;
            }
            dst.flush().await.map_err(|err| Self::io_err(&err))
        }
        .await;
        if let Err(err) = assembled {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(err);
        }
        if let Err(err) = Self::place_object(&tmp, &path, &content_type).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(err);
        }
        let _ = tokio::fs::remove_dir_all(&dir).await;
        Ok(())
    }

    async fn abort_multipart(&self, key: &str, upload_id: &UploadId) -> Result<(), BlobError> {
        let dir = self.upload_dir(upload_id)?;
        let stored = Self::read_upload_key(&dir, upload_id).await?;
        if stored != key {
            return Err(BlobError::Operation(
                "multipart upload belongs to a different key".to_owned(),
            ));
        }
        tokio::fs::remove_dir_all(&dir)
            .await
            .map_err(|err| Self::io_err(&err))
    }

    async fn list_multipart_uploads(&self, prefix: &str) -> Result<Vec<PendingUpload>, BlobError> {
        let root = self.base.join(MULTIPART_DIR);
        let mut entries = match tokio::fs::read_dir(&root).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(Self::io_err(&err)),
        };
        let mut pending = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|err| Self::io_err(&err))?
        {
            let Ok(key) = tokio::fs::read_to_string(entry.path().join(MULTIPART_KEY_FILE)).await
            else {
                continue;
            };
            if key.starts_with(prefix) {
                let upload_id = UploadId::new(entry.file_name().to_string_lossy().into_owned());
                pending.push(PendingUpload { key, upload_id });
            }
        }
        pending.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(pending)
    }
}

/// Adapts [`ReaderStream`]'s `io::Error` to the port's [`StreamError`], so a
/// mid-stream read failure surfaces as a transport error rather than being
/// swallowed.
struct MapIoError<S> {
    inner: S,
}

impl<S> Stream for MapIoError<S>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Unpin,
{
    type Item = Result<Bytes, StreamError>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let inner = std::pin::Pin::new(&mut self.get_mut().inner);
        inner.poll_next(cx).map(|polled| {
            polled.map(|item| item.map_err(|err| StreamError::Transport(err.to_string())))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use cratefield_testing::assert_blob_large_round_trips;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("cf-blob-{}", unique_token()))
    }

    /// A `Stream` over pre-built chunks, for the streamed-write tests.
    struct Chunks(std::vec::IntoIter<Result<Bytes, StreamError>>);

    impl Stream for Chunks {
        type Item = Result<Bytes, StreamError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.get_mut().0.next())
        }
    }

    /// Type-erases `chunks` into the body shape the blob port takes.
    fn chunk_stream(chunks: Vec<Vec<u8>>) -> BoxStream<'static, Result<Bytes, StreamError>> {
        Box::pin(Chunks(
            chunks
                .into_iter()
                .map(|chunk| Ok(Bytes::from(chunk)))
                .collect::<Vec<_>>()
                .into_iter(),
        ))
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

    /// The `Blob` large-object contract (issue #586) holds on the directory
    /// store, the same way `crates/testing/tests/blob_large.rs` holds it on
    /// the memory fake.
    #[tokio::test]
    async fn dir_blob_satisfies_the_large_blob_contract() {
        let base = temp_dir();
        assert_blob_large_round_trips(DirBlob::arc(&base)).await;
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A streamed put past its ceiling leaves no object and no temp file: the
    /// staging file is swept up on the refusal.
    #[tokio::test]
    async fn a_refused_streamed_put_leaves_no_temp_files() {
        let base = temp_dir();
        let blob = DirBlob::new(&base);
        let err = blob
            .put_stream(
                "cms/big.bin",
                chunk_stream(vec![vec![0_u8; 4096]]),
                "application/octet-stream",
                1024,
            )
            .await
            .expect_err("4096 bytes over a 1024-byte ceiling is refused");
        assert!(matches!(err, BlobError::TooLarge(_)), "got {err:?}");
        assert!(blob.get("cms/big.bin").await.unwrap().is_none());

        let mut leftover = 0;
        if let Ok(mut entries) = tokio::fs::read_dir(base.join(TMP_DIR)).await {
            while entries.next_entry().await.unwrap().is_some() {
                leftover += 1;
            }
        }
        assert_eq!(leftover, 0, "no staging file remains after the refusal");
        let _ = std::fs::remove_dir_all(&base);
    }
}
