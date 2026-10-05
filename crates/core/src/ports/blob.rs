//! The `Blob` port (issue #105): small media stored outside the database —
//! R2 on Workers, a directory or S3-compatible store when self-hosted.
//!
//! KV caps a value at 25 MB and is the wrong tool for media, and D1 `BLOB`
//! columns are banned by the portable lint, so a coach's voice clip (the
//! request in `yoginini-backend#4`) has nowhere to live. This port gives it
//! one, keyed and content-typed, with the same ownership rule the tables have:
//! a module only ever touches keys under its own `<module>/` prefix, enforced
//! by the [`ScopedBlob`] the harness hands each module.

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_core::Stream;
use thiserror::Error;

use crate::stream::{BoxStream, ResponseStream, StreamError};

/// Hard ceiling on one stored object (issue #136). The port exists for
/// *small* media — a coach's voice clip, an avatar — and every caller
/// reaches it through [`ScopedBlob`] or an adapter that enforces this
/// bound before allocating or writing. Ten MiB is well past any legit
/// clip at conversational bitrates and far below what threatens a
/// self-hosted process or an isolate that buffers the bytes.
///
/// Objects above this bound take a separate, explicitly opted-in path:
/// the streamed [`Blob::put_stream`] and the multipart upload methods
/// (issue #586), bounded instead by the module's declared
/// [`Module::max_blob_object_bytes`](crate::Module::max_blob_object_bytes).
pub const MAX_BLOB_BYTES: usize = 10 * 1024 * 1024;

/// The harness-wide absolute cap on the large-object limit a module may
/// declare (issue #586). Five GiB is a harness-chosen ceiling — large
/// enough to stream a video for a person who uploaded one, and well under
/// R2's ~5 TiB single-object maximum — so no module can declare its way
/// past a bound the harness is willing to enforce.
pub const MAX_LARGE_BLOB_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// The most parts one multipart upload may have (issue #586): S3's and
/// R2's own limit. [`Blob::complete_multipart`] refuses more, and part
/// numbers are `1 ..= MAX_MULTIPART_PARTS`.
pub const MAX_MULTIPART_PARTS: u16 = 10_000;

/// The smallest a non-final multipart part may be (issue #586): R2's
/// rule. Every part except the last one listed must be at least this,
/// and R2 additionally requires all non-final parts to be the same size;
/// [`ScopedBlob`] leaves that to the adapter, which alone sees the parts
/// as they are written.
pub const MIN_MULTIPART_PART_BYTES: u64 = 5 * 1024 * 1024;

/// The most objects one [`Blob::list`] call may return (issue #586):
/// R2's list cap. [`ScopedBlob`] clamps a caller's `limit` into
/// `1 ..= MAX_LIST_LIMIT` before any adapter sees it.
pub const MAX_LIST_LIMIT: usize = 1000;

/// The longest presign lifetime a store accepts: seven days, the S3 maximum.
/// [`ScopedBlob`] refuses a longer one before any adapter sees it
/// (issue #622).
pub const MAX_PRESIGN_TTL: Duration = Duration::from_hours(7 * 24);

/// The presign lifetime a caller gets when it does not choose one: one hour —
/// long enough for a browser to fetch or upload, short enough that a leaked
/// URL ages out (issue #622).
pub const DEFAULT_PRESIGN_TTL: Duration = Duration::from_hours(1);

/// Rejects a presign lifetime outside `1 s ..= MAX_PRESIGN_TTL` before any
/// store sees it (issue #622): a sub-second TTL truncates to `X-Amz-Expires=0`
/// — an already-dead URL — and [`BlobError`] is not `#[non_exhaustive]`, so
/// this reuses [`BlobError::Operation`] rather than adding a variant.
fn check_presign_ttl(ttl: Duration) -> Result<(), BlobError> {
    if ttl < Duration::from_secs(1) || ttl > MAX_PRESIGN_TTL {
        return Err(BlobError::Operation(format!(
            "presign ttl must be between 1 and {} seconds, got {}",
            MAX_PRESIGN_TTL.as_secs(),
            ttl.as_secs(),
        )));
    }
    Ok(())
}

/// Rejects a write whose payload exceeds [`MAX_BLOB_BYTES`] (issue #136).
/// Every [`Blob::put`] implementation MUST call this before touching
/// storage; [`ScopedBlob`] (the module-facing wrapper) already does, so
/// an adapter's own call is the second, defence-in-depth gate for
/// runtimes-wired stores and direct users.
///
/// # Errors
///
/// [`BlobError::TooLarge`] when `bytes.len()` exceeds the bound.
pub fn check_blob_size(bytes: &[u8]) -> Result<(), BlobError> {
    if bytes.len() > MAX_BLOB_BYTES {
        return Err(BlobError::TooLarge(format!(
            "blob of {} bytes exceeds the {MAX_BLOB_BYTES}-byte bound",
            bytes.len()
        )));
    }
    Ok(())
}

/// A stored object: its bytes and the content type to serve it with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobObject {
    pub bytes: Vec<u8>,
    pub content_type: String,
}

/// What a store knows about an object *without* reading its bytes
/// (issue #586): the metadata a [`Blob::head`] call returns, and one row
/// of a [`BlobPage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobMeta {
    /// The key, module-relative when it came through a [`ScopedBlob`].
    pub key: String,
    /// The object's size in bytes.
    pub size: u64,
    /// The content type it was stored with.
    pub content_type: String,
}

/// One page of a [`Blob::list`] (issue #586). `cursor` is `None` on the
/// last page and otherwise an opaque token to hand straight back to the
/// next `list` call — the module never parses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobPage {
    /// The objects on this page, in lexicographic key order.
    pub objects: Vec<BlobMeta>,
    /// The token for the next page, or `None` when this is the last one.
    pub cursor: Option<String>,
}

/// A streamed object body (issue #586): what [`Blob::get_stream`] returns
/// instead of buffering the bytes. `size` and `content_type` are known
/// before a single chunk is read, so a handler can set response headers
/// from them.
pub struct BlobStream {
    /// The content type the object was stored with.
    pub content_type: String,
    /// The object's size in bytes, known up front.
    pub size: u64,
    /// The body chunks. A chunk error is a mid-stream transport failure.
    pub body: BoxStream<'static, Result<Bytes, StreamError>>,
}

impl BlobStream {
    /// Turns the body into a [`ResponseStream`], so a handler on a route
    /// its module declared in
    /// [`Module::streaming_routes`](crate::Module::streaming_routes) can
    /// return an object without buffering it first (issue #586).
    #[must_use]
    pub fn into_response_stream(self) -> ResponseStream {
        ResponseStream::new(self.body)
    }
}

// Hand-written because `BoxStream` is not `Debug`; the body is named as a
// placeholder rather than dumped.
impl fmt::Debug for BlobStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlobStream")
            .field("content_type", &self.content_type)
            .field("size", &self.size)
            .field("body", &"<stream>")
            .finish()
    }
}

/// Identifies one multipart upload in flight (issue #586). Opaque: an
/// adapter mints it in [`Blob::create_multipart`] and a module only ever
/// hands it back to the other multipart methods.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UploadId(String);

impl UploadId {
    /// Wraps an adapter-minted id.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The id as a string, for an adapter that has to name it in a URL or
    /// a store request.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One part that was uploaded, as S3 and R2 report it: its number and the
/// `ETag` the store assigned (issue #586). A module collects these from
/// [`Blob::upload_part`] and passes them, in ascending part order, to
/// [`Blob::complete_multipart`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartReceipt {
    /// The part's 1-based number, `1 ..= MAX_MULTIPART_PARTS`.
    pub part_number: u16,
    /// The store's `ETag` for the part.
    pub etag: String,
}

/// A multipart upload the module started but has not completed or aborted
/// (issue #586): what [`Blob::list_multipart_uploads`] reports, so a
/// module can find and abort the ones it abandoned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingUpload {
    /// The target key, module-relative when it came through a
    /// [`ScopedBlob`].
    pub key: String,
    /// The upload's id.
    pub upload_id: UploadId,
}

/// Rejects a multipart part number outside `1 ..= MAX_MULTIPART_PARTS`
/// (issue #586) before any store sees it.
///
/// # Errors
///
/// [`BlobError::Operation`] when `n` is zero or past the last part — the
/// number is a caller mistake, not a bad key, and [`BlobError`] is not
/// `#[non_exhaustive]`, so [`BlobError::Operation`] carries it.
pub fn check_part_number(n: u16) -> Result<(), BlobError> {
    if n == 0 || n > MAX_MULTIPART_PARTS {
        return Err(BlobError::Operation(format!(
            "multipart part number must be between 1 and {MAX_MULTIPART_PARTS}, got {n}"
        )));
    }
    Ok(())
}

/// Wraps a byte-chunk stream so that the chunk which would push the total
/// past `max_bytes` is replaced by [`StreamError::TooLarge`] (it is not
/// delivered), the source is dropped, and every later poll answers `None`
/// (issue #586). The tool an adapter reaches for to implement
/// [`Blob::put_stream`] and [`Blob::upload_part`] without buffering, and
/// the same enforcement, one layer down, that [`ScopedBlob`] applies.
///
/// Written out by hand because core depends on `futures-core` only — no
/// `futures-util` `StreamExt`.
#[must_use]
pub fn limit_stream(
    body: BoxStream<'static, Result<Bytes, StreamError>>,
    max_bytes: u64,
) -> BoxStream<'static, Result<Bytes, StreamError>> {
    Box::pin(LimitStream {
        inner: Some(body),
        delivered: 0,
        max: max_bytes,
    })
}

/// Maps a mid-stream failure to a [`BlobError`] (issue #586): a ceiling
/// breach is [`BlobError::TooLarge`], a transport failure is
/// [`BlobError::Operation`] with the detail for logs.
#[must_use]
pub fn blob_error_from_stream(error: StreamError) -> BlobError {
    error.into()
}

impl From<StreamError> for BlobError {
    fn from(error: StreamError) -> Self {
        match error {
            StreamError::TooLarge => {
                Self::TooLarge("the streamed body exceeded its ceiling".to_owned())
            }
            StreamError::Transport(detail) => {
                Self::Operation(format!("blob stream transport error: {detail}"))
            }
        }
    }
}

/// The [`limit_stream`] enforcer: counts delivered bytes and refuses the
/// one chunk that crosses `max`.
struct LimitStream {
    inner: Option<BoxStream<'static, Result<Bytes, StreamError>>>,
    delivered: u64,
    max: u64,
}

impl Stream for LimitStream {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let polled = match this.inner.as_mut() {
            Some(stream) => stream.as_mut().poll_next(cx),
            None => return Poll::Ready(None),
        };
        match polled {
            Poll::Ready(Some(Ok(chunk))) => {
                if this.delivered.saturating_add(chunk.len() as u64) > this.max {
                    // Drop the source and fuse: nothing further is read.
                    this.inner = None;
                    Poll::Ready(Some(Err(StreamError::TooLarge)))
                } else {
                    this.delivered += chunk.len() as u64;
                    Poll::Ready(Some(Ok(chunk)))
                }
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => {
                this.inner = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Blob store failures.
#[derive(Debug, Clone, Error)]
pub enum BlobError {
    /// The store rejected or could not complete the operation.
    #[error("blob operation failed: {0}")]
    Operation(String),
    /// The key is empty, absolute, or tries to escape its prefix (`..`).
    #[error("invalid blob key: {0}")]
    BadKey(String),
    /// The object is bigger than [`MAX_BLOB_BYTES`] (issue #136).
    #[error("blob rejected by size: {0}")]
    TooLarge(String),
    /// The adapter does not support this operation (e.g. a directory store has
    /// no presigned URLs).
    #[error("blob operation not supported: {0}")]
    Unsupported(String),
}

/// A presigned upload: the URL to `PUT` to, the method, and the headers the
/// client must send **exactly** — the signature covers each signed header, so
/// a different value is refused by the store (issue #622).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresignedPut {
    /// The `https://…` URL, query string and all. A bearer credential until
    /// it expires: never log it.
    pub url: String,
    /// Always `"PUT"`; carried so a caller need not hard-code it.
    pub method: &'static str,
    /// Headers the client must send with exactly these values (e.g.
    /// `Content-Type`, `Content-Length`).
    pub headers: Vec<(String, String)>,
}

/// A blob store. Keys are module-prefixed; the harness wraps this in a
/// [`ScopedBlob`] per module so a module cannot name another's objects.
#[async_trait]
pub trait Blob: Send + Sync {
    /// Stores `bytes` at `key` with `content_type`, replacing any existing
    /// object. Implementations MUST reject a payload larger than
    /// [`MAX_BLOB_BYTES`] with [`BlobError::TooLarge`] via
    /// [`check_blob_size`], before writing (issue #136).
    async fn put(&self, key: &str, bytes: &[u8], content_type: &str) -> Result<(), BlobError>;
    /// Fetches the object at `key`, or `None` if there is none.
    async fn get(&self, key: &str) -> Result<Option<BlobObject>, BlobError>;
    /// Removes the object at `key`. Idempotent: removing a missing key is `Ok`.
    async fn delete(&self, key: &str) -> Result<(), BlobError>;
    /// A presigned `GET` for `key`, valid for `ttl`: a URL that serves the
    /// object directly, skipping the Worker. Adapters without presigned URLs
    /// (a directory store) return [`BlobError::Unsupported`]; callers then
    /// serve the bytes through [`get`](Blob::get). The URL's query string is
    /// a bearer credential: never log it.
    async fn signed_url(&self, key: &str, ttl: Duration) -> Result<String, BlobError>;
    /// A presigned `PUT` for `key` with `content_type`, valid for `ttl`.
    ///
    /// The signature cannot cover the body, but when `content_length` is
    /// `Some` adapters sign `Content-Length` for that value, so a store that
    /// honours it rejects any other size. The returned [`PresignedPut`] names
    /// the headers the client must send exactly. Adapters without presigned
    /// URLs return [`BlobError::Unsupported`] (the default). The URL's query
    /// string is a bearer credential: never log it.
    async fn signed_put_url(
        &self,
        key: &str,
        content_type: &str,
        content_length: Option<u64>,
        ttl: Duration,
    ) -> Result<PresignedPut, BlobError> {
        let _ = (key, content_type, content_length, ttl);
        Err(BlobError::Unsupported(
            "this blob store has no presigned uploads".to_owned(),
        ))
    }

    /// Stores a streamed body at `key` (issue #586), for an object larger
    /// than the [`MAX_BLOB_BYTES`] buffered path allows, and returns the
    /// number of bytes written. `max_bytes` is the caller's ceiling;
    /// adapters MUST enforce it (typically by wrapping `body` in
    /// [`limit_stream`]) and, once it is passed, answer
    /// [`BlobError::TooLarge`] and leave **no** object behind.
    ///
    /// The module-facing [`ScopedBlob`] lowers `max_bytes` to the
    /// module's declared ceiling before an adapter sees it. Unlike
    /// [`put`](Blob::put), which stays capped at [`MAX_BLOB_BYTES`], this
    /// path may carry an object up to
    /// [`MAX_LARGE_BLOB_BYTES`]. The default answers
    /// [`BlobError::Unsupported`], so an adapter that has not implemented
    /// streaming compiles and behaves unchanged.
    async fn put_stream(
        &self,
        key: &str,
        body: BoxStream<'static, Result<Bytes, StreamError>>,
        content_type: &str,
        max_bytes: u64,
    ) -> Result<u64, BlobError> {
        let _ = (key, body, content_type, max_bytes);
        Err(BlobError::Unsupported(
            "this blob store has no streamed puts".to_owned(),
        ))
    }

    /// Fetches the object at `key` as a stream (issue #586), or `None` if
    /// there is none. The size and content type are known before the body
    /// is read, so a handler can set headers and hand the body on without
    /// buffering it.
    ///
    /// The default answers [`BlobError::Unsupported`].
    async fn get_stream(&self, key: &str) -> Result<Option<BlobStream>, BlobError> {
        let _ = key;
        Err(BlobError::Unsupported(
            "this blob store has no streamed gets".to_owned(),
        ))
    }

    /// Reports the object's metadata without reading its bytes (issue
    /// #586), or `None` if there is none.
    ///
    /// The default answers [`BlobError::Unsupported`].
    async fn head(&self, key: &str) -> Result<Option<BlobMeta>, BlobError> {
        let _ = key;
        Err(BlobError::Unsupported(
            "this blob store has no head".to_owned(),
        ))
    }

    /// Lists stored objects whose key starts with `prefix` (issue #586),
    /// newest page at a time. Keys are returned in lexicographic order;
    /// `cursor` is the opaque token from the previous [`BlobPage`], or
    /// `None` to start at the beginning. Adapters cap `limit` at
    /// [`MAX_LIST_LIMIT`].
    ///
    /// The default answers [`BlobError::Unsupported`].
    async fn list(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<BlobPage, BlobError> {
        let _ = (prefix, cursor, limit);
        Err(BlobError::Unsupported(
            "this blob store has no listings".to_owned(),
        ))
    }

    /// Starts a multipart upload for `key` with `content_type` (issue
    /// #586) and returns its id. Parts are then written with
    /// [`upload_part`](Blob::upload_part) and the object is made visible
    /// by [`complete_multipart`](Blob::complete_multipart); an upload the
    /// module abandons must be [`abort_multipart`](Blob::abort_multipart)ed,
    /// or reclaimed by an R2 lifecycle rule, or its parts linger.
    ///
    /// The default answers [`BlobError::Unsupported`].
    async fn create_multipart(&self, key: &str, content_type: &str) -> Result<UploadId, BlobError> {
        let _ = (key, content_type);
        Err(BlobError::Unsupported(
            "this blob store has no multipart uploads".to_owned(),
        ))
    }

    /// Uploads one part of a multipart upload (issue #586),
    /// `1 ..= MAX_MULTIPART_PARTS`, and returns its [`PartReceipt`].
    /// `max_part_bytes` is the caller's ceiling, enforced like
    /// [`put_stream`](Blob::put_stream)'s. Every part but the last listed
    /// in [`complete_multipart`](Blob::complete_multipart) must be at
    /// least [`MIN_MULTIPART_PART_BYTES`]; adapters may enforce it at
    /// complete, when the last part is known.
    ///
    /// The default answers [`BlobError::Unsupported`].
    async fn upload_part(
        &self,
        key: &str,
        upload_id: &UploadId,
        part_number: u16,
        body: BoxStream<'static, Result<Bytes, StreamError>>,
        max_part_bytes: u64,
    ) -> Result<PartReceipt, BlobError> {
        let _ = (key, upload_id, part_number, body, max_part_bytes);
        Err(BlobError::Unsupported(
            "this blob store has no multipart uploads".to_owned(),
        ))
    }

    /// Assembles the parts listed in `parts` (in ascending part order)
    /// into the object at `key` and ends the upload (issue #586). A part
    /// whose `ETag` does not match what was uploaded is refused; an
    /// unknown upload id is [`BlobError::Operation`].
    ///
    /// The default answers [`BlobError::Unsupported`].
    async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &UploadId,
        parts: &[PartReceipt],
    ) -> Result<(), BlobError> {
        let _ = (key, upload_id, parts);
        Err(BlobError::Unsupported(
            "this blob store has no multipart uploads".to_owned(),
        ))
    }

    /// Abandons a multipart upload (issue #586), discarding its parts. An
    /// unknown upload id is [`BlobError::Operation`].
    ///
    /// The default answers [`BlobError::Unsupported`].
    async fn abort_multipart(&self, key: &str, upload_id: &UploadId) -> Result<(), BlobError> {
        let _ = (key, upload_id);
        Err(BlobError::Unsupported(
            "this blob store has no multipart uploads".to_owned(),
        ))
    }

    /// Lists the module's multipart uploads in flight whose key starts
    /// with `prefix` (issue #586), so it can abort the ones it abandoned.
    ///
    /// The default answers [`BlobError::Unsupported`].
    async fn list_multipart_uploads(&self, prefix: &str) -> Result<Vec<PendingUpload>, BlobError> {
        let _ = prefix;
        Err(BlobError::Unsupported(
            "this blob store has no multipart uploads".to_owned(),
        ))
    }
}

/// Wraps a [`Blob`] so every key is prefixed with `<module>/` and no key can
/// escape it. The harness applies this in `Ports::view_for`, so a module sees a
/// store scoped to itself — the blob equivalent of the table-ownership check.
pub struct ScopedBlob {
    inner: Arc<dyn Blob>,
    prefix: String,
    /// The ceiling this view enforces on the streamed and multipart write
    /// paths (issue #586), lower than the store's own. Defaults to the
    /// buffered [`MAX_BLOB_BYTES`], so a view that says nothing changes
    /// nothing.
    max_object_bytes: u64,
}

impl ScopedBlob {
    /// Scopes `inner` to `<module>/`.
    #[must_use]
    pub fn new(inner: Arc<dyn Blob>, module: &str) -> Self {
        Self {
            inner,
            prefix: format!("{module}/"),
            max_object_bytes: MAX_BLOB_BYTES as u64,
        }
    }

    /// Sets the per-object ceiling this view enforces on
    /// [`Blob::put_stream`], [`Blob::upload_part`] and
    /// [`Blob::complete_multipart`] (issue #586). Clamped to
    /// [`MAX_LARGE_BLOB_BYTES`], so no module can declare its way past
    /// what the store itself accepts. The harness sets it from
    /// [`Module::max_blob_object_bytes`](crate::Module::max_blob_object_bytes)
    /// in `Ports::view_for`.
    #[must_use]
    pub fn with_max_object_bytes(mut self, max: u64) -> Self {
        self.max_object_bytes = max.min(MAX_LARGE_BLOB_BYTES);
        self
    }

    /// Prefixes a caller key, refusing one that is empty, absolute, or walks
    /// out of the prefix with `..`.
    fn scope(&self, key: &str) -> Result<String, BlobError> {
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
        Ok(format!("{}{key}", self.prefix))
    }

    /// Prefixes a caller-supplied *listing* prefix. Like [`Self::scope`],
    /// but an empty prefix is allowed and means "every key this module
    /// owns" — a listing names a namespace, not one key (issue #586).
    fn scope_prefix(&self, prefix: &str) -> Result<String, BlobError> {
        if prefix.is_empty() {
            return Ok(self.prefix.clone());
        }
        if prefix.starts_with('/') {
            return Err(BlobError::BadKey(format!(
                "prefix `{prefix}` must be relative"
            )));
        }
        if prefix
            .split('/')
            .any(|segment| segment == ".." || segment == ".")
        {
            return Err(BlobError::BadKey(format!(
                "prefix `{prefix}` must not contain `.` or `..` segments"
            )));
        }
        Ok(format!("{}{prefix}", self.prefix))
    }

    /// Strips this view's module prefix from a key the store returned, or
    /// `None` when the key is not under it — the defence-in-depth filter
    /// that keeps a listing or a `head` from ever surfacing another
    /// module's object (issue #586).
    fn unscope(&self, key: &str) -> Option<String> {
        key.strip_prefix(&self.prefix).map(str::to_owned)
    }
}

#[async_trait]
impl Blob for ScopedBlob {
    async fn put(&self, key: &str, bytes: &[u8], content_type: &str) -> Result<(), BlobError> {
        check_blob_size(bytes)?;
        self.inner.put(&self.scope(key)?, bytes, content_type).await
    }
    async fn get(&self, key: &str) -> Result<Option<BlobObject>, BlobError> {
        self.inner.get(&self.scope(key)?).await
    }
    async fn delete(&self, key: &str) -> Result<(), BlobError> {
        self.inner.delete(&self.scope(key)?).await
    }
    async fn signed_url(&self, key: &str, ttl: Duration) -> Result<String, BlobError> {
        let key = self.scope(key)?;
        check_presign_ttl(ttl)?;
        self.inner.signed_url(&key, ttl).await
    }
    async fn signed_put_url(
        &self,
        key: &str,
        content_type: &str,
        content_length: Option<u64>,
        ttl: Duration,
    ) -> Result<PresignedPut, BlobError> {
        let key = self.scope(key)?;
        check_presign_ttl(ttl)?;
        self.inner
            .signed_put_url(&key, content_type, content_length, ttl)
            .await
    }
    async fn put_stream(
        &self,
        key: &str,
        body: BoxStream<'static, Result<Bytes, StreamError>>,
        content_type: &str,
        max_bytes: u64,
    ) -> Result<u64, BlobError> {
        let key = self.scope(key)?;
        let effective = max_bytes.min(self.max_object_bytes);
        self.inner
            .put_stream(&key, body, content_type, effective)
            .await
    }
    async fn get_stream(&self, key: &str) -> Result<Option<BlobStream>, BlobError> {
        let key = self.scope(key)?;
        self.inner.get_stream(&key).await
    }
    async fn head(&self, key: &str) -> Result<Option<BlobMeta>, BlobError> {
        let scoped = self.scope(key)?;
        Ok(self.inner.head(&scoped).await?.map(|mut meta| {
            // We scoped the key ourselves, so report the caller's original
            // key rather than trying to unscope whatever the store echoed
            // back (which need not carry our prefix).
            key.clone_into(&mut meta.key);
            meta
        }))
    }
    async fn list(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<BlobPage, BlobError> {
        let scoped = self.scope_prefix(prefix)?;
        let limit = limit.clamp(1, MAX_LIST_LIMIT);
        let page = self.inner.list(&scoped, cursor, limit).await?;
        let objects = page
            .objects
            .into_iter()
            .filter_map(|mut meta| {
                meta.key = self.unscope(&meta.key)?;
                Some(meta)
            })
            .collect();
        Ok(BlobPage {
            objects,
            cursor: page.cursor,
        })
    }
    async fn create_multipart(&self, key: &str, content_type: &str) -> Result<UploadId, BlobError> {
        let key = self.scope(key)?;
        self.inner.create_multipart(&key, content_type).await
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
        let key = self.scope(key)?;
        let effective = max_part_bytes.min(self.max_object_bytes);
        self.inner
            .upload_part(&key, upload_id, part_number, body, effective)
            .await
    }
    async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &UploadId,
        parts: &[PartReceipt],
    ) -> Result<(), BlobError> {
        if parts.is_empty() {
            return Err(BlobError::Operation(
                "a multipart upload needs at least one part".to_owned(),
            ));
        }
        if parts.len() > usize::from(MAX_MULTIPART_PARTS) {
            return Err(BlobError::Operation(format!(
                "a multipart upload takes at most {MAX_MULTIPART_PARTS} parts"
            )));
        }
        let key = self.scope(key)?;
        self.inner
            .complete_multipart(&key, upload_id, parts)
            .await?;
        // The adapter assembled the object; the ceiling is enforced here,
        // on the finished size, because no single part knows it.
        match self.inner.head(&key).await? {
            Some(meta) if meta.size > self.max_object_bytes => {
                self.inner.delete(&key).await?;
                Err(BlobError::TooLarge(format!(
                    "completed object of {} bytes exceeds the {}-byte bound",
                    meta.size, self.max_object_bytes
                )))
            }
            Some(_) => Ok(()),
            // The adapter reported the completion succeeded but the object
            // is not there: fail closed rather than trust an absent size.
            None => Err(BlobError::Operation(
                "completed object not found".to_owned(),
            )),
        }
    }
    async fn abort_multipart(&self, key: &str, upload_id: &UploadId) -> Result<(), BlobError> {
        let key = self.scope(key)?;
        self.inner.abort_multipart(&key, upload_id).await
    }
    async fn list_multipart_uploads(&self, prefix: &str) -> Result<Vec<PendingUpload>, BlobError> {
        let scoped = self.scope_prefix(prefix)?;
        let uploads = self.inner.list_multipart_uploads(&scoped).await?;
        Ok(uploads
            .into_iter()
            .filter_map(|mut upload| {
                upload.key = self.unscope(&upload.key)?;
                Some(upload)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    // A recording test fixture, not request state (ADR 0007). The scoped
    // allow follows the policy in the workspace clippy.toml, as the fakes
    // in `cratefield-testing` and the sibling tests in this crate do.
    #![allow(clippy::disallowed_types)]

    use super::*;
    use std::sync::Mutex;

    /// An in-memory blob store for testing the scoping.
    #[derive(Default)]
    struct MemBlob {
        objects: Mutex<std::collections::HashMap<String, BlobObject>>,
        /// The keys the presign methods were reached with, so a test can prove
        /// a refused call never arrived.
        presigned: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl Blob for MemBlob {
        async fn put(&self, key: &str, bytes: &[u8], content_type: &str) -> Result<(), BlobError> {
            self.objects.lock().unwrap().insert(
                key.to_owned(),
                BlobObject {
                    bytes: bytes.to_vec(),
                    content_type: content_type.to_owned(),
                },
            );
            Ok(())
        }
        async fn get(&self, key: &str) -> Result<Option<BlobObject>, BlobError> {
            Ok(self.objects.lock().unwrap().get(key).cloned())
        }
        async fn delete(&self, key: &str) -> Result<(), BlobError> {
            self.objects.lock().unwrap().remove(key);
            Ok(())
        }
        async fn signed_url(&self, key: &str, _ttl: Duration) -> Result<String, BlobError> {
            self.presigned.lock().unwrap().push(key.to_owned());
            Ok(format!("mem://{key}"))
        }
        async fn signed_put_url(
            &self,
            key: &str,
            content_type: &str,
            _content_length: Option<u64>,
            _ttl: Duration,
        ) -> Result<PresignedPut, BlobError> {
            self.presigned.lock().unwrap().push(key.to_owned());
            Ok(PresignedPut {
                url: format!("mem://{key}"),
                method: "PUT",
                headers: vec![("content-type".to_owned(), content_type.to_owned())],
            })
        }
        async fn put_stream(
            &self,
            key: &str,
            body: BoxStream<'static, Result<Bytes, StreamError>>,
            content_type: &str,
            max_bytes: u64,
        ) -> Result<u64, BlobError> {
            let mut limited = limit_stream(body, max_bytes);
            let mut bytes = Vec::new();
            while let Some(chunk) = std::future::poll_fn(|cx| limited.as_mut().poll_next(cx)).await
            {
                bytes.extend_from_slice(&chunk.map_err(blob_error_from_stream)?);
            }
            let written = bytes.len() as u64;
            self.objects.lock().unwrap().insert(
                key.to_owned(),
                BlobObject {
                    bytes,
                    content_type: content_type.to_owned(),
                },
            );
            Ok(written)
        }
        async fn head(&self, key: &str) -> Result<Option<BlobMeta>, BlobError> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .get(key)
                .map(|object| BlobMeta {
                    key: key.to_owned(),
                    size: object.bytes.len() as u64,
                    content_type: object.content_type.clone(),
                }))
        }
        async fn list(
            &self,
            prefix: &str,
            cursor: Option<&str>,
            limit: usize,
        ) -> Result<BlobPage, BlobError> {
            let objects = self.objects.lock().unwrap();
            let mut keys: Vec<String> = objects
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect();
            keys.sort();
            let start = cursor.map_or(0, |cursor| {
                keys.partition_point(|key| key.as_str() <= cursor)
            });
            let take = (keys.len() - start).min(limit);
            let selected = &keys[start..start + take];
            let objects = selected
                .iter()
                .map(|key| {
                    let object = &objects[key];
                    BlobMeta {
                        key: key.clone(),
                        size: object.bytes.len() as u64,
                        content_type: object.content_type.clone(),
                    }
                })
                .collect();
            let cursor = if start + take < keys.len() {
                selected.last().cloned()
            } else {
                None
            };
            Ok(BlobPage { objects, cursor })
        }
    }

    /// A `Stream` over pre-built chunks, for the `limit_stream` and
    /// streamed-write tests. Written out because core has no `futures-util`.
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

    /// Implements only the required [`Blob`] methods, so the provided
    /// [`Blob::signed_put_url`] default is what a test exercises.
    struct BareBlob;

    #[async_trait]
    impl Blob for BareBlob {
        async fn put(
            &self,
            _key: &str,
            _bytes: &[u8],
            _content_type: &str,
        ) -> Result<(), BlobError> {
            Ok(())
        }
        async fn get(&self, _key: &str) -> Result<Option<BlobObject>, BlobError> {
            Ok(None)
        }
        async fn delete(&self, _key: &str) -> Result<(), BlobError> {
            Ok(())
        }
        async fn signed_url(&self, _key: &str, _ttl: Duration) -> Result<String, BlobError> {
            Err(BlobError::Unsupported("memory store".to_owned()))
        }
    }

    #[pollster::test]
    async fn a_scoped_blob_prefixes_the_key() {
        let mem = Arc::new(MemBlob::default());
        let scoped = ScopedBlob::new(mem.clone(), "waitlist");
        scoped.put("clip.mp3", b"x", "audio/mpeg").await.unwrap();
        // The underlying store sees the prefixed key.
        assert!(mem.get("waitlist/clip.mp3").await.unwrap().is_some());
        assert!(mem.get("clip.mp3").await.unwrap().is_none());
        // And the scoped view reads it back by the bare key.
        assert!(scoped.get("clip.mp3").await.unwrap().is_some());
    }

    #[pollster::test]
    async fn a_scoped_blob_refuses_an_escaping_key() {
        let scoped = ScopedBlob::new(Arc::new(MemBlob::default()), "cms");
        for bad in ["", "/etc/passwd", "../secrets/x", "a/../../b", "."] {
            assert!(
                matches!(scoped.get(bad).await.unwrap_err(), BlobError::BadKey(_)),
                "key `{bad}` should be refused"
            );
        }
    }

    #[pollster::test]
    async fn delete_is_idempotent() {
        let scoped = ScopedBlob::new(Arc::new(MemBlob::default()), "cms");
        scoped.delete("missing").await.expect("no-op delete is ok");
    }

    #[pollster::test]
    async fn an_oversized_put_is_refused_before_the_store_is_reached() {
        let mem = Arc::new(MemBlob::default());
        let scoped = ScopedBlob::new(mem.clone(), "cms");
        let oversized = vec![0_u8; MAX_BLOB_BYTES + 1];
        let err = scoped
            .put("big.bin", &oversized, "application/octet-stream")
            .await
            .expect_err("one byte past the bound must be refused");
        assert!(matches!(err, BlobError::TooLarge(_)), "got {err}");
        assert!(
            mem.get("cms/big.bin").await.unwrap().is_none(),
            "the store never saw the rejected key"
        );
    }

    #[pollster::test]
    async fn a_put_at_exactly_the_bound_is_accepted() {
        let scoped = ScopedBlob::new(Arc::new(MemBlob::default()), "cms");
        let exact = vec![0_u8; MAX_BLOB_BYTES];
        scoped
            .put("edge.bin", &exact, "application/octet-stream")
            .await
            .expect("the bound itself is allowed");
    }

    #[pollster::test]
    async fn a_scoped_blob_prefixes_both_presign_keys() {
        let mem = Arc::new(MemBlob::default());
        let scoped = ScopedBlob::new(mem.clone(), "cms");
        let get = scoped
            .signed_url("clip.mp3", Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(get, "mem://cms/clip.mp3");
        let put = scoped
            .signed_put_url("clip.mp3", "audio/mpeg", Some(3), Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(put.url, "mem://cms/clip.mp3");
        assert_eq!(
            *mem.presigned.lock().unwrap(),
            vec!["cms/clip.mp3".to_owned(), "cms/clip.mp3".to_owned()],
        );
    }

    #[pollster::test]
    async fn a_scoped_blob_refuses_an_escaping_presign_key_before_the_store() {
        let mem = Arc::new(MemBlob::default());
        let scoped = ScopedBlob::new(mem.clone(), "cms");
        for bad in ["", "/etc/passwd", "../secrets/x"] {
            assert!(
                matches!(
                    scoped
                        .signed_url(bad, Duration::from_secs(60))
                        .await
                        .unwrap_err(),
                    BlobError::BadKey(_)
                ),
                "key `{bad}` should be refused"
            );
            assert!(
                matches!(
                    scoped
                        .signed_put_url(bad, "image/png", None, Duration::from_secs(60))
                        .await
                        .unwrap_err(),
                    BlobError::BadKey(_)
                ),
                "key `{bad}` should be refused"
            );
        }
        assert!(
            mem.presigned.lock().unwrap().is_empty(),
            "the store never saw a key"
        );
    }

    #[pollster::test]
    async fn a_scoped_blob_refuses_a_presign_ttl_outside_the_bound() {
        let mem = Arc::new(MemBlob::default());
        let scoped = ScopedBlob::new(mem.clone(), "cms");
        for bad in [
            // A sub-second TTL truncates to `X-Amz-Expires=0`, so it is
            // refused alongside zero and over-long ones.
            Duration::from_millis(500),
            Duration::ZERO,
            MAX_PRESIGN_TTL + Duration::from_secs(1),
        ] {
            assert!(
                matches!(
                    scoped.signed_url("clip.mp3", bad).await.unwrap_err(),
                    BlobError::Operation(_)
                ),
                "ttl {bad:?} should be refused"
            );
        }
        // The bound itself is allowed, and the store is reached.
        scoped
            .signed_url("clip.mp3", MAX_PRESIGN_TTL)
            .await
            .unwrap();
        assert_eq!(mem.presigned.lock().unwrap().len(), 1);
    }

    #[pollster::test]
    async fn the_default_signed_put_url_is_unsupported() {
        let scoped = ScopedBlob::new(Arc::new(BareBlob), "cms");
        assert!(matches!(
            scoped
                .signed_put_url("clip.mp3", "audio/mpeg", None, Duration::from_secs(60))
                .await
                .unwrap_err(),
            BlobError::Unsupported(_)
        ));
    }

    #[test]
    fn the_ceiling_defaults_to_the_small_bound_and_clamps_to_the_large_one() {
        let default = ScopedBlob::new(Arc::new(BareBlob), "cms");
        assert_eq!(
            default.max_object_bytes, MAX_BLOB_BYTES as u64,
            "a view that says nothing keeps the buffered bound"
        );
        let raised = ScopedBlob::new(Arc::new(BareBlob), "cms").with_max_object_bytes(u64::MAX);
        assert_eq!(
            raised.max_object_bytes, MAX_LARGE_BLOB_BYTES,
            "a declaration cannot outrun the harness-wide ceiling"
        );
        let lowered = ScopedBlob::new(Arc::new(BareBlob), "cms").with_max_object_bytes(4096);
        assert_eq!(lowered.max_object_bytes, 4096, "lowering is honoured");
    }

    #[test]
    fn check_part_number_bounds_the_one_based_range() {
        assert!(check_part_number(1).is_ok());
        assert!(check_part_number(MAX_MULTIPART_PARTS).is_ok());
        assert!(matches!(
            check_part_number(0).unwrap_err(),
            BlobError::Operation(_)
        ));
        assert!(matches!(
            check_part_number(MAX_MULTIPART_PARTS + 1).unwrap_err(),
            BlobError::Operation(_)
        ));
    }

    #[pollster::test]
    async fn limit_stream_refuses_the_crossing_chunk_and_fuses() {
        let mut stream = limit_stream(
            chunk_stream(vec![b"12345".to_vec(), b"67890".to_vec(), b"x".to_vec()]),
            8,
        );
        let first = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await;
        assert_eq!(first.unwrap().unwrap(), Bytes::from_static(b"12345"));
        // 5 + 5 crosses 8: refused, not delivered.
        let second = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await;
        assert!(matches!(second.unwrap(), Err(StreamError::TooLarge)));
        let third = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await;
        assert!(third.is_none(), "fused after the refusal");
    }

    #[pollster::test]
    async fn list_strips_the_prefix_and_hides_other_modules() {
        let mem = Arc::new(MemBlob::default());
        mem.put("cms/a.txt", b"a", "text/plain").await.unwrap();
        mem.put("cms/b.txt", b"b", "text/plain").await.unwrap();
        mem.put("cms2/c.txt", b"c", "text/plain").await.unwrap();
        let scoped = ScopedBlob::new(mem, "cms");

        let page = scoped.list("", None, 10).await.unwrap();
        let keys: Vec<&str> = page.objects.iter().map(|meta| meta.key.as_str()).collect();
        assert_eq!(keys, ["a.txt", "b.txt"], "stripped, ordered, scoped");
        assert!(page.cursor.is_none());

        let narrowed = scoped.list("a", None, 10).await.unwrap();
        assert_eq!(narrowed.objects.len(), 1, "the prefix narrows the listing");
        assert_eq!(narrowed.objects[0].key, "a.txt");

        assert!(matches!(
            scoped.list("/abs", None, 10).await.unwrap_err(),
            BlobError::BadKey(_)
        ));
        assert!(matches!(
            scoped.list("../x", None, 10).await.unwrap_err(),
            BlobError::BadKey(_)
        ));
    }

    #[pollster::test]
    async fn put_stream_uses_the_smaller_of_the_call_and_the_ceiling() {
        let mem = Arc::new(MemBlob::default());
        let scoped = ScopedBlob::new(mem.clone(), "cms").with_max_object_bytes(8);
        let err = scoped
            .put_stream(
                "clip.bin",
                chunk_stream(vec![vec![0_u8; 10]]),
                "application/octet-stream",
                1 << 30,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, BlobError::TooLarge(_)), "got {err:?}");
        assert!(
            mem.get("cms/clip.bin").await.unwrap().is_none(),
            "the ceiling left no object behind"
        );

        let written = scoped
            .put_stream(
                "clip.bin",
                chunk_stream(vec![vec![1_u8; 8]]),
                "application/octet-stream",
                1 << 30,
            )
            .await
            .unwrap();
        assert_eq!(written, 8, "the effective ceiling is the view's own");
        assert!(mem.get("cms/clip.bin").await.unwrap().is_some());
    }
}
