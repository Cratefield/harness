//! [`Blob`] over a Cloudflare R2 bucket (issue #105). Small media on Workers:
//! a coach's voice clip, served to members.
//!
//! [`Blob::put`], [`get`](Blob::get) and [`delete`](Blob::delete) go through
//! the Worker binding; the two presign methods go through R2's S3-compatible
//! API instead (issue #622) — a different endpoint with its own credentials.
//! They work only when the venture called
//! [`Cloudflare::blob_presign`](crate::Cloudflare::blob_presign) **and** the
//! four named values are present and non-empty in the Worker `Env` at request
//! time; otherwise both answer [`BlobError::Unsupported`] and the bytes are
//! served through [`Blob::get`].
//!
//! Presigning is pure — no binding, no network. A presigned `PUT` cannot cap
//! the size (the signature covers headers, not the body) but can pin an exact
//! `Content-Length`. Never log a presigned URL: its query string is a bearer
//! credential until it expires.
//!
//! **Verification.** Like every Workers adapter this is build-checked here and
//! must be exercised in `wrangler dev` against a real bucket before it is
//! trusted (issue #105 acceptance) — cargo tests never touch R2.

use async_trait::async_trait;
use bytes::Bytes;
use cratefield_core::sigv4::{self, Credentials, SignableRequest};
use cratefield_core::{
    Blob, BlobError, BlobMeta, BlobObject, BlobPage, BlobStream, BoxStream, Clock, MAX_LIST_LIMIT,
    MAX_MULTIPART_PARTS, PartReceipt, PendingUpload, PresignedPut, StreamError, UploadId,
    check_blob_size, check_part_number, limit_stream,
};
use futures_core::Stream;
use futures_util::StreamExt;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use worker::send::{IntoSendFuture, SendWrapper};
use worker::{Bucket, Data, HttpMetadata, Include};

/// R2's S3-compatible API signs for the `auto` region and the `s3` service.
const R2_REGION: &str = "auto";
const R2_SERVICE: &str = "s3";

fn op_err(err: &worker::Error) -> BlobError {
    BlobError::Operation(err.to_string())
}

/// The refusal both presign methods answer when presigning is off:
/// `.blob_presign` was never called, or a value it named is missing or empty.
fn unsupported_presign() -> BlobError {
    BlobError::Unsupported(
        "R2 presigning needs the S3-compatible API and its access keys; configure \
         Cloudflare::blob_presign(account_id, access_key_id, secret_access_key, bucket), \
         or serve the bytes through the harness"
            .to_owned(),
    )
}

/// The presigning seam, or the shared refusal when it is absent. Free so the
/// `Unsupported` path is testable without a `worker::Bucket`.
fn presigner(presigner: Option<&R2Presigner>) -> Result<&R2Presigner, BlobError> {
    presigner.ok_or_else(unsupported_presign)
}

/// The signing seam (issue #622): everything a presigned URL needs except the
/// Worker binding, so it is unit-testable natively (`worker::Bucket` cannot be
/// built off-wasm). Its [`fmt::Debug`] prints the account, bucket and access
/// key id — never the secret.
pub(crate) struct R2Presigner {
    account_id: String,
    bucket: String,
    credentials: Credentials,
    clock: Arc<dyn Clock>,
}

impl R2Presigner {
    pub(crate) fn new(
        account_id: impl Into<String>,
        bucket: impl Into<String>,
        credentials: Credentials,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            account_id: account_id.into(),
            bucket: bucket.into(),
            credentials,
            clock,
        }
    }

    /// Presigns `method` on `key` for `ttl`, signing `headers` exactly as
    /// given: host `<account>.r2.cloudflarestorage.com`, path
    /// `/<bucket>/<encoded key>`. Pure; time comes from the [`Clock`] port.
    fn sign(&self, method: &str, key: &str, headers: &[(String, String)], ttl: Duration) -> String {
        let host = format!("{}.r2.cloudflarestorage.com", self.account_id);
        let path = format!("/{}{}", self.bucket, sigv4::s3_key_path(key));
        sigv4::presign(
            &self.credentials,
            R2_REGION,
            R2_SERVICE,
            &SignableRequest {
                method,
                host: &host,
                path: &path,
                query: &[],
                headers,
            },
            ttl.as_secs().max(1),
            self.clock.now(),
        )
    }

    /// A presigned `GET` for `key`.
    fn signed_url(&self, key: &str, ttl: Duration) -> String {
        self.sign("GET", key, &[], ttl)
    }

    /// A presigned `PUT` for `key`. Signs `content-type`, and `content-length`
    /// too when given, and returns both for the client to send back exactly.
    fn signed_put_url(
        &self,
        key: &str,
        content_type: &str,
        content_length: Option<u64>,
        ttl: Duration,
    ) -> PresignedPut {
        let mut headers = vec![("content-type".to_owned(), content_type.to_owned())];
        if let Some(length) = content_length {
            headers.push(("content-length".to_owned(), length.to_string()));
        }
        PresignedPut {
            url: self.sign("PUT", key, &headers, ttl),
            method: "PUT",
            headers,
        }
    }
}

impl fmt::Debug for R2Presigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Credentials`' own `Debug` prints the access key id and redacts the
        // secret, so this can safely include it.
        f.debug_struct("R2Presigner")
            .field("account_id", &self.account_id)
            .field("bucket", &self.bucket)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

/// A [`Blob`] store over an R2 bucket binding, plus the presigning seam when
/// the venture configured one: `None` leaves both presign methods
/// [`BlobError::Unsupported`] and touches no network.
pub(crate) struct R2Blob {
    bucket: Bucket,
    presigner: Option<R2Presigner>,
}

impl R2Blob {
    pub(crate) fn new(bucket: Bucket, presigner: Option<R2Presigner>) -> Self {
        Self { bucket, presigner }
    }

    /// A plain R2 `put` of an in-hand buffer, with no [`check_blob_size`]:
    /// the streamed path ([`Blob::put_stream`]) is bounded by its caller's
    /// ceiling, not the buffered [`MAX_BLOB_BYTES`] one (issue #586).
    async fn put_bytes(
        &self,
        key: &str,
        bytes: &[u8],
        content_type: &str,
    ) -> Result<(), BlobError> {
        self.bucket
            .put(key, bytes.to_vec())
            .http_metadata(HttpMetadata {
                content_type: Some(content_type.to_owned()),
                ..Default::default()
            })
            .execute()
            .into_send()
            .await
            .map(|_| ())
            .map_err(|err| op_err(&err))
    }

    /// Creates a multipart upload for `key`, `content_type` stamped as the
    /// object's HTTP metadata (issue #586).
    async fn create_upload(
        &self,
        key: &str,
        content_type: &str,
    ) -> Result<worker::MultipartUpload, BlobError> {
        self.bucket
            .create_multipart_upload(key)
            .http_metadata(HttpMetadata {
                content_type: Some(content_type.to_owned()),
                ..Default::default()
            })
            .execute()
            .into_send()
            .await
            .map_err(|err| op_err(&err))
    }

    /// Buffers `body` through [`limit_stream`] into Worker memory, refusing
    /// the chunk that would cross `max_part_bytes` with
    /// [`BlobError::TooLarge`] (issue #586). R2 rejects a part whose length
    /// it does not know up front, so a part must be held whole before it is
    /// uploaded; the ceiling is what keeps that from being unbounded.
    async fn read_part(
        &self,
        body: BoxStream<'static, Result<Bytes, StreamError>>,
        max_part_bytes: u64,
    ) -> Result<Vec<u8>, BlobError> {
        let mut limited = limit_stream(body, max_part_bytes);
        let mut buffered = Vec::new();
        while let Some(chunk) = limited.next().await {
            buffered.extend_from_slice(&chunk.map_err(BlobError::from)?);
        }
        Ok(buffered)
    }

    /// Uploads one already-buffered part, appending its receipt and
    /// advancing the part number. A number past [`MAX_MULTIPART_PARTS`] is
    /// the wrong shape (a size the store would refuse anyway), refused with
    /// [`BlobError::TooLarge`] by the caller's convention.
    async fn upload_one_part(
        &self,
        upload: &worker::MultipartUpload,
        parts: &mut Vec<worker::UploadedPart>,
        part_number: &mut u16,
        part: Vec<u8>,
    ) -> Result<(), BlobError> {
        if u64::from(*part_number) > u64::from(MAX_MULTIPART_PARTS) {
            return Err(BlobError::TooLarge(format!(
                "streamed object needs more than {MAX_MULTIPART_PARTS} parts"
            )));
        }
        let uploaded = upload
            .upload_part(*part_number, Data::Bytes(part))
            .into_send()
            .await
            .map_err(|err| op_err(&err))?;
        parts.push(uploaded);
        *part_number = part_number.saturating_add(1);
        Ok(())
    }

    /// The multipart half of [`Blob::put_stream`]: `buffered` already holds
    /// at least [`PUT_STREAM_PART_BYTES`] and `limited` the unread tail.
    /// Flushes equal [`PUT_STREAM_PART_BYTES`] parts and a final remainder,
    /// aborting the upload on any failure so nothing lingers (issue #586).
    async fn put_stream_multipart(
        &self,
        key: &str,
        content_type: &str,
        mut limited: BoxStream<'static, Result<Bytes, StreamError>>,
        mut buffered: Vec<u8>,
    ) -> Result<u64, BlobError> {
        let upload = self.create_upload(key, content_type).await?;
        let mut parts: Vec<worker::UploadedPart> = Vec::new();
        let mut part_number: u16 = 1;
        let mut written: u64 = 0;
        loop {
            while buffered.len() >= PUT_STREAM_PART_BYTES {
                let part: Vec<u8> = buffered.drain(..PUT_STREAM_PART_BYTES).collect();
                written += part.len() as u64;
                if let Err(err) = self
                    .upload_one_part(&upload, &mut parts, &mut part_number, part)
                    .await
                {
                    let _ = upload.abort().into_send().await;
                    return Err(err);
                }
            }
            match limited.next().await {
                Some(Ok(chunk)) => buffered.extend_from_slice(&chunk),
                Some(Err(err)) => {
                    let _ = upload.abort().into_send().await;
                    return Err(BlobError::from(err));
                }
                None => break,
            }
        }
        if !buffered.is_empty() {
            let part = std::mem::take(&mut buffered);
            written += part.len() as u64;
            if let Err(err) = self
                .upload_one_part(&upload, &mut parts, &mut part_number, part)
                .await
            {
                let _ = upload.abort().into_send().await;
                return Err(err);
            }
        }
        let upload_id = upload.upload_id().into_send().await;
        if let Err(err) = upload.complete(parts).into_send().await {
            // `complete` consumed the upload, so resume it by id to abort
            // and leave nothing pending. The abort's own error is ignored —
            // the completion error is the one the caller needs.
            if let Ok(resumed) = self.bucket.resume_multipart_upload(key, upload_id.as_str()) {
                let _ = resumed.abort().into_send().await;
            }
            return Err(op_err(&err));
        }
        Ok(written)
    }
}

/// The content type an object with none reports. R2 lets an object carry no
/// HTTP metadata; the port's [`BlobMeta`] and [`BlobStream`] always name one.
fn content_type_or_default(metadata: &HttpMetadata) -> String {
    metadata
        .content_type
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_owned())
}

/// The fixed size [`Blob::put_stream`] buffers and uploads per multipart
/// part (issue #586): 8 MiB, comfortably above
/// [`MIN_MULTIPART_PART_BYTES`](cratefield_core::MIN_MULTIPART_PART_BYTES)
/// so every non-final part is valid, and far enough below the isolate's
/// memory that a part plus its copy is never a large fraction of the budget.
const PUT_STREAM_PART_BYTES: usize = 8 * 1024 * 1024;

/// A worker object body stream is `!Send` — its `JsFuture` holds an `Rc` —
/// but a Workers isolate is single-threaded (ADR 0002), which is exactly
/// what `worker::send::SendWrapper` is for: the `worker` crate's own safe
/// (mis)claim that a JS-backed type may cross a `Send` bound. Coercing the
/// stream to a boxed trait object and wrapping that costs no `unsafe` of
/// our own — this crate still `forbid`s it — and gives [`BlobStream`]'s
/// `Send` body stream something to hold.
/// The boxed worker body stream [`SendBlobStream`] wraps.
type BoxedWorkerStream = Pin<Box<dyn Stream<Item = Result<Vec<u8>, worker::Error>>>>;

struct SendBlobStream(SendWrapper<BoxedWorkerStream>);

impl Stream for SendBlobStream {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        // `Pin<Box<_>>` is `Unpin`, so the newtype is and `get_mut` is sound;
        // the boxed stream stays pinned.
        match self.get_mut().0.0.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(Bytes::from(chunk)))),
            Poll::Ready(Some(Err(err))) => {
                Poll::Ready(Some(Err(StreamError::Transport(err.to_string()))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// [`SendBlobStream`]s a worker `ByteStream`. `Box::new` before `Pin::from`
/// so the unsizing coercion to the trait object is the well-worn one.
fn blob_body_stream(stream: worker::ByteStream) -> BoxStream<'static, Result<Bytes, StreamError>> {
    let boxed: Box<dyn Stream<Item = Result<Vec<u8>, worker::Error>>> = Box::new(stream);
    Box::pin(SendBlobStream(SendWrapper::new(Pin::from(boxed))))
}

/// An empty body, for an object whose bytes R2 reports it cannot serve (a
/// failed conditional read): the port still answers a stream, just an empty
/// one, matching [`Blob::get`]'s empty buffer.
fn empty_body_stream() -> BoxStream<'static, Result<Bytes, StreamError>> {
    Box::pin(futures_util::stream::empty::<Result<Bytes, StreamError>>())
}

#[async_trait]
impl Blob for R2Blob {
    async fn put(&self, key: &str, bytes: &[u8], content_type: &str) -> Result<(), BlobError> {
        check_blob_size(bytes)?;
        self.bucket
            .put(key, bytes.to_vec())
            .http_metadata(HttpMetadata {
                content_type: Some(content_type.to_owned()),
                ..Default::default()
            })
            .execute()
            .into_send()
            .await
            .map(|_| ())
            .map_err(|err| op_err(&err))
    }

    async fn get(&self, key: &str) -> Result<Option<BlobObject>, BlobError> {
        let Some(object) = self
            .bucket
            .get(key)
            .execute()
            .into_send()
            .await
            .map_err(|err| op_err(&err))?
        else {
            return Ok(None);
        };
        let content_type = object
            .http_metadata()
            .content_type
            .unwrap_or_else(|| "application/octet-stream".to_owned());
        let bytes = match object.body() {
            Some(body) => body.bytes().into_send().await.map_err(|err| op_err(&err))?,
            None => Vec::new(),
        };
        Ok(Some(BlobObject {
            bytes,
            content_type,
        }))
    }

    async fn delete(&self, key: &str) -> Result<(), BlobError> {
        self.bucket
            .delete(key)
            .into_send()
            .await
            .map_err(|err| op_err(&err))
    }

    async fn signed_url(&self, key: &str, ttl: Duration) -> Result<String, BlobError> {
        Ok(presigner(self.presigner.as_ref())?.signed_url(key, ttl))
    }

    async fn signed_put_url(
        &self,
        key: &str,
        content_type: &str,
        content_length: Option<u64>,
        ttl: Duration,
    ) -> Result<PresignedPut, BlobError> {
        Ok(presigner(self.presigner.as_ref())?.signed_put_url(
            key,
            content_type,
            content_length,
            ttl,
        ))
    }

    async fn put_stream(
        &self,
        key: &str,
        body: BoxStream<'static, Result<Bytes, StreamError>>,
        content_type: &str,
        max_bytes: u64,
    ) -> Result<u64, BlobError> {
        // Buffer up to one part. An object that ends inside the first part
        // is a plain put (no multipart machinery); anything larger streams
        // through a multipart upload. The fill loop never holds more than
        // `PUT_STREAM_PART_BYTES` plus the chunk that crossed it, so peak
        // memory is a couple of parts regardless of object size.
        let mut limited = limit_stream(body, max_bytes);
        let mut buffered: Vec<u8> = Vec::new();
        let mut ended = false;
        while buffered.len() < PUT_STREAM_PART_BYTES {
            match limited.next().await {
                Some(Ok(chunk)) => buffered.extend_from_slice(&chunk),
                Some(Err(err)) => return Err(BlobError::from(err)),
                None => {
                    ended = true;
                    break;
                }
            }
        }
        if ended {
            let written = buffered.len() as u64;
            self.put_bytes(key, &buffered, content_type).await?;
            return Ok(written);
        }
        self.put_stream_multipart(key, content_type, limited, buffered)
            .await
    }

    async fn get_stream(&self, key: &str) -> Result<Option<BlobStream>, BlobError> {
        let Some(object) = self
            .bucket
            .get(key)
            .execute()
            .into_send()
            .await
            .map_err(|err| op_err(&err))?
        else {
            return Ok(None);
        };
        let size = object.size();
        let content_type = content_type_or_default(&object.http_metadata());
        // `stream()` hands back a `!Send` JS-backed stream; `blob_body_stream`
        // wraps it for the port's `Send` body (ADR 0002, single-threaded).
        let body = match object.body() {
            Some(body) => blob_body_stream(body.stream().map_err(|err| op_err(&err))?),
            None => empty_body_stream(),
        };
        Ok(Some(BlobStream {
            content_type,
            size,
            body,
        }))
    }

    async fn head(&self, key: &str) -> Result<Option<BlobMeta>, BlobError> {
        let Some(object) = self
            .bucket
            .head(key)
            .into_send()
            .await
            .map_err(|err| op_err(&err))?
        else {
            return Ok(None);
        };
        Ok(Some(BlobMeta {
            key: object.key(),
            size: object.size(),
            content_type: content_type_or_default(&object.http_metadata()),
        }))
    }

    async fn list(
        &self,
        prefix: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<BlobPage, BlobError> {
        // The `ScopedBlob` clamps this already; the adapter clamps again so a
        // direct user cannot ask R2 for more than its own page cap. The value
        // is `1 ..= MAX_LIST_LIMIT`, so it always fits R2's `u32` limit.
        let limit =
            u32::try_from(limit.clamp(1, MAX_LIST_LIMIT)).expect("MAX_LIST_LIMIT fits a u32");
        // `include(httpMetadata)` so each listed object carries the content
        // type the module stored, rather than an empty one.
        let mut builder = self
            .bucket
            .list()
            .prefix(prefix)
            .limit(limit)
            .include(vec![Include::HttpMetadata]);
        if let Some(cursor) = cursor {
            builder = builder.cursor(cursor);
        }
        let objects = builder
            .execute()
            .into_send()
            .await
            .map_err(|err| op_err(&err))?;
        let page = objects
            .objects()
            .iter()
            .map(|object| BlobMeta {
                key: object.key(),
                size: object.size(),
                content_type: content_type_or_default(&object.http_metadata()),
            })
            .collect();
        // R2's cursor is only meaningful while truncated; a `None` here is the
        // port's "last page" signal.
        let cursor = if objects.truncated() {
            objects.cursor()
        } else {
            None
        };
        Ok(BlobPage {
            objects: page,
            cursor,
        })
    }

    async fn create_multipart(&self, key: &str, content_type: &str) -> Result<UploadId, BlobError> {
        let upload = self.create_upload(key, content_type).await?;
        let id = upload.upload_id().into_send().await;
        Ok(UploadId::new(id))
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
        // R2 refuses a part whose length it does not know, so the part is
        // buffered whole first — bounded by the caller's ceiling, which
        // `limit_stream` enforces as it goes. Parts should be well under the
        // isolate's memory (issue #586); this is the adapter's own second
        // gate.
        let buffered = self.read_part(body, max_part_bytes).await?;
        let upload = self
            .bucket
            .resume_multipart_upload(key, upload_id.as_str())
            .map_err(|err| op_err(&err))?;
        let uploaded = upload
            .upload_part(part_number, Data::Bytes(buffered))
            .into_send()
            .await
            .map_err(|err| op_err(&err))?;
        Ok(PartReceipt {
            part_number,
            etag: uploaded.etag(),
        })
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
        let upload = self
            .bucket
            .resume_multipart_upload(key, upload_id.as_str())
            .map_err(|err| op_err(&err))?;
        // R2 takes the ETag each part reported; the receipts carry them back,
        // so a part whose ETag no longer matches is refused by the store.
        // `UploadedPart::new` reconstructs one from the number and ETag.
        let uploaded: Vec<worker::UploadedPart> = parts
            .iter()
            .map(|receipt| worker::UploadedPart::new(receipt.part_number, receipt.etag.clone()))
            .collect();
        upload
            .complete(uploaded)
            .into_send()
            .await
            .map_err(|err| op_err(&err))?;
        Ok(())
    }

    async fn abort_multipart(&self, key: &str, upload_id: &UploadId) -> Result<(), BlobError> {
        let upload = self
            .bucket
            .resume_multipart_upload(key, upload_id.as_str())
            .map_err(|err| op_err(&err))?;
        upload.abort().into_send().await.map_err(|err| op_err(&err))
    }

    async fn list_multipart_uploads(&self, _prefix: &str) -> Result<Vec<PendingUpload>, BlobError> {
        // The Worker R2 binding exposes no way to enumerate in-flight
        // multipart uploads. worker 0.8.5's `r2` module has per-upload
        // operations (resume/abort/complete/upload_part) but no
        // `list_multipart_uploads`, and Cloudflare's binding docs match: the
        // S3 API has it, the binding does not. An R2 lifecycle rule that
        // aborts incomplete multipart uploads after a few days is the
        // supported reclaim path (issue #586).
        Err(BlobError::Unsupported(
            "the Workers R2 binding cannot list multipart uploads; configure an R2 \
             lifecycle rule that aborts incomplete multipart uploads"
                .to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cratefield_core::sigv4::{SigV4Error, verify_presigned};
    use time::OffsetDateTime;

    const ACCESS_KEY: &str = "AKIAEXAMPLE";
    const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    /// A key whose space must be percent-encoded, so the test pins the path
    /// shape rather than a trivially-safe key.
    const KEY: &str = "renders/job 1/out.mp4";
    const PATH: &str = "/media/renders/job%201/out.mp4";

    /// A clock frozen at one instant, so a test can verify at a later one to
    /// prove expiry. (`cratefield-testing`'s `FixedClock` sits behind a feature
    /// this crate's dev-dependencies do not carry.)
    struct TestClock(OffsetDateTime);

    #[async_trait]
    impl Clock for TestClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    /// A valid test timestamp, read as UTC.
    fn at(year: i32, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> OffsetDateTime {
        let date =
            time::Date::from_calendar_date(year, time::Month::try_from(month).expect("month"), day)
                .expect("a valid test date");
        let time = time::Time::from_hms(hour, minute, second).expect("a valid test time");
        time::PrimitiveDateTime::new(date, time).assume_utc()
    }

    fn credentials() -> Credentials {
        Credentials::new(ACCESS_KEY, SECRET_KEY)
    }

    fn presigner_at(now: OffsetDateTime) -> R2Presigner {
        R2Presigner::new("acct123", "media", credentials(), Arc::new(TestClock(now)))
    }

    #[test]
    fn a_signed_get_url_has_the_r2_shape_and_verifies() {
        let now = at(2026, 1, 1, 0, 0, 0);
        let url = presigner_at(now).signed_url(KEY, Duration::from_secs(600));
        assert!(
            url.starts_with(&format!("https://acct123.r2.cloudflarestorage.com{PATH}?")),
            "{url}"
        );
        verify_presigned(&url, "GET", &[], &credentials(), R2_REGION, R2_SERVICE, now)
            .expect("the URL verifies against the same credentials");
    }

    #[test]
    fn a_signed_put_url_signs_content_type_and_length() {
        let now = at(2026, 1, 1, 0, 0, 0);
        let put = presigner_at(now).signed_put_url(
            KEY,
            "video/mp4",
            Some(1024),
            Duration::from_secs(600),
        );
        assert_eq!(put.method, "PUT");
        assert_eq!(
            put.headers,
            vec![
                ("content-type".to_owned(), "video/mp4".to_owned()),
                ("content-length".to_owned(), "1024".to_owned()),
            ]
        );
        verify_presigned(
            &put.url,
            "PUT",
            &put.headers,
            &credentials(),
            R2_REGION,
            R2_SERVICE,
            now,
        )
        .expect("the signed headers verify");
    }

    #[test]
    fn a_url_is_refused_after_it_expires() {
        let url = presigner_at(at(2026, 1, 1, 0, 0, 0)).signed_url(KEY, Duration::from_secs(600));
        let verify_at =
            |now| verify_presigned(&url, "GET", &[], &credentials(), R2_REGION, R2_SERVICE, now);
        // The deadline itself (signed_at + 600s) is still valid; a second later
        // is not.
        verify_at(at(2026, 1, 1, 0, 10, 0)).expect("the deadline itself still verifies");
        assert_eq!(
            verify_at(at(2026, 1, 1, 0, 10, 1)),
            Err(SigV4Error::Expired)
        );
    }

    #[test]
    fn presigning_is_unsupported_without_a_presigner() {
        // Both presign methods share this refusal: no seam means `Unsupported`.
        assert!(matches!(presigner(None), Err(BlobError::Unsupported(_))));
        assert!(presigner(Some(&presigner_at(at(2026, 1, 1, 0, 0, 0)))).is_ok());
    }
}
