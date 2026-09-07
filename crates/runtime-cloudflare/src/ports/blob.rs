//! [`Blob`] over a Cloudflare R2 bucket (issue #105). Small media on Workers:
//! a coach's voice clip, served to members.
//!
//! `signed_url` returns [`BlobError::Unsupported`]: R2 presigned URLs need the
//! S3-compatible API and its access keys, not the Worker binding, so a direct
//! download that skips the Worker is a later, separate adapter. Serve the bytes
//! through [`Blob::get`] until then.
//!
//! **Verification.** Like every Workers adapter this is build-checked here and
//! must be exercised in `wrangler dev` against a real bucket before it is
//! trusted (issue #105 acceptance) — cargo tests never touch R2.

use async_trait::async_trait;
use cratefield_core::{Blob, BlobError, BlobObject};
use std::time::Duration;
use worker::send::IntoSendFuture;
use worker::{Bucket, HttpMetadata};

/// A [`Blob`] store over an R2 bucket binding.
pub struct R2Blob(pub Bucket);

fn op_err(err: &worker::Error) -> BlobError {
    BlobError::Operation(err.to_string())
}

#[async_trait]
impl Blob for R2Blob {
    async fn put(&self, key: &str, bytes: &[u8], content_type: &str) -> Result<(), BlobError> {
        self.0
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
            .0
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
        self.0
            .delete(key)
            .into_send()
            .await
            .map_err(|err| op_err(&err))
    }

    async fn signed_url(&self, _key: &str, _ttl: Duration) -> Result<String, BlobError> {
        Err(BlobError::Unsupported(
            "R2 presigned URLs need the S3-compatible API, not the Worker binding; \
             serve the bytes through the harness for now"
                .to_owned(),
        ))
    }
}
