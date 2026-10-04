//! `assert_blob_large_round_trips` (issue #586) proven against the kit's
//! own `MemoryBlob`, the way `vector_index_conformance` is proven against
//! the exact index.

use std::sync::Arc;

use cratefield_testing::{MemoryBlob, assert_blob_large_round_trips};

#[test]
fn memory_blob_satisfies_the_large_blob_contract() {
    pollster::block_on(assert_blob_large_round_trips(Arc::new(MemoryBlob::new())));
}
