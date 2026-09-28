//! `vector_index_conformance` (issue #561) proven against the native
//! exact index, the way `classifier_conformance` is proven against
//! `FakeClassifier` in `classifier_conformance.rs`.

use cratefield_core::ExactVectorIndex;
use cratefield_testing::vector_index_conformance;

#[test]
fn the_suite_passes_the_exact_index() {
    pollster::block_on(vector_index_conformance(&ExactVectorIndex::new(3)));
}
