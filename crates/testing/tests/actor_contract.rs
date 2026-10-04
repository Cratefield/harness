//! `MemoryActors`, the in-process actor host the kit ships (issue #583),
//! held to `assert_actor_contract` — the same contract a real adapter's
//! host must pass. A fake that drifted from the port would let a module
//! pass its own tests and then lose a counter against Durable Objects.

use std::sync::Arc;

use cratefield_core::Actors;
use cratefield_testing::{
    ManualClock, MemoryActors, assert_actor_contract, contract_actor_handlers,
};

#[pollster::test]
async fn memory_actors_meet_the_actor_contract() {
    let actors = Arc::new(MemoryActors::new(
        contract_actor_handlers(),
        ManualClock::new(
            time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("a valid epoch"),
        ),
    ));
    let host: Arc<dyn Actors> = actors.clone();
    assert_actor_contract(host, |by| {
        let actors = Arc::clone(&actors);
        async move { actors.advance(by).await }
    })
    .await;
}
