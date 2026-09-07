//! [`Realtime`] over an in-process room registry (issue #103), the self-hosted
//! counterpart of the Cloudflare Durable Object adapter. Each room keeps its
//! connected members' outgoing channels in a map; broadcasts fan out over
//! them, and the shared clock is a `tokio` timer.
//!
//! This is the adapter the conformance suite runs against (join, broadcast to
//! N, leave, alarm once, a non-member's message refused). A real deployment
//! bridges [`Connection`] to a `tokio-tungstenite` / axum WebSocket; the tests
//! drive it directly.

// The room registry is the adapter's own coordinator state, shared across a
// room's connections — not per-request state (ADR 0007 allows a scoped,
// justified Mutex, as the sqlite and testing crates do).
#![allow(clippy::disallowed_types)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use cratefield_core::{Member, Realtime, RealtimeError, RoomContext, RoomHandler};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// A member id paired with its outgoing-message sender.
type MemberSender = (String, UnboundedSender<Vec<u8>>);

/// A [`Realtime`] adapter that holds every room's sockets in this process.
#[derive(Clone)]
pub struct InProcessRealtime {
    handler: Arc<dyn RoomHandler>,
    rooms: Arc<Mutex<HashMap<String, Room>>>,
}

#[derive(Default)]
struct Room {
    /// Each connected member's outgoing channel: a message pushed here is
    /// written to that member's socket by the caller pumping [`Connection`].
    members: HashMap<String, UnboundedSender<Vec<u8>>>,
    /// The pending shared-clock alarm, if any.
    alarm: Option<tokio::task::JoinHandle<()>>,
}

impl InProcessRealtime {
    #[must_use]
    pub fn new(handler: Arc<dyn RoomHandler>) -> Self {
        Self {
            handler,
            rooms: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn context(&self, room_id: &str) -> NativeContext {
        NativeContext {
            rooms: Arc::clone(&self.rooms),
            handler: Arc::clone(&self.handler),
            room_id: room_id.to_owned(),
        }
    }

    /// Opens a socket for `member` in `room_id`: registers its outgoing
    /// channel, runs [`RoomHandler::on_join`], and returns a [`Connection`] the
    /// caller pumps. `next_outgoing` yields messages to write to the socket;
    /// `deliver` feeds messages received from it; `close` ends the membership.
    ///
    /// # Panics
    ///
    /// Panics if the room registry lock is poisoned.
    ///
    /// # Errors
    ///
    /// Propagates any [`RealtimeError`] the handler's `on_join` returns.
    pub async fn connect(
        &self,
        room_id: &str,
        member: Member,
    ) -> Result<Connection, RealtimeError> {
        let (tx, rx) = unbounded_channel();
        {
            let mut rooms = self.rooms.lock().expect("rooms lock");
            rooms
                .entry(room_id.to_owned())
                .or_default()
                .members
                .insert(member.id.clone(), tx);
        }
        let ctx = self.context(room_id);
        self.handler.on_join(&ctx, &member).await?;
        Ok(Connection {
            rx,
            member,
            room_id: room_id.to_owned(),
            realtime: self.clone(),
        })
    }
}

/// One member's open socket. The caller writes [`Connection::next_outgoing`]
/// messages to the wire and calls [`Connection::deliver`] with what it reads.
pub struct Connection {
    rx: UnboundedReceiver<Vec<u8>>,
    member: Member,
    room_id: String,
    realtime: InProcessRealtime,
}

impl Connection {
    /// The next message the room wants written to this socket, or `None` once
    /// the connection is closed.
    pub async fn next_outgoing(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }

    /// Feeds a message received from the socket to [`RoomHandler::on_message`].
    ///
    /// # Errors
    ///
    /// [`RealtimeError::NotAMember`] if this member has already left (so a late
    /// or forged frame is dropped), else any error the handler returns.
    ///
    /// # Panics
    ///
    /// Panics if the room registry lock is poisoned.
    pub async fn deliver(&self, message: &[u8]) -> Result<(), RealtimeError> {
        let present = {
            let rooms = self.realtime.rooms.lock().expect("rooms lock");
            rooms
                .get(&self.room_id)
                .is_some_and(|room| room.members.contains_key(&self.member.id))
        };
        if !present {
            return Err(RealtimeError::NotAMember);
        }
        let ctx = self.realtime.context(&self.room_id);
        self.realtime
            .handler
            .on_message(&ctx, &self.member, message)
            .await
    }

    /// Ends the membership: removes the socket and runs
    /// [`RoomHandler::on_leave`].
    ///
    /// # Errors
    ///
    /// Propagates any error the handler's `on_leave` returns.
    ///
    /// # Panics
    ///
    /// Panics if the room registry lock is poisoned.
    pub async fn close(self) -> Result<(), RealtimeError> {
        {
            let mut rooms = self.realtime.rooms.lock().expect("rooms lock");
            if let Some(room) = rooms.get_mut(&self.room_id) {
                room.members.remove(&self.member.id);
                if room.members.is_empty() {
                    if let Some(alarm) = room.alarm.take() {
                        alarm.abort();
                    }
                    rooms.remove(&self.room_id);
                }
            }
        }
        let ctx = self.realtime.context(&self.room_id);
        self.realtime.handler.on_leave(&ctx, &self.member).await
    }
}

/// The [`RoomContext`] handed to handler callbacks on the native runtime.
struct NativeContext {
    rooms: Arc<Mutex<HashMap<String, Room>>>,
    handler: Arc<dyn RoomHandler>,
    room_id: String,
}

impl NativeContext {
    /// Snapshots the room's senders without holding the lock across the sends
    /// (a handler's `broadcast` must not deadlock against a lock the runtime
    /// holds while calling it).
    fn senders(&self) -> Vec<MemberSender> {
        let rooms = self.rooms.lock().expect("rooms lock");
        rooms
            .get(&self.room_id)
            .map(|room| {
                room.members
                    .iter()
                    .map(|(id, tx)| (id.clone(), tx.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[async_trait]
impl RoomContext for NativeContext {
    fn room_id(&self) -> &str {
        &self.room_id
    }

    async fn members(&self) -> Vec<Member> {
        self.senders()
            .into_iter()
            .map(|(id, _)| Member::new(id))
            .collect()
    }

    async fn broadcast(&self, message: &[u8]) -> Result<(), RealtimeError> {
        for (_, tx) in self.senders() {
            // A closed receiver just means that socket is gone; ignore it.
            let _ = tx.send(message.to_vec());
        }
        Ok(())
    }

    async fn send(&self, member_id: &str, message: &[u8]) -> Result<(), RealtimeError> {
        let sender = self
            .senders()
            .into_iter()
            .find(|(id, _)| id == member_id)
            .map(|(_, tx)| tx);
        if let Some(tx) = sender {
            let _ = tx.send(message.to_vec());
        }
        Ok(())
    }

    async fn set_alarm(&self, delay: Duration) -> Result<(), RealtimeError> {
        let rooms = Arc::clone(&self.rooms);
        let handler = Arc::clone(&self.handler);
        let room_id = self.room_id.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let ctx = NativeContext {
                rooms,
                handler: Arc::clone(&handler),
                room_id,
            };
            let _ = handler.on_alarm(&ctx).await;
        });
        let mut rooms = self.rooms.lock().expect("rooms lock");
        if let Some(room) = rooms.get_mut(&self.room_id) {
            if let Some(previous) = room.alarm.replace(handle) {
                previous.abort();
            }
        } else {
            // No room to hang the alarm on (everyone left): cancel it.
            handle.abort();
        }
        Ok(())
    }
}

#[async_trait]
impl Realtime for InProcessRealtime {
    async fn broadcast(&self, room_id: &str, message: &[u8]) -> Result<(), RealtimeError> {
        self.context(room_id).broadcast(message).await
    }

    async fn members(&self, room_id: &str) -> Result<Vec<Member>, RealtimeError> {
        Ok(self.context(room_id).members().await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A handler that records its callbacks and, on join/message, re-broadcasts
    /// so the tests can observe what reached the sockets.
    #[derive(Default)]
    struct Recorder {
        joins: AtomicUsize,
        leaves: AtomicUsize,
        alarms: AtomicUsize,
    }

    #[async_trait]
    impl RoomHandler for Recorder {
        async fn on_join(
            &self,
            ctx: &dyn RoomContext,
            member: &Member,
        ) -> Result<(), RealtimeError> {
            self.joins.fetch_add(1, Ordering::SeqCst);
            ctx.broadcast(format!("join:{}", member.id).as_bytes())
                .await
        }

        async fn on_message(
            &self,
            ctx: &dyn RoomContext,
            member: &Member,
            message: &[u8],
        ) -> Result<(), RealtimeError> {
            let echo = format!("{}:{}", member.id, String::from_utf8_lossy(message));
            ctx.broadcast(echo.as_bytes()).await
        }

        async fn on_leave(
            &self,
            _ctx: &dyn RoomContext,
            _member: &Member,
        ) -> Result<(), RealtimeError> {
            self.leaves.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn on_alarm(&self, ctx: &dyn RoomContext) -> Result<(), RealtimeError> {
            self.alarms.fetch_add(1, Ordering::SeqCst);
            ctx.broadcast(b"tick").await
        }
    }

    fn recorder() -> (InProcessRealtime, Arc<Recorder>) {
        let recorder = Arc::new(Recorder::default());
        (InProcessRealtime::new(recorder.clone()), recorder)
    }

    #[tokio::test]
    async fn join_broadcasts_to_every_member() {
        let (rt, rec) = recorder();
        let mut a = rt.connect("room", Member::new("a")).await.unwrap();
        let mut b = rt.connect("room", Member::new("b")).await.unwrap();

        // Both joins broadcast; from the outside, a fresh broadcast reaches N.
        rt.broadcast("room", b"hello").await.unwrap();
        assert_eq!(rt.members("room").await.unwrap().len(), 2);
        assert_eq!(rec.joins.load(Ordering::SeqCst), 2);

        // `a` sees its own join, `b`'s join, then the external hello.
        assert_eq!(a.next_outgoing().await.unwrap(), b"join:a");
        assert_eq!(a.next_outgoing().await.unwrap(), b"join:b");
        assert_eq!(a.next_outgoing().await.unwrap(), b"hello");
        // `b` joined after `a`, so it only sees its own join and the hello.
        assert_eq!(b.next_outgoing().await.unwrap(), b"join:b");
        assert_eq!(b.next_outgoing().await.unwrap(), b"hello");
    }

    #[tokio::test]
    async fn a_message_reaches_the_other_members() {
        let (rt, _rec) = recorder();
        let a = rt.connect("room", Member::new("a")).await.unwrap();
        let mut b = rt.connect("room", Member::new("b")).await.unwrap();
        // `a` joined first, so `b` only sees its own join broadcast (`join:b`);
        // `a`'s `join:a` fired before `b` connected. Drain that one notice.
        assert_eq!(b.next_outgoing().await.unwrap(), b"join:b");

        a.deliver(b"hi").await.unwrap();
        assert_eq!(b.next_outgoing().await.unwrap(), b"a:hi");
    }

    #[tokio::test]
    async fn leaving_removes_the_member_and_runs_on_leave() {
        let (rt, rec) = recorder();
        let a = rt.connect("room", Member::new("a")).await.unwrap();
        rt.connect("room", Member::new("b")).await.unwrap();
        a.close().await.unwrap();
        assert_eq!(rec.leaves.load(Ordering::SeqCst), 1);
        let ids: Vec<String> = rt
            .members("room")
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.id)
            .collect();
        assert_eq!(ids, ["b"]);
    }

    #[tokio::test]
    async fn a_message_from_a_departed_member_is_refused() {
        let (rt, _rec) = recorder();
        rt.connect("room", Member::new("keep")).await.unwrap();
        let gone = rt.connect("room", Member::new("gone")).await.unwrap();
        // Take a handle to deliver through after closing.
        let realtime = rt.clone();
        let member = gone.member.clone();
        gone.close().await.unwrap();
        let orphan = Connection {
            rx: unbounded_channel().1,
            member,
            room_id: "room".to_owned(),
            realtime,
        };
        assert!(matches!(
            orphan.deliver(b"late").await,
            Err(RealtimeError::NotAMember)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn an_alarm_fires_exactly_once() {
        let (rt, rec) = recorder();
        let mut a = rt.connect("room", Member::new("a")).await.unwrap();
        let _ = a.next_outgoing().await; // the join notice

        // Schedule the shared-clock tick via a handler event.
        rt.context("room")
            .set_alarm(Duration::from_millis(50))
            .await
            .unwrap();
        tokio::time::advance(Duration::from_millis(60)).await;
        // Let the spawned alarm task run.
        tokio::task::yield_now().await;

        assert_eq!(a.next_outgoing().await.unwrap(), b"tick");
        assert_eq!(rec.alarms.load(Ordering::SeqCst), 1);
    }
}
