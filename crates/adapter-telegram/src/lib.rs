//! `cratefield-adapter-telegram`: the [`TelegramBot`] port over the Telegram
//! Bot API (issue #764), the harness's chat side. Uses the runtime's
//! [`HttpClient`](cratefield_core::HttpClient) port — no vendor SDK, no
//! `reqwest` — so the same adapter runs on Workers and natively, and the
//! [`Clock`](cratefield_core::Clock) port to drive its local rate budgets so
//! tests move time by hand.
//!
//! The outbound half ([`HttpTelegramBot`]) speaks the four calls a module
//! needs — send, edit, delete, answer-callback — and refuses locally what
//! Telegram would refuse remotely: an exhausted rate bucket returns
//! [`TelegramError::RateLimited`] before any HTTP request is sent. The
//! inbound half ([`parse_update`], [`webhook::parse_verified`]) turns one
//! webhook delivery into a typed [`Update`], verified before it is parsed.

#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod client;
mod update;

pub mod conformance;
pub mod fake;
pub mod webhook;

pub use client::{
    ButtonKind, HttpTelegramBot, InlineButton, OutgoingMessage, RateLimits, SentMessage,
    TelegramBot, TelegramError,
};
pub use update::{
    CallbackQuery, ChannelPost, Chat, ChatKind, Command, Message, Update, UpdateError, UpdateKind,
    User, parse_update,
};
