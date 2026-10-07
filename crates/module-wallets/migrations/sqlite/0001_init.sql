-- One row per outstanding nonce (issue #835) and one per linked wallet.
-- Both tables are a subject's: `wallet_nonces` is an in-flight proof of
-- ownership attempt (account_id, chain, chain_id, nonce, expiry), and
-- `wallet_links` is a durable link (account_id, chain, address). A nonce is
-- single-use: the guarded conditional UPDATE that sets `consumed_at` is the
-- replay check, and the `UNIQUE (chain, address)` index on `wallet_links` is
-- the one-wallet one-account rule. Every timestamp is an RFC 3339 UTC string
-- with whole seconds, so the comparisons the handlers make are the ones the
-- columns can carry.
--
-- `chain` is the coarse family ("evm" or "solana"); `chain_id` is the exact
-- chain the nonce was minted for ("1", "8453", "mainnet-beta"). Both are
-- needed: the family alone would let a message written for another chain of
-- the same family be spent here.
CREATE TABLE IF NOT EXISTS wallet_nonces (
    nonce TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    chain TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS wallet_nonces_expires_idx ON wallet_nonces (expires_at);

CREATE TABLE IF NOT EXISTS wallet_links (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    chain TEXT NOT NULL,
    address TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    UNIQUE (chain, address)
);
CREATE INDEX IF NOT EXISTS wallet_links_account_idx ON wallet_links (account_id);
