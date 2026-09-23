//! # A Token-2022 remittance stablecoin
//!
//! Two mints are described here, because the second requirement set cannot be
//! bolted onto the first:
//!
//! * [`mint::create_remittance_mint_v1`] — protocol transfer fee, new accounts
//!   default-frozen until KYC clears, metadata living in the mint itself, and a
//!   close authority so the mint can be decommissioned.
//! * [`mint::create_remittance_mint_v2`] — the same extension set, re-issued
//!   with a `PermanentDelegate` (regulator-facing seizure authority) and
//!   confidential transfers with manual approval.
//!
//! Extensions can only be initialised between `CreateAccount` and
//! `InitializeMint`, so "add confidential transfers to the live mint" is not an
//! option — v2 is a genuinely new mint address that holders must migrate to.
//!
//! ## Why this is a client crate and not an on-chain program
//!
//! Token-2022 already implements every instruction below. The confidential
//! lifecycle additionally needs ElGamal/AES key material and zero-knowledge
//! proofs built *from* that material; a program cannot do that, because the
//! secret must never reach the chain. So the useful artifact is a builder that
//! produces correctly ordered, correctly signed instructions.
//!
//! Nothing here sends transactions. Every entry point returns instructions (or
//! [`plan::Step`]s, when an operation spans more than one transaction) and
//! reads chain state from `&[u8]` account data the caller fetched. That keeps
//! the crate testable against `litesvm` and free of an RPC dependency.
//!
//! ## The gap between "seizable" and "confidential"
//!
//! See [`mint::gap_analysis`]. In short: Token-2022 *forces* the two
//! requirements to interact (a fee-bearing confidential mint must also carry
//! `ConfidentialTransferFeeConfig`, and its confidential transfers must use
//! `TransferWithFee`), and the permanent delegate can move the public balance
//! but cannot reach the confidential one.

pub mod confidential;
pub mod error;
pub mod kyc;
pub mod mint;
pub mod plan;
pub mod proof;
pub mod state;
pub mod transfer;

pub use error::{Error, Result};

use solana_pubkey::Pubkey;

/// `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`.
///
/// Every builder in this crate targets Token-2022 specifically; the original
/// Token program has none of these extensions.
pub fn token_program_id() -> Pubkey {
    spl_token_2022_interface::id()
}
