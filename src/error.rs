//! One error type for the whole crate, so callers never have to juggle
//! `ProgramError`, `TokenProofGenerationError` and `Box<dyn Error>` by hand.

use {
    solana_program_error::ProgramError,
    spl_token_confidential_transfer_proof_generation::errors::TokenProofGenerationError,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("token-2022 rejected the request: {0}")]
    Program(#[from] ProgramError),

    #[error("could not build a zero-knowledge proof: {0}")]
    ProofGeneration(#[from] TokenProofGenerationError),

    /// Key derivation signs a seed with the owner's wallet, which can fail for
    /// hardware signers.
    #[error("could not derive confidential-transfer keys: {0}")]
    KeyDerivation(String),

    /// The mint is missing an extension the requested operation depends on.
    #[error("mint or account is missing the {0} extension")]
    MissingExtension(&'static str),

    /// `calculate_epoch_fee` returns `None` only on overflow.
    #[error("transfer fee calculation overflowed for amount {0}")]
    FeeOverflow(u64),

    /// The AES key handed in does not match the ciphertext stored on chain.
    #[error("could not decrypt the account's balance with the supplied AES key")]
    BalanceDecryption,

    /// Withdraw (and transfer) spend the *available* balance only. Pending
    /// credits must be rolled in with `ApplyPendingBalance` first, otherwise
    /// the equality proof is built against a stale ciphertext and the
    /// instruction fails on chain.
    #[error("account still holds an unapplied pending balance; apply it before withdrawing")]
    PendingBalanceNotApplied,

    #[error("insufficient confidential balance: have {available}, need {requested}")]
    InsufficientConfidentialBalance { available: u64, requested: u64 },
}
