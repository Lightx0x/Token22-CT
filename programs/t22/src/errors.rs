use anchor_lang::prelude::*;

#[error_code]
pub enum MintError {
    #[msg("mint carries an extension this program has not been written to handle")]
    UnsupportedExtension,
    #[msg("mint does not charge a transfer fee")]
    MissingTransferFee,
    #[msg("transfer fee calculation overflowed")]
    FeeOverflow,
    #[msg("mint has no permanent delegate, or the signer is not it")]
    NoSeizureAuthority,
    #[msg("a confidential transfer with a fee needs five proof context accounts")]
    MissingProofContexts,
    #[msg("no accounts were supplied to harvest fees from")]
    NoFeeSources,
    #[msg("apply the pending balance before withdrawing")]
    PendingBalanceNotApplied,
}
