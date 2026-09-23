//! **Task 4: the unfreeze path.**
//!
//! `DefaultAccountState(Frozen)` makes every *newly created* account start
//! frozen. It is a mint-level default read at account-initialisation time — it
//! is not a switch that freezes or thaws accounts that already exist.
//!
//! That gives two clearly separate operations, and conflating them is the
//! classic mistake:
//!
//! * [`thaw_after_kyc`] — the freeze authority thaws **one** account, once that
//!   holder's KYC cleared. Nothing else on the mint changes.
//! * [`set_default_account_state`] — the freeze authority changes the default
//!   for accounts created **from now on**. Setting it to `Initialized` opens
//!   the gate for future holders and leaves every already-frozen account
//!   exactly as frozen as it was.
//!
//! So a KYC programme runs entirely through the first function; the second is a
//! policy change (e.g. dropping the KYC requirement) and is not part of
//! onboarding a user.

use {
    crate::{error::Result, state},
    solana_instruction::Instruction,
    solana_pubkey::Pubkey,
    spl_token_2022_interface::{
        extension::default_account_state, instruction as token_instruction, state::AccountState,
    },
};

/// Thaw one account after its holder passed KYC.
///
/// Signed by the mint's freeze authority. Until this lands the account can
/// neither receive nor send — including confidential deposits, which reject
/// frozen accounts.
pub fn thaw_after_kyc(
    mint: &Pubkey,
    token_account: &Pubkey,
    freeze_authority: &Pubkey,
) -> Result<Instruction> {
    Ok(token_instruction::thaw_account(
        &spl_token_2022_interface::id(),
        token_account,
        mint,
        freeze_authority,
        &[],
    )?)
}

/// Re-freeze a single account, e.g. on a sanctions hit.
///
/// Freezing is the only unilateral control that reaches a confidential balance:
/// it cannot take the funds, but it stops them moving.
pub fn freeze(
    mint: &Pubkey,
    token_account: &Pubkey,
    freeze_authority: &Pubkey,
) -> Result<Instruction> {
    Ok(token_instruction::freeze_account(
        &spl_token_2022_interface::id(),
        token_account,
        mint,
        freeze_authority,
        &[],
    )?)
}

/// Change the mint-level default for **future** accounts only.
///
/// Distinct from [`thaw_after_kyc`] in both effect and blast radius; see the
/// module docs.
pub fn set_default_account_state(
    mint: &Pubkey,
    freeze_authority: &Pubkey,
    new_state: AccountState,
) -> Result<Instruction> {
    Ok(
        default_account_state::instruction::update_default_account_state(
            &spl_token_2022_interface::id(),
            mint,
            freeze_authority,
            &[],
            &new_state,
        )?,
    )
}

/// Whether this account still needs a KYC thaw.
pub fn needs_thaw(account_data: &[u8]) -> Result<bool> {
    state::is_frozen(account_data)
}
