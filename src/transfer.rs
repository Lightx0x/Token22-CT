//! **Task 2: public transfers on a fee-bearing mint.**
//!
//! On a mint with `TransferFeeConfig`, `Transfer` is deprecated and
//! `TransferChecked` lets the program pick the fee on its own. Neither tells
//! the caller what the recipient will actually receive.
//!
//! `TransferCheckedWithFee` makes the caller state the fee explicitly and the
//! program recomputes it; a mismatch aborts with `FeeMismatch`. That turns a
//! silent deduction into a checked assertion — which is what you want when the
//! fee is issuer revenue and the amounts are remittances.
//!
//! The fee is therefore always computed here from the mint's live
//! `TransferFeeConfig` for the *current epoch*, never from a cached rate. The
//! extension stores two schedules, `older_transfer_fee` and
//! `newer_transfer_fee`, with the newer one carrying the epoch it activates in;
//! `calculate_epoch_fee` picks between them. A rate cached even one epoch ago
//! can pick the wrong side of that boundary and fail the whole transfer.

use {
    crate::{
        error::{Error, Result},
        state,
    },
    solana_instruction::Instruction,
    solana_pubkey::Pubkey,
    spl_token_2022_interface::extension::transfer_fee,
};

/// What a transfer will cost and what will land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeQuote {
    /// Debited from the source.
    pub amount: u64,
    /// Parked on the *destination* account's `TransferFeeAmount` extension —
    /// alongside its balance, not inside it — for the withdraw-withheld
    /// authority to harvest later. It never moves separately at transfer time.
    pub fee: u64,
    /// What the destination's `amount` actually grows by: `amount - fee`.
    pub net_received: u64,
    /// The epoch the fee was computed for; a transfer built for epoch N and
    /// submitted in epoch N+1 can be rejected if the schedule changed.
    pub epoch: u64,
}

/// Quote a transfer without building it.
///
/// `current_epoch` comes from the cluster (`getEpochInfo`), not from a clock
/// the caller keeps.
pub fn quote(mint_data: &[u8], current_epoch: u64, amount: u64) -> Result<FeeQuote> {
    let config = state::transfer_fee_config(mint_data)?;

    // The only `None` case is arithmetic overflow inside the fee maths.
    let fee = config
        .calculate_epoch_fee(current_epoch, amount)
        .ok_or(Error::FeeOverflow(amount))?;

    Ok(FeeQuote {
        amount,
        fee,
        // Cannot underflow: the fee is capped at `amount` by construction.
        net_received: amount.saturating_sub(fee),
        epoch: current_epoch,
    })
}

/// Build a fee-aware transfer, signed by the token account owner.
///
/// `mint_data` supplies both the fee schedule and the decimals, so a stale
/// `decimals` constant cannot cause a `MintDecimalsMismatch`.
#[allow(clippy::too_many_arguments)]
pub fn transfer_checked_with_fee(
    mint: &Pubkey,
    mint_data: &[u8],
    source: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    multisig_signers: &[&Pubkey],
    amount: u64,
    current_epoch: u64,
) -> Result<(Instruction, FeeQuote)> {
    let quote = quote(mint_data, current_epoch, amount)?;
    let decimals = state::decimals(mint_data)?;

    let instruction = transfer_fee::instruction::transfer_checked_with_fee(
        &spl_token_2022_interface::id(),
        source,
        mint,
        destination,
        authority,
        multisig_signers,
        amount,
        decimals,
        // Asserted against the program's own calculation.
        quote.fee,
    )?;

    Ok((instruction, quote))
}

/// **Seizure (task 5).** The same instruction, signed by the mint's
/// `PermanentDelegate` instead of the account owner.
///
/// Token-2022 accepts the permanent delegate wherever it accepts the owner, so
/// no separate instruction exists — the difference is entirely in who signs.
/// Two things worth being deliberate about:
///
/// * The transfer fee still applies. Seizing `amount` withholds `quote.fee` in
///   the destination, so a seizure that must land whole has to be grossed up,
///   or the fee recovered afterwards by the withdraw-withheld authority.
/// * A frozen account cannot be transferred out of, even by the permanent
///   delegate. Sanctioned-wallet handling therefore has to seize *before*
///   freezing, or thaw, seize, and re-freeze.
///
/// This reaches the public balance only. See [`crate::mint::gap_analysis`]
/// for why the confidential balance is out of reach.
pub fn seize_with_permanent_delegate(
    mint: &Pubkey,
    mint_data: &[u8],
    source: &Pubkey,
    destination: &Pubkey,
    permanent_delegate: &Pubkey,
    amount: u64,
    current_epoch: u64,
) -> Result<(Instruction, FeeQuote)> {
    // Fail loudly if the mint has no seizure authority at all, rather than
    // producing an instruction that will be rejected as an owner mismatch.
    let configured = state::permanent_delegate(mint_data)?;
    let configured: Option<Pubkey> = Option::from(configured.delegate);
    if configured.as_ref() != Some(permanent_delegate) {
        return Err(Error::MissingExtension(
            "PermanentDelegate (address mismatch)",
        ));
    }

    transfer_checked_with_fee(
        mint,
        mint_data,
        source,
        destination,
        permanent_delegate,
        &[],
        amount,
        current_epoch,
    )
}

/// Move fees that transfers withheld in recipient accounts back to the mint,
/// where the withdraw-withheld authority can collect them.
///
/// Permissionless on purpose: anyone may harvest, which is how a wallet closing
/// an account clears the withheld amount blocking the close.
pub fn harvest_withheld_to_mint(mint: &Pubkey, sources: &[&Pubkey]) -> Result<Instruction> {
    Ok(transfer_fee::instruction::harvest_withheld_tokens_to_mint(
        &spl_token_2022_interface::id(),
        mint,
        sources,
    )?)
}

/// Collect harvested fees from the mint into a destination account.
pub fn withdraw_withheld_from_mint(
    mint: &Pubkey,
    destination: &Pubkey,
    withdraw_withheld_authority: &Pubkey,
) -> Result<Instruction> {
    Ok(
        transfer_fee::instruction::withdraw_withheld_tokens_from_mint(
            &spl_token_2022_interface::id(),
            mint,
            destination,
            withdraw_withheld_authority,
            &[],
        )?,
    )
}
