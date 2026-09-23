//! **Task 3: every read of a mint or token account goes through this module.**
//!
//! A Token-2022 account is a base struct followed by a TLV region. Calling
//! `Mint::unpack(data)` / `Account::unpack(data)` on it — the "raw unpack" that
//! works fine for the original Token program — either fails outright (the
//! length no longer matches `Mint::LEN`) or, worse, silently succeeds on a
//! prefix and hides every extension. `StateWithExtensions` parses the base
//! state *and* the TLV region, so it is the only reader used anywhere in this
//! crate.
//!
//! The accessors below return owned copies of the (`Pod`, `Copy`) extension
//! structs rather than borrows, so callers are not forced to keep the
//! `StateWithExtensions` view — and therefore the account buffer — alive.

use {
    crate::error::{Error, Result},
    spl_token_2022_interface::{
        extension::{
            confidential_transfer::{ConfidentialTransferAccount, ConfidentialTransferMint},
            confidential_transfer_fee::ConfidentialTransferFeeConfig,
            default_account_state::DefaultAccountState,
            metadata_pointer::MetadataPointer,
            mint_close_authority::MintCloseAuthority,
            permanent_delegate::PermanentDelegate,
            transfer_fee::TransferFeeConfig,
            BaseStateWithExtensions, Extension, ExtensionType, StateWithExtensions,
        },
        state::{Account, AccountState, Mint},
    },
};

/// Parse a mint account, base state plus TLV region.
pub fn mint(data: &[u8]) -> Result<StateWithExtensions<'_, Mint>> {
    Ok(StateWithExtensions::<Mint>::unpack(data)?)
}

/// Parse a token account, base state plus TLV region.
pub fn token_account(data: &[u8]) -> Result<StateWithExtensions<'_, Account>> {
    Ok(StateWithExtensions::<Account>::unpack(data)?)
}

/// Pull one extension out of a mint, copying it out of the borrowed buffer.
///
/// `name` is only used to make the error message readable.
fn mint_extension<E: Extension + bytemuck::Pod>(data: &[u8], name: &'static str) -> Result<E> {
    mint(data)?
        .get_extension::<E>()
        .copied()
        .map_err(|_| Error::MissingExtension(name))
}

/// Pull one extension out of a token account.
fn account_extension<E: Extension + bytemuck::Pod>(data: &[u8], name: &'static str) -> Result<E> {
    token_account(data)?
        .get_extension::<E>()
        .copied()
        .map_err(|_| Error::MissingExtension(name))
}

pub fn transfer_fee_config(mint_data: &[u8]) -> Result<TransferFeeConfig> {
    mint_extension(mint_data, "TransferFeeConfig")
}

pub fn metadata_pointer(mint_data: &[u8]) -> Result<MetadataPointer> {
    mint_extension(mint_data, "MetadataPointer")
}

pub fn default_account_state(mint_data: &[u8]) -> Result<DefaultAccountState> {
    mint_extension(mint_data, "DefaultAccountState")
}

pub fn mint_close_authority(mint_data: &[u8]) -> Result<MintCloseAuthority> {
    mint_extension(mint_data, "MintCloseAuthority")
}

pub fn permanent_delegate(mint_data: &[u8]) -> Result<PermanentDelegate> {
    mint_extension(mint_data, "PermanentDelegate")
}

pub fn confidential_transfer_mint(mint_data: &[u8]) -> Result<ConfidentialTransferMint> {
    mint_extension(mint_data, "ConfidentialTransferMint")
}

pub fn confidential_transfer_fee_config(mint_data: &[u8]) -> Result<ConfidentialTransferFeeConfig> {
    mint_extension(mint_data, "ConfidentialTransferFeeConfig")
}

pub fn confidential_transfer_account(account_data: &[u8]) -> Result<ConfidentialTransferAccount> {
    account_extension(account_data, "ConfidentialTransferAccount")
}

/// `true` when the mint charges a protocol fee on transfers.
///
/// This is the switch that decides which confidential transfer variant is
/// legal for the mint — see [`crate::confidential::transfer`].
pub fn has_transfer_fee(mint_data: &[u8]) -> Result<bool> {
    Ok(mint(mint_data)?
        .get_extension::<TransferFeeConfig>()
        .is_ok())
}

/// Decimals, read from the mint instead of trusted from the caller.
///
/// Every `*_checked` instruction re-verifies this on chain; passing a stale
/// constant is how callers get `MintDecimalsMismatch`.
pub fn decimals(mint_data: &[u8]) -> Result<u8> {
    Ok(mint(mint_data)?.base.decimals)
}

/// Which extensions a live mint actually carries.
///
/// Useful when re-issuing: it is the checklist of what v2 must carry forward.
pub fn extension_types(mint_data: &[u8]) -> Result<Vec<ExtensionType>> {
    Ok(mint(mint_data)?.get_extension_types()?)
}

/// `true` when a token account is frozen — the state new accounts start in
/// while `DefaultAccountState` is `Frozen`.
pub fn is_frozen(account_data: &[u8]) -> Result<bool> {
    Ok(token_account(account_data)?.base.state == AccountState::Frozen)
}
