use {
    crate::errors::MintError,
    anchor_lang::prelude::*,
    anchor_spl::token_interface::spl_token_2022::{
        extension::{transfer_fee::TransferFeeConfig, BaseStateWithExtensions, StateWithExtensions},
        state::Mint as MintState,
    },
};

/// Reads the live schedule for the current epoch rather than a cached rate:
/// the extension holds two, and the newer one activates on an epoch boundary.
pub fn quote_fee(mint: &UncheckedAccount<'_>, amount: u64) -> Result<(u64, u8)> {
    let data = mint.try_borrow_data()?;
    let parsed = StateWithExtensions::<MintState>::unpack(&data)?;
    let config = parsed
        .get_extension::<TransferFeeConfig>()
        .map_err(|_| error!(MintError::MissingTransferFee))?;

    let fee = config
        .calculate_epoch_fee(Clock::get()?.epoch, amount)
        .ok_or(error!(MintError::FeeOverflow))?;

    Ok((fee, parsed.base.decimals))
}
