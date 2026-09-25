use {
    crate::helpers::quote_fee,
    anchor_lang::prelude::*,
    anchor_spl::{
        token_2022::Token2022,
        token_2022_extensions::{transfer_checked_with_fee, TransferCheckedWithFee},
    },
};

#[derive(Accounts)]
pub struct TransferWithFee<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub source: UncheckedAccount<'info>,

    /// Parsed here by `quote_fee`, which checks layout only. The `owner`
    /// constraint rejects a non-Token-2022 account before we compute a fee
    /// from its bytes; the CPI would reject it too, but later and less clearly.
    ///
    /// CHECK: parsed in the handler.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    /// CHECK: validated by the token program.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,

    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token2022>,
}

/// `TransferCheckedWithFee` makes the program recheck the fee we quote and
/// abort on a mismatch; `TransferChecked` would deduct silently.
pub fn handler(ctx: Context<TransferWithFee>, amount: u64) -> Result<()> {
    let (fee, decimals) = quote_fee(&ctx.accounts.mint, amount)?;

    transfer_checked_with_fee(
        CpiContext::new(
            ctx.accounts.token_program.key(),
            TransferCheckedWithFee {
                token_program_id: ctx.accounts.token_program.to_account_info(),
                source: ctx.accounts.source.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                destination: ctx.accounts.destination.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
        ),
        amount,
        decimals,
        fee,
    )?;

    msg!(
        "transferred {}, fee {} withheld on destination",
        amount,
        fee
    );
    Ok(())
}
