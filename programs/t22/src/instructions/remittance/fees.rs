use {
    crate::errors::MintError,
    anchor_lang::prelude::*,
    anchor_spl::{
        token_2022::Token2022,
        token_2022_extensions::{
            harvest_withheld_tokens_to_mint, withdraw_withheld_tokens_from_mint,
            HarvestWithheldTokensToMint, WithdrawWithheldTokensFromMint,
        },
    },
};

/// The accounts to sweep arrive as `remaining_accounts`.
#[derive(Accounts)]
pub struct HarvestFees<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token2022>,
}

#[derive(Accounts)]
pub struct CollectFees<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,

    /// CHECK: validated by the token program.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,

    pub withdraw_withheld_authority: Signer<'info>,
    pub token_program: Program<'info, Token2022>,
}

/// Sweeps fees withheld on recipient accounts into the mint. Permissionless
/// on purpose: a wallet closing an account must clear its withheld balance,
/// and only the sweep can do that.
pub fn harvest<'info>(ctx: Context<'info, HarvestFees<'info>>) -> Result<()> {
    require!(!ctx.remaining_accounts.is_empty(), MintError::NoFeeSources);

    harvest_withheld_tokens_to_mint(
        CpiContext::new(
            ctx.accounts.token_program.key(),
            HarvestWithheldTokensToMint {
                token_program_id: ctx.accounts.token_program.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
            },
        ),
        ctx.remaining_accounts.to_vec(),
    )?;

    msg!("harvested from {} accounts", ctx.remaining_accounts.len());
    Ok(())
}

/// Collects harvested fees out of the mint. Not permissionless: this takes
/// the withdraw-withheld authority.
pub fn collect(ctx: Context<CollectFees>) -> Result<()> {
    withdraw_withheld_tokens_from_mint(CpiContext::new(
        ctx.accounts.token_program.key(),
        WithdrawWithheldTokensFromMint {
            token_program_id: ctx.accounts.token_program.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            destination: ctx.accounts.destination.to_account_info(),
            authority: ctx.accounts.withdraw_withheld_authority.to_account_info(),
        },
    ))?;

    msg!("fees collected to {}", ctx.accounts.destination.key());
    Ok(())
}
