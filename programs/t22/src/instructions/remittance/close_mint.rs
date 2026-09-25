use {
    anchor_lang::prelude::*,
    anchor_spl::token_2022::{close_account, CloseAccount, Token2022},
};

#[derive(Accounts)]
pub struct CloseMint<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,

    /// CHECK: receives the reclaimed rent.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,

    pub close_authority: Signer<'info>,
    pub token_program: Program<'info, Token2022>,
}

/// Decommissions the mint and reclaims its rent. Token-2022 allows this
/// only at zero supply, which is what makes it the last step of a
/// v1 -> v2 migration.
pub fn handler(ctx: Context<CloseMint>) -> Result<()> {
    close_account(CpiContext::new(
        ctx.accounts.token_program.key(),
        CloseAccount {
            account: ctx.accounts.mint.to_account_info(),
            destination: ctx.accounts.destination.to_account_info(),
            authority: ctx.accounts.close_authority.to_account_info(),
        },
    ))?;

    msg!("mint {} closed", ctx.accounts.mint.key());
    Ok(())
}
