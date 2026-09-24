use {
    anchor_lang::{prelude::*, solana_program::program::invoke},
    anchor_spl::token_interface::{
        spl_token_2022::extension::confidential_transfer::instruction as confidential_instruction,
        TokenInterface,
    },
};

#[derive(Accounts)]
pub struct ApproveConfidentialAccount<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub token_account: UncheckedAccount<'info>,

    /// CHECK: validated by the token program.
    pub mint: UncheckedAccount<'info>,

    /// The mint's confidential-transfer authority, not the account owner.
    pub authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

/// Required because the mint uses approve_policy = manual.
pub fn handler(ctx: Context<ApproveConfidentialAccount>) -> Result<()> {
    invoke(
        &confidential_instruction::approve_account(
            ctx.accounts.token_program.key,
            &ctx.accounts.token_account.key(),
            &ctx.accounts.mint.key(),
            &ctx.accounts.authority.key(),
            &[],
        )?,
        &[
            ctx.accounts.token_account.to_account_info(),
            ctx.accounts.mint.to_account_info(),
            ctx.accounts.authority.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
        ],
    )?;

    msg!("approved {}", ctx.accounts.token_account.key());
    Ok(())
}
