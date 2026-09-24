use {
    anchor_lang::{prelude::*, solana_program::program::invoke},
    anchor_spl::token_interface::{
        spl_token_2022::{
            extension::{
                confidential_transfer::instruction as confidential_instruction,
                StateWithExtensions,
            },
            state::Mint as MintState,
        },
        TokenInterface,
    },
};

#[derive(Accounts)]
pub struct DepositConfidential<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub token_account: UncheckedAccount<'info>,

    /// CHECK: decimals read in the handler.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    pub owner: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

/// Credits the *pending* balance. The amount is public on the way in.
pub fn handler(ctx: Context<DepositConfidential>, amount: u64) -> Result<()> {
    let decimals = {
        let data = ctx.accounts.mint.try_borrow_data()?;
        StateWithExtensions::<MintState>::unpack(&data)?
            .base
            .decimals
    };

    invoke(
        &confidential_instruction::deposit(
            ctx.accounts.token_program.key,
            &ctx.accounts.token_account.key(),
            &ctx.accounts.mint.key(),
            amount,
            decimals,
            &ctx.accounts.owner.key(),
            &[],
        )?,
        &[
            ctx.accounts.token_account.to_account_info(),
            ctx.accounts.mint.to_account_info(),
            ctx.accounts.owner.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
        ],
    )?;

    msg!("deposited {} to pending", amount);
    Ok(())
}
