use {
    anchor_lang::prelude::*,
    anchor_spl::{
        token_2022::{spl_token_2022::state::AccountState, thaw_account, ThawAccount, Token2022},
        token_2022_extensions::{default_account_state_update, DefaultAccountStateUpdate},
    },
};

#[derive(Accounts)]
pub struct ThawAfterKyc<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub token_account: UncheckedAccount<'info>,

    /// CHECK: validated by the token program.
    pub mint: UncheckedAccount<'info>,

    pub freeze_authority: Signer<'info>,
    pub token_program: Program<'info, Token2022>,
}

#[derive(Accounts)]
pub struct SetDefaultState<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,

    pub freeze_authority: Signer<'info>,
    pub token_program: Program<'info, Token2022>,
}

/// Thaws one account. Distinct from [`set_default_state`], which only governs
/// accounts created afterwards.
pub fn thaw(ctx: Context<ThawAfterKyc>) -> Result<()> {
    thaw_account(CpiContext::new(
        ctx.accounts.token_program.key(),
        ThawAccount {
            account: ctx.accounts.token_account.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            authority: ctx.accounts.freeze_authority.to_account_info(),
        },
    ))?;

    msg!("kyc cleared for {}", ctx.accounts.token_account.key());
    Ok(())
}

/// Leaves every existing account exactly as frozen as it was.
pub fn set_default_state(ctx: Context<SetDefaultState>, frozen: bool) -> Result<()> {
    let state = if frozen {
        AccountState::Frozen
    } else {
        AccountState::Initialized
    };

    default_account_state_update(
        CpiContext::new(
            ctx.accounts.token_program.key(),
            DefaultAccountStateUpdate {
                token_program_id: ctx.accounts.token_program.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                freeze_authority: ctx.accounts.freeze_authority.to_account_info(),
            },
        ),
        &state,
    )?;

    msg!("new accounts now open {:?}", state);
    Ok(())
}
