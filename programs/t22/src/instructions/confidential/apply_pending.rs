use {
    crate::constants::AE_CIPHERTEXT_LEN,
    anchor_lang::{prelude::*, solana_program::program::invoke},
    anchor_spl::token_interface::{
        spl_token_2022::extension::confidential_transfer::{
            instruction as confidential_instruction, DecryptableBalance,
        },
        TokenInterface,
    },
};

#[derive(Accounts)]
pub struct ApplyPendingBalance<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub token_account: UncheckedAccount<'info>,

    pub owner: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

/// Mandatory before any transfer or withdrawal: only this moves pending
/// into the spendable available balance. The counter detects a credit that
/// landed mid-flight; it does not abort on one.
pub fn handler(
    ctx: Context<ApplyPendingBalance>,
    expected_pending_balance_credit_counter: u64,
    new_decryptable_available_balance: [u8; AE_CIPHERTEXT_LEN],
) -> Result<()> {
    let new_decryptable_available_balance: DecryptableBalance =
        new_decryptable_available_balance.into();

    invoke(
        &confidential_instruction::apply_pending_balance(
            ctx.accounts.token_program.key,
            &ctx.accounts.token_account.key(),
            expected_pending_balance_credit_counter,
            &new_decryptable_available_balance,
            &ctx.accounts.owner.key(),
            &[],
        )?,
        &[
            ctx.accounts.token_account.to_account_info(),
            ctx.accounts.owner.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
        ],
    )?;

    msg!("pending balance applied");
    Ok(())
}
