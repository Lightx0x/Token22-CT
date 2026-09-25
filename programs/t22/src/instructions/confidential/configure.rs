use {
    crate::constants::AE_CIPHERTEXT_LEN,
    anchor_lang::{prelude::*, solana_program::program::invoke},
    anchor_spl::token_2022::{
        spl_token_2022::extension::confidential_transfer::{
            instruction as confidential_instruction, DecryptableBalance,
        },
        Token2022,
    },
    proofext::instruction::ProofLocation,
};

#[derive(Accounts)]
pub struct ConfigureConfidentialAccount<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub token_account: UncheckedAccount<'info>,

    /// CHECK: validated by the token program.
    pub mint: UncheckedAccount<'info>,

    /// A `PubkeyValidity` proof already verified by the ZK ElGamal proof
    /// program.
    ///
    /// CHECK: the token program checks its type and contents.
    pub proof_context: UncheckedAccount<'info>,

    /// Not the payer: checked against the token account's owner field.
    pub owner: Signer<'info>,
    pub token_program: Program<'info, Token2022>,
}

/// Owner-only, unlike the ATA creation that precedes it. Requires the
/// account to have been grown with `Reallocate` first.
pub fn handler(
    ctx: Context<ConfigureConfidentialAccount>,
    decryptable_zero_balance: [u8; AE_CIPHERTEXT_LEN],
    maximum_pending_balance_credit_counter: u64,
) -> Result<()> {
    let decryptable_zero_balance: DecryptableBalance = decryptable_zero_balance.into();

    invoke(
        &confidential_instruction::inner_configure_account(
            ctx.accounts.token_program.key,
            &ctx.accounts.token_account.key(),
            &ctx.accounts.mint.key(),
            &decryptable_zero_balance,
            maximum_pending_balance_credit_counter,
            &ctx.accounts.owner.key(),
            &[],
            ProofLocation::ContextStateAccount(&ctx.accounts.proof_context.key()),
        )?,
        &[
            ctx.accounts.token_account.to_account_info(),
            ctx.accounts.mint.to_account_info(),
            ctx.accounts.proof_context.to_account_info(),
            ctx.accounts.owner.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
        ],
    )?;

    msg!("configured {}", ctx.accounts.token_account.key());
    Ok(())
}
