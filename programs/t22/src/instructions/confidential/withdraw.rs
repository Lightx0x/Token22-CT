use {
    crate::{constants::AE_CIPHERTEXT_LEN, errors::MintError},
    anchor_lang::{prelude::*, solana_program::program::invoke},
    anchor_spl::token_interface::{
        spl_token_2022::{
            extension::{
                confidential_transfer::{
                    instruction as confidential_instruction, ConfidentialTransferAccount,
                    DecryptableBalance, EncryptedBalance,
                },
                BaseStateWithExtensions, StateWithExtensions,
            },
            state::{Account as TokenAccountState, Mint as MintState},
        },
        TokenInterface,
    },
    proofext::instruction::ProofLocation,
};

#[derive(Accounts)]
pub struct WithdrawConfidential<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub token_account: UncheckedAccount<'info>,

    /// CHECK: decimals read in the handler.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    /// CHECK: the token program checks its type and contents.
    pub equality_proof: UncheckedAccount<'info>,

    /// CHECK: the token program checks its type and contents.
    pub range_proof: UncheckedAccount<'info>,

    pub owner: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

/// Spends the available balance, so apply pending first or the equality
/// proof is built against a stale ciphertext.
pub fn handler(
    ctx: Context<WithdrawConfidential>,
    amount: u64,
    new_decryptable_available_balance: [u8; AE_CIPHERTEXT_LEN],
) -> Result<()> {
    let new_decryptable_available_balance: DecryptableBalance =
        new_decryptable_available_balance.into();
    let decimals = {
        let data = ctx.accounts.mint.try_borrow_data()?;
        StateWithExtensions::<MintState>::unpack(&data)?
            .base
            .decimals
    };

    // ApplyPendingBalance zeroes both halves, so a non-zero one means the
    // equality proof was built against a ciphertext the chain has moved
    // past. Refuse rather than emit a transfer that fails opaquely.
    {
        let data = ctx.accounts.token_account.try_borrow_data()?;
        let account = StateWithExtensions::<TokenAccountState>::unpack(&data)?;
        let confidential = account.get_extension::<ConfidentialTransferAccount>()?;
        require!(
            confidential.pending_balance_lo == EncryptedBalance::default()
                && confidential.pending_balance_hi == EncryptedBalance::default(),
            MintError::PendingBalanceNotApplied
        );
    }

    invoke(
        &confidential_instruction::inner_withdraw(
            ctx.accounts.token_program.key,
            &ctx.accounts.token_account.key(),
            &ctx.accounts.mint.key(),
            amount,
            decimals,
            &new_decryptable_available_balance,
            &ctx.accounts.owner.key(),
            &[],
            ProofLocation::ContextStateAccount(&ctx.accounts.equality_proof.key()),
            ProofLocation::ContextStateAccount(&ctx.accounts.range_proof.key()),
        )?,
        &[
            ctx.accounts.token_account.to_account_info(),
            ctx.accounts.mint.to_account_info(),
            ctx.accounts.equality_proof.to_account_info(),
            ctx.accounts.range_proof.to_account_info(),
            ctx.accounts.owner.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
        ],
    )?;

    msg!("withdrew {} to the public balance", amount);
    Ok(())
}
