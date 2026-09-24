use {
    crate::{
        constants::{AE_CIPHERTEXT_LEN, ELGAMAL_CIPHERTEXT_LEN},
        errors::MintError,
    },
    anchor_lang::{prelude::*, solana_program::program::invoke},
    anchor_spl::token_interface::{
        spl_token_2022::extension::confidential_transfer::{
            instruction as confidential_instruction, DecryptableBalance, EncryptedBalance,
        },
        TokenInterface,
    },
    proofext::instruction::ProofLocation,
};

/// The five proof contexts ride in `remaining_accounts`, in the order
/// `TransferWithFee` expects: equality, amount validity, fee percentage-with-cap,
/// fee validity, range.
#[derive(Accounts)]
pub struct TransferConfidential<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub source: UncheckedAccount<'info>,

    /// CHECK: validated by the token program.
    pub mint: UncheckedAccount<'info>,

    /// CHECK: validated by the token program.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,

    pub owner: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

/// `TransferWithFee`, not `Transfer`: the processor branches on
/// `TransferFeeConfig` and this mint has one, which costs five proofs
/// instead of three.
pub fn handler<'info>(
    ctx: Context<'info, TransferConfidential<'info>>,
    new_source_decryptable_available_balance: [u8; AE_CIPHERTEXT_LEN],
    auditor_ciphertext_lo: [u8; ELGAMAL_CIPHERTEXT_LEN],
    auditor_ciphertext_hi: [u8; ELGAMAL_CIPHERTEXT_LEN],
) -> Result<()> {
    let new_source_decryptable_available_balance: DecryptableBalance =
        new_source_decryptable_available_balance.into();
    let auditor_ciphertext_lo: EncryptedBalance = auditor_ciphertext_lo.into();
    let auditor_ciphertext_hi: EncryptedBalance = auditor_ciphertext_hi.into();

    let proofs = &ctx.remaining_accounts;
    require!(proofs.len() == 5, MintError::MissingProofContexts);

    let instruction = confidential_instruction::inner_transfer_with_fee(
        ctx.accounts.token_program.key,
        &ctx.accounts.source.key(),
        &ctx.accounts.mint.key(),
        &ctx.accounts.destination.key(),
        &new_source_decryptable_available_balance,
        &auditor_ciphertext_lo,
        &auditor_ciphertext_hi,
        &ctx.accounts.owner.key(),
        &[],
        ProofLocation::ContextStateAccount(proofs[0].key),
        ProofLocation::ContextStateAccount(proofs[1].key),
        ProofLocation::ContextStateAccount(proofs[2].key),
        ProofLocation::ContextStateAccount(proofs[3].key),
        ProofLocation::ContextStateAccount(proofs[4].key),
    )?;

    let mut infos = vec![
        ctx.accounts.source.to_account_info(),
        ctx.accounts.mint.to_account_info(),
        ctx.accounts.destination.to_account_info(),
    ];
    infos.extend(proofs.iter().cloned());
    infos.push(ctx.accounts.owner.to_account_info());
    infos.push(ctx.accounts.token_program.to_account_info());

    invoke(&instruction, &infos)?;

    msg!("confidential transfer settled");
    Ok(())
}
