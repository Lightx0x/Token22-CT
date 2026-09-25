use {
    crate::{constants::CONFIDENTIAL_EXTENSIONS, helpers::*, instructions::remittance::CreateMint},
    anchor_lang::{prelude::*, solana_program::program::invoke},
    anchor_spl::{
        token_2022::spl_token_2022::{
            extension::{
                confidential_transfer::instruction as confidential_instruction,
                confidential_transfer_fee::instruction as confidential_fee_instruction,
                ExtensionType,
            },
            state::Mint as MintState,
        },
        token_2022_extensions::{permanent_delegate_initialize, PermanentDelegateInitialize},
    },
};

/// A new mint address, not an upgrade: extensions initialize only before
/// `InitializeMint`, so holders migrate. `auto_approve_new_accounts: false`
/// is approve_policy = manual.
#[allow(clippy::too_many_arguments)]
pub fn handler(
    ctx: Context<CreateMint>,
    decimals: u8,
    basis_points: u16,
    maximum_fee: u64,
    withdraw_withheld_elgamal: [u8; 32],
    auditor_elgamal: Option<[u8; 32]>,
    name: String,
    symbol: String,
    uri: String,
) -> Result<()> {
    let space = ExtensionType::try_calculate_account_len::<MintState>(CONFIDENTIAL_EXTENSIONS)?;
    init_mint(&ctx.accounts.common(), space, &name, &symbol, &uri, |a| {
        init_remittance_extensions(a, basis_points, maximum_fee)?;

        permanent_delegate_initialize(
            CpiContext::new(
                a.token_program.key(),
                PermanentDelegateInitialize {
                    token_program_id: a.token_program.clone(),
                    mint: a.mint.clone(),
                },
            ),
            &a.authority.key(),
        )?;

        // anchor-spl ships no CPI helper for these two.
        invoke(
            &confidential_instruction::initialize_mint(
                a.token_program.key,
                a.mint.key,
                Some(a.authority.key()),
                false,
                auditor_elgamal.map(Into::into),
            )?,
            &[a.mint.clone(), a.token_program.clone()],
        )?;

        // Must follow ConfidentialTransferMint, which it checks exists.
        invoke(
            &confidential_fee_instruction::initialize_confidential_transfer_fee_config(
                a.token_program.key,
                a.mint.key,
                Some(a.authority.key()),
                &withdraw_withheld_elgamal.into(),
            )?,
            &[a.mint.clone(), a.token_program.clone()],
        )?;
        Ok(())
    })?;
    seal_mint(&ctx.accounts.common(), decimals)?;
    write_metadata(&ctx.accounts.common(), name, symbol, uri)?;

    msg!(
        "confidential mint {} at {} bytes",
        ctx.accounts.mint.key(),
        space
    );
    Ok(())
}
