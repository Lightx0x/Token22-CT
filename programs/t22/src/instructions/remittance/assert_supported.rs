use {
    crate::{
        constants::{CONFIDENTIAL_EXTENSIONS, REMITTANCE_EXTENSIONS},
        errors::MintError,
    },
    anchor_lang::prelude::*,
    anchor_spl::token_2022::{
        spl_token_2022::{
            extension::{BaseStateWithExtensions, ExtensionType, StateWithExtensions},
            state::Mint as MintState,
        },
        Token2022,
    },
};

#[derive(Accounts)]
pub struct AssertSupportedMint<'info> {
    /// CHECK: allowlisted in the handler.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token2022>,
}

/// `InterfaceAccount<Mint>` parses the TLV region and discards it, and
/// `MintState::unpack` cannot read an extended mint at all, so extensions
/// are only visible through `StateWithExtensions` on the raw bytes.
pub fn handler(ctx: Context<AssertSupportedMint>) -> Result<()> {
    let data = ctx.accounts.mint.try_borrow_data()?;
    let mint = StateWithExtensions::<MintState>::unpack(&data)?;

    for extension in mint.get_extension_types()? {
        require!(
            REMITTANCE_EXTENSIONS.contains(&extension)
                || CONFIDENTIAL_EXTENSIONS.contains(&extension)
                || extension == ExtensionType::TokenMetadata,
            MintError::UnsupportedExtension
        );
    }

    msg!("mint {} is supported", ctx.accounts.mint.key());
    Ok(())
}
