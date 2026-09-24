use {
    crate::{constants::REMITTANCE_EXTENSIONS, helpers::*},
    anchor_lang::prelude::*,
    anchor_spl::token_interface::{
        spl_token_2022::{extension::ExtensionType, state::Mint as MintState},
        TokenInterface,
    },
};

#[derive(Accounts)]
pub struct CreateMint<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Unchecked because Anchor's `extensions::` constraints cannot express a
    /// transfer-fee mint.
    ///
    /// CHECK: created and initialized in the handler.
    #[account(mut, signer)]
    pub mint: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

impl<'info> CreateMint<'info> {
    pub(crate) fn common(&self) -> MintParts<'info> {
        MintParts {
            payer: self.payer.to_account_info(),
            mint: self.mint.to_account_info(),
            authority: self.payer.to_account_info(),
            token_program: self.token_program.to_account_info(),
            system_program: self.system_program.to_account_info(),
        }
    }
}

pub fn handler(
    ctx: Context<CreateMint>,
    decimals: u8,
    basis_points: u16,
    maximum_fee: u64,
    name: String,
    symbol: String,
    uri: String,
) -> Result<()> {
    let space = ExtensionType::try_calculate_account_len::<MintState>(REMITTANCE_EXTENSIONS)?;
    init_mint(&ctx.accounts.common(), space, &name, &symbol, &uri, |a| {
        init_remittance_extensions(a, basis_points, maximum_fee)
    })?;
    seal_mint(&ctx.accounts.common(), decimals)?;
    write_metadata(&ctx.accounts.common(), name, symbol, uri)?;

    msg!(
        "remittance mint {} at {} bytes",
        ctx.accounts.mint.key(),
        space
    );
    Ok(())
}
