use {
    crate::{errors::MintError, helpers::quote_fee},
    anchor_lang::prelude::*,
    anchor_spl::{
        token_2022::{
            spl_token_2022::{
                extension::{
                    permanent_delegate::PermanentDelegate, BaseStateWithExtensions,
                    StateWithExtensions,
                },
                state::Mint as MintState,
            },
            Token2022,
        },
        token_2022_extensions::{transfer_checked_with_fee, TransferCheckedWithFee},
    },
};

#[derive(Accounts)]
pub struct Seize<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub source: UncheckedAccount<'info>,

    /// CHECK: delegate checked in the handler.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    /// CHECK: validated by the token program.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,

    /// The account owner does not sign.
    pub permanent_delegate: Signer<'info>,
    pub token_program: Program<'info, Token2022>,
}

/// Same instruction as a normal transfer; only the signer differs. Reaches
/// the public balance only, and a frozen account blocks it.
pub fn handler(ctx: Context<Seize>, amount: u64) -> Result<()> {
    {
        let data = ctx.accounts.mint.try_borrow_data()?;
        let mint = StateWithExtensions::<MintState>::unpack(&data)?;
        let delegate = mint
            .get_extension::<PermanentDelegate>()
            .map_err(|_| error!(MintError::NoSeizureAuthority))?;
        let configured: Option<Pubkey> = Option::from(delegate.delegate);
        require_keys_eq!(
            configured.ok_or(error!(MintError::NoSeizureAuthority))?,
            ctx.accounts.permanent_delegate.key(),
            MintError::NoSeizureAuthority
        );
    }

    let (fee, decimals) = quote_fee(&ctx.accounts.mint, amount)?;
    transfer_checked_with_fee(
        CpiContext::new(
            ctx.accounts.token_program.key(),
            TransferCheckedWithFee {
                token_program_id: ctx.accounts.token_program.to_account_info(),
                source: ctx.accounts.source.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                destination: ctx.accounts.destination.to_account_info(),
                authority: ctx.accounts.permanent_delegate.to_account_info(),
            },
        ),
        amount,
        decimals,
        fee,
    )?;

    msg!("seized {} from {}", amount, ctx.accounts.source.key());
    Ok(())
}
