use anchor_lang::prelude::*;

pub mod constants;
pub mod errors;
pub mod helpers;
pub mod instructions;

pub use constants::*;
pub use errors::*;
pub use instructions::*;

declare_id!("GWiW3NmAppZ91sGyjPN8QGpBwEX4avcUMGZmGKiExBmx");

#[program]
pub mod t22 {
    use super::*;

    pub fn create_remittance_mint(
        ctx: Context<CreateMint>,
        decimals: u8,
        basis_points: u16,
        maximum_fee: u64,
        name: String,
        symbol: String,
        uri: String,
    ) -> Result<()> {
        remittance::create_mint::handler(ctx, decimals, basis_points, maximum_fee, name, symbol, uri)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_confidential_mint(
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
        confidential::create_mint::handler(
            ctx,
            decimals,
            basis_points,
            maximum_fee,
            withdraw_withheld_elgamal,
            auditor_elgamal,
            name,
            symbol,
            uri,
        )
    }

    pub fn transfer_with_fee(ctx: Context<TransferWithFee>, amount: u64) -> Result<()> {
        remittance::transfer::handler(ctx, amount)
    }

    pub fn seize(ctx: Context<Seize>, amount: u64) -> Result<()> {
        confidential::seize::handler(ctx, amount)
    }

    pub fn thaw_after_kyc(ctx: Context<ThawAfterKyc>) -> Result<()> {
        remittance::kyc::thaw(ctx)
    }

    pub fn set_default_account_state(ctx: Context<SetDefaultState>, frozen: bool) -> Result<()> {
        remittance::kyc::set_default_state(ctx, frozen)
    }

    pub fn assert_supported_mint(ctx: Context<AssertSupportedMint>) -> Result<()> {
        remittance::assert_supported::handler(ctx)
    }

    pub fn harvest_fees<'info>(ctx: Context<'info, HarvestFees<'info>>) -> Result<()> {
        remittance::fees::harvest(ctx)
    }

    pub fn collect_fees(ctx: Context<CollectFees>) -> Result<()> {
        remittance::fees::collect(ctx)
    }

    pub fn close_mint(ctx: Context<CloseMint>) -> Result<()> {
        remittance::close_mint::handler(ctx)
    }

    pub fn configure_confidential_account(
        ctx: Context<ConfigureConfidentialAccount>,
        decryptable_zero_balance: [u8; AE_CIPHERTEXT_LEN],
        maximum_pending_balance_credit_counter: u64,
    ) -> Result<()> {
        confidential::configure::handler(
            ctx,
            decryptable_zero_balance,
            maximum_pending_balance_credit_counter,
        )
    }

    pub fn approve_confidential_account(ctx: Context<ApproveConfidentialAccount>) -> Result<()> {
        confidential::approve::handler(ctx)
    }

    pub fn deposit_confidential(ctx: Context<DepositConfidential>, amount: u64) -> Result<()> {
        confidential::deposit::handler(ctx, amount)
    }

    pub fn apply_pending_balance(
        ctx: Context<ApplyPendingBalance>,
        expected_pending_balance_credit_counter: u64,
        new_decryptable_available_balance: [u8; AE_CIPHERTEXT_LEN],
    ) -> Result<()> {
        confidential::apply_pending::handler(
            ctx,
            expected_pending_balance_credit_counter,
            new_decryptable_available_balance,
        )
    }

    pub fn transfer_confidential<'info>(
        ctx: Context<'info, TransferConfidential<'info>>,
        new_source_decryptable_available_balance: [u8; AE_CIPHERTEXT_LEN],
        auditor_ciphertext_lo: [u8; ELGAMAL_CIPHERTEXT_LEN],
        auditor_ciphertext_hi: [u8; ELGAMAL_CIPHERTEXT_LEN],
    ) -> Result<()> {
        confidential::transfer::handler(
            ctx,
            new_source_decryptable_available_balance,
            auditor_ciphertext_lo,
            auditor_ciphertext_hi,
        )
    }

    pub fn withdraw_confidential(
        ctx: Context<WithdrawConfidential>,
        amount: u64,
        new_decryptable_available_balance: [u8; AE_CIPHERTEXT_LEN],
    ) -> Result<()> {
        confidential::withdraw::handler(ctx, amount, new_decryptable_available_balance)
    }
}
