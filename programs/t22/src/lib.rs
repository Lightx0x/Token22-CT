use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_spl::token_interface::{
    close_account, default_account_state_initialize, default_account_state_update,
    harvest_withheld_tokens_to_mint, initialize_mint2, metadata_pointer_initialize,
    mint_close_authority_initialize, permanent_delegate_initialize, spl_token_2022, thaw_account,
    token_metadata_initialize, transfer_checked_with_fee, transfer_fee_initialize,
    withdraw_withheld_tokens_from_mint, CloseAccount, DefaultAccountStateInitialize,
    DefaultAccountStateUpdate, HarvestWithheldTokensToMint, InitializeMint2,
    MetadataPointerInitialize, MintCloseAuthorityInitialize, PermanentDelegateInitialize,
    ThawAccount, TokenInterface, TokenMetadataInitialize, TransferCheckedWithFee,
    TransferFeeInitialize, WithdrawWithheldTokensFromMint,
};
use proofext::instruction::ProofLocation;
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            instruction as confidential_instruction, ConfidentialTransferAccount,
            DecryptableBalance, EncryptedBalance,
        },
        confidential_transfer_fee::instruction as confidential_fee_instruction,
        permanent_delegate::PermanentDelegate,
        transfer_fee::TransferFeeConfig,
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    state::{Account as TokenAccountState, AccountState, Mint as MintState},
};
use spl_token_metadata_interface::state::TokenMetadata;
use spl_type_length_value::variable_len_pack::VariableLenPack;

declare_id!("GWiW3NmAppZ91sGyjPN8QGpBwEX4avcUMGZmGKiExBmx");

/// Instruction args are Borsh-encoded; the pod ciphertext types are not Borsh,
/// so they cross the boundary as raw bytes.
pub const AE_CIPHERTEXT_LEN: usize = 36;
pub const ELGAMAL_CIPHERTEXT_LEN: usize = 64;

const REMITTANCE_EXTENSIONS: &[ExtensionType] = &[
    ExtensionType::TransferFeeConfig,
    ExtensionType::MetadataPointer,
    ExtensionType::DefaultAccountState,
    ExtensionType::MintCloseAuthority,
];

/// `ConfidentialTransferFeeConfig` is forced: Token-2022 rejects
/// `TransferFeeConfig + ConfidentialTransferMint` without it.
const CONFIDENTIAL_EXTENSIONS: &[ExtensionType] = &[
    ExtensionType::TransferFeeConfig,
    ExtensionType::MetadataPointer,
    ExtensionType::DefaultAccountState,
    ExtensionType::MintCloseAuthority,
    ExtensionType::PermanentDelegate,
    ExtensionType::ConfidentialTransferMint,
    ExtensionType::ConfidentialTransferFeeConfig,
];

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

    /// A new mint address, not an upgrade: extensions initialize only before
    /// `InitializeMint`, so holders migrate. `auto_approve_new_accounts: false`
    /// is approve_policy = manual.
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

    /// `TransferCheckedWithFee` makes the program recheck the fee we quote and
    /// abort on a mismatch; `TransferChecked` would deduct silently.
    pub fn transfer_with_fee(ctx: Context<TransferWithFee>, amount: u64) -> Result<()> {
        let (fee, decimals) = quote_fee(&ctx.accounts.mint, amount)?;

        transfer_checked_with_fee(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                TransferCheckedWithFee {
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                    source: ctx.accounts.source.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    destination: ctx.accounts.destination.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount,
            decimals,
            fee,
        )?;

        msg!(
            "transferred {}, fee {} withheld on destination",
            amount,
            fee
        );
        Ok(())
    }

    /// Same instruction as a normal transfer; only the signer differs. Reaches
    /// the public balance only, and a frozen account blocks it.
    pub fn seize(ctx: Context<Seize>, amount: u64) -> Result<()> {
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

    /// Thaws one account. Distinct from [`t22::set_default_account_state`],
    /// which only governs accounts created afterwards.
    pub fn thaw_after_kyc(ctx: Context<ThawAfterKyc>) -> Result<()> {
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
    pub fn set_default_account_state(ctx: Context<SetDefaultState>, frozen: bool) -> Result<()> {
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

    /// `InterfaceAccount<Mint>` parses the TLV region and discards it, and
    /// `MintState::unpack` cannot read an extended mint at all, so extensions
    /// are only visible through `StateWithExtensions` on the raw bytes.
    pub fn assert_supported_mint(ctx: Context<AssertSupportedMint>) -> Result<()> {
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

    /// Sweeps fees withheld on recipient accounts into the mint. Permissionless
    /// on purpose: a wallet closing an account must clear its withheld balance,
    /// and only the sweep can do that.
    pub fn harvest_fees<'info>(ctx: Context<'info, HarvestFees<'info>>) -> Result<()> {
        require!(!ctx.remaining_accounts.is_empty(), MintError::NoFeeSources);

        harvest_withheld_tokens_to_mint(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                HarvestWithheldTokensToMint {
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            ctx.remaining_accounts.to_vec(),
        )?;

        msg!("harvested from {} accounts", ctx.remaining_accounts.len());
        Ok(())
    }

    /// Collects harvested fees out of the mint. Not permissionless: this takes
    /// the withdraw-withheld authority.
    pub fn collect_fees(ctx: Context<CollectFees>) -> Result<()> {
        withdraw_withheld_tokens_from_mint(CpiContext::new(
            ctx.accounts.token_program.key(),
            WithdrawWithheldTokensFromMint {
                token_program_id: ctx.accounts.token_program.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                destination: ctx.accounts.destination.to_account_info(),
                authority: ctx.accounts.withdraw_withheld_authority.to_account_info(),
            },
        ))?;

        msg!("fees collected to {}", ctx.accounts.destination.key());
        Ok(())
    }

    /// Decommissions the mint and reclaims its rent. Token-2022 allows this
    /// only at zero supply, which is what makes it the last step of a
    /// v1 -> v2 migration.
    pub fn close_mint(ctx: Context<CloseMint>) -> Result<()> {
        close_account(CpiContext::new(
            ctx.accounts.token_program.key(),
            CloseAccount {
                account: ctx.accounts.mint.to_account_info(),
                destination: ctx.accounts.destination.to_account_info(),
                authority: ctx.accounts.close_authority.to_account_info(),
            },
        ))?;

        msg!("mint {} closed", ctx.accounts.mint.key());
        Ok(())
    }

    /// Owner-only, unlike the ATA creation that precedes it. Requires the
    /// account to have been grown with `Reallocate` first.
    pub fn configure_confidential_account(
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

    /// Required because the mint uses approve_policy = manual.
    pub fn approve_confidential_account(ctx: Context<ApproveConfidentialAccount>) -> Result<()> {
        invoke(
            &confidential_instruction::approve_account(
                ctx.accounts.token_program.key,
                &ctx.accounts.token_account.key(),
                &ctx.accounts.mint.key(),
                &ctx.accounts.authority.key(),
                &[],
            )?,
            &[
                ctx.accounts.token_account.to_account_info(),
                ctx.accounts.mint.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;

        msg!("approved {}", ctx.accounts.token_account.key());
        Ok(())
    }

    /// Credits the *pending* balance. The amount is public on the way in.
    pub fn deposit_confidential(ctx: Context<DepositConfidential>, amount: u64) -> Result<()> {
        let decimals = {
            let data = ctx.accounts.mint.try_borrow_data()?;
            StateWithExtensions::<MintState>::unpack(&data)?
                .base
                .decimals
        };

        invoke(
            &confidential_instruction::deposit(
                ctx.accounts.token_program.key,
                &ctx.accounts.token_account.key(),
                &ctx.accounts.mint.key(),
                amount,
                decimals,
                &ctx.accounts.owner.key(),
                &[],
            )?,
            &[
                ctx.accounts.token_account.to_account_info(),
                ctx.accounts.mint.to_account_info(),
                ctx.accounts.owner.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;

        msg!("deposited {} to pending", amount);
        Ok(())
    }

    /// Mandatory before any transfer or withdrawal: only this moves pending
    /// into the spendable available balance. The counter detects a credit that
    /// landed mid-flight; it does not abort on one.
    pub fn apply_pending_balance(
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

    /// `TransferWithFee`, not `Transfer`: the processor branches on
    /// `TransferFeeConfig` and this mint has one, which costs five proofs
    /// instead of three.
    pub fn transfer_confidential<'info>(
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

    /// Spends the available balance, so apply pending first or the equality
    /// proof is built against a stale ciphertext.
    pub fn withdraw_confidential(
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
}

struct MintParts<'info> {
    payer: AccountInfo<'info>,
    mint: AccountInfo<'info>,
    authority: AccountInfo<'info>,
    token_program: AccountInfo<'info>,
    system_program: AccountInfo<'info>,
}

impl<'info> CreateMint<'info> {
    fn common(&self) -> MintParts<'info> {
        MintParts {
            payer: self.payer.to_account_info(),
            mint: self.mint.to_account_info(),
            authority: self.payer.to_account_info(),
            token_program: self.token_program.to_account_info(),
            system_program: self.system_program.to_account_info(),
        }
    }
}

/// Allocates at the full extended length, then runs the extension
/// initializers. Metadata is variable length, so it is excluded from `space`
/// and its rent is funded up front for the realloc in [`write_metadata`].
fn init_mint<'info>(
    a: &MintParts<'info>,
    space: usize,
    name: &str,
    symbol: &str,
    uri: &str,
    extensions: impl FnOnce(&MintParts<'info>) -> Result<()>,
) -> Result<()> {
    // Token-2022 stores a variable-length extension behind its own u16 type and
    // u16 length. `TokenMetadata::tlv_size_of` sizes for the generic TLV header
    // instead, which is 8 bytes larger and over-funds the mint.
    let metadata_space = TokenMetadata {
        name: name.to_string(),
        symbol: symbol.to_string(),
        uri: uri.to_string(),
        ..Default::default()
    }
    .get_packed_len()?
        + std::mem::size_of::<ExtensionType>()
        + std::mem::size_of::<u16>();
    let lamports = Rent::get()?.minimum_balance(space + metadata_space);

    anchor_lang::system_program::create_account(
        CpiContext::new(
            a.system_program.key(),
            anchor_lang::system_program::CreateAccount {
                from: a.payer.clone(),
                to: a.mint.clone(),
            },
        ),
        lamports,
        space as u64,
        a.token_program.key,
    )?;

    extensions(a)
}

fn init_remittance_extensions(
    a: &MintParts<'_>,
    basis_points: u16,
    maximum_fee: u64,
) -> Result<()> {
    transfer_fee_initialize(
        CpiContext::new(
            a.token_program.key(),
            TransferFeeInitialize {
                token_program_id: a.token_program.clone(),
                mint: a.mint.clone(),
            },
        ),
        Some(&a.authority.key()),
        Some(&a.authority.key()),
        basis_points,
        maximum_fee,
    )?;

    // Pointed at the mint itself, so the metadata needs no second account.
    metadata_pointer_initialize(
        CpiContext::new(
            a.token_program.key(),
            MetadataPointerInitialize {
                token_program_id: a.token_program.clone(),
                mint: a.mint.clone(),
            },
        ),
        Some(a.authority.key()),
        Some(a.mint.key()),
    )?;

    // The KYC gate: new accounts open frozen.
    default_account_state_initialize(
        CpiContext::new(
            a.token_program.key(),
            DefaultAccountStateInitialize {
                token_program_id: a.token_program.clone(),
                mint: a.mint.clone(),
            },
        ),
        &AccountState::Frozen,
    )?;

    mint_close_authority_initialize(
        CpiContext::new(
            a.token_program.key(),
            MintCloseAuthorityInitialize {
                token_program_id: a.token_program.clone(),
                mint: a.mint.clone(),
            },
        ),
        Some(&a.authority.key()),
    )
}

/// Seals the extension set. The freeze authority is not optional:
/// `DefaultAccountState` is administered by it.
fn seal_mint(a: &MintParts<'_>, decimals: u8) -> Result<()> {
    initialize_mint2(
        CpiContext::new(
            a.token_program.key(),
            InitializeMint2 {
                mint: a.mint.clone(),
            },
        ),
        decimals,
        &a.authority.key(),
        Some(&a.authority.key()),
    )
}

/// Not an extension initializer: it runs after `InitializeMint2` and needs a
/// mint-authority signature.
fn write_metadata(a: &MintParts<'_>, name: String, symbol: String, uri: String) -> Result<()> {
    token_metadata_initialize(
        CpiContext::new(
            a.token_program.key(),
            TokenMetadataInitialize {
                program_id: a.token_program.clone(),
                metadata: a.mint.clone(),
                update_authority: a.authority.clone(),
                mint_authority: a.authority.clone(),
                mint: a.mint.clone(),
            },
        ),
        name,
        symbol,
        uri,
    )
}

/// Reads the live schedule for the current epoch rather than a cached rate:
/// the extension holds two, and the newer one activates on an epoch boundary.
fn quote_fee(mint: &UncheckedAccount<'_>, amount: u64) -> Result<(u64, u8)> {
    let data = mint.try_borrow_data()?;
    let parsed = StateWithExtensions::<MintState>::unpack(&data)?;
    let config = parsed
        .get_extension::<TransferFeeConfig>()
        .map_err(|_| error!(MintError::MissingTransferFee))?;

    let fee = config
        .calculate_epoch_fee(Clock::get()?.epoch, amount)
        .ok_or(error!(MintError::FeeOverflow))?;

    Ok((fee, parsed.base.decimals))
}

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

#[derive(Accounts)]
pub struct TransferWithFee<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub source: UncheckedAccount<'info>,

    /// The `owner` constraint is load-bearing: `StateWithExtensions::unpack`
    /// validates layout only.
    ///
    /// CHECK: parsed in the handler.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    /// CHECK: validated by the token program.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,

    pub authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

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
    pub token_program: Interface<'info, TokenInterface>,
}

/// The accounts to sweep arrive as `remaining_accounts`.
#[derive(Accounts)]
pub struct HarvestFees<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct CollectFees<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,

    /// CHECK: validated by the token program.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,

    pub withdraw_withheld_authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct CloseMint<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,

    /// CHECK: receives the reclaimed rent.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,

    pub close_authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct ThawAfterKyc<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub token_account: UncheckedAccount<'info>,

    /// CHECK: validated by the token program.
    pub mint: UncheckedAccount<'info>,

    pub freeze_authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct SetDefaultState<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,

    pub freeze_authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct AssertSupportedMint<'info> {
    /// CHECK: allowlisted in the handler.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
}

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
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct ApproveConfidentialAccount<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub token_account: UncheckedAccount<'info>,

    /// CHECK: validated by the token program.
    pub mint: UncheckedAccount<'info>,

    /// The mint's confidential-transfer authority, not the account owner.
    pub authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct DepositConfidential<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub token_account: UncheckedAccount<'info>,

    /// CHECK: decimals read in the handler.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    pub owner: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct ApplyPendingBalance<'info> {
    /// CHECK: validated by the token program.
    #[account(mut)]
    pub token_account: UncheckedAccount<'info>,

    pub owner: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

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

#[error_code]
pub enum MintError {
    #[msg("mint carries an extension this program has not been written to handle")]
    UnsupportedExtension,
    #[msg("mint does not charge a transfer fee")]
    MissingTransferFee,
    #[msg("transfer fee calculation overflowed")]
    FeeOverflow,
    #[msg("mint has no permanent delegate, or the signer is not it")]
    NoSeizureAuthority,
    #[msg("a confidential transfer with a fee needs five proof context accounts")]
    MissingProofContexts,
    #[msg("no accounts were supplied to harvest fees from")]
    NoFeeSources,
    #[msg("apply the pending balance before withdrawing")]
    PendingBalanceNotApplied,
}
