//! **Task 1 and Task 5: creating the two mints.**
//!
//! The hard rule that shapes both builders: a Token-2022 extension can only be
//! initialised on an *uninitialised* mint. So every mint creation is one
//! transaction laid out as
//!
//! 1. `SystemProgram::CreateAccount` — with the size the full extension set
//!    will need, computed by [`ExtensionType::try_calculate_account_len`]
//!    rather than by hand;
//! 2. one `Initialize*` instruction per extension, in any order among
//!    themselves but **all before** step 3;
//! 3. `InitializeMint2`, which seals the extension set forever.
//!
//! Getting the size wrong in step 1 fails in step 2 and cannot be repaired
//! afterwards: the account is already owned by the token program with a fixed
//! length, and only `Reallocate` (token accounts, not mints) can grow it.

use {
    crate::{error::Result, plan::Step, state},
    solana_instruction::Instruction,
    solana_pubkey::Pubkey,
    solana_rent::Rent,
    solana_system_interface::instruction as system_instruction,
    solana_zk_sdk::encryption::pod::elgamal::PodElGamalPubkey,
    spl_token_2022_interface::{
        extension::{
            confidential_transfer, confidential_transfer_fee, default_account_state,
            metadata_pointer, transfer_fee, ExtensionType,
        },
        instruction as token_instruction,
        state::{AccountState, Mint},
    },
    spl_token_metadata_interface::state::TokenMetadata,
};

pub mod gap_analysis {
    //! Why the two requirement sets cannot share a mint, and what Token-2022 forces
    //! you to do about it.
    //!
    //! **1. Confidentiality is not retrofittable.** `ConfidentialTransferMint` is
    //! an extension, and extensions are initialised only between `CreateAccount`
    //! and `InitializeMint`. The live v1 mint is already initialised, so the only
    //! path is a new mint plus a holder migration. `MintCloseAuthority` on v1 is
    //! what makes that migration finishable: once every account is drained, the
    //! issuer can close the old mint and reclaim its rent.
    //!
    //! **2. A fee-bearing confidential mint is a different animal.** Token-2022
    //! rejects the combination `TransferFeeConfig + ConfidentialTransferMint`
    //! unless `ConfidentialTransferFeeConfig` is *also* initialised
    //! (`check_for_invalid_mint_extension_combinations`). And once the mint has a
    //! transfer fee, the plain confidential `Transfer` path is unreachable: the
    //! processor branches on `mint.get_extension::<TransferFeeConfig>()`, and the
    //! fee branch demands the five-proof `TransferWithFee`. So "keep the fee" and
    //! "add confidentiality" are not two independent checkboxes — together they
    //! change which instruction moves tokens.
    //!
    //! **3. The seizure authority does not reach confidential balances — this is
    //! the real gap.** `PermanentDelegate` lets the issuer sign a transfer out of
    //! any account without the owner's consent, which satisfies the regulator for
    //! the *public* balance. It buys nothing for the confidential balance: moving
    //! confidential funds requires an equality proof over the source's available
    //! balance, and that proof can only be built with the source owner's ElGamal
    //! secret key. The delegate has authority but not the key.
    //!
    //! The mint-level auditor ElGamal key narrows this only partially: an auditor
    //! can *decrypt* transfer amounts, so the issuer can see what moved, but
    //! decryption confers no ability to spend. Practical consequences:
    //!
    //! * Seizure is reliable only against the public balance. An enforcement flow
    //!   therefore has to reach the confidential balance first — which means either
    //!   the holder cooperating (`WithdrawConfidentialTokens` back to public, then
    //!   seize) or the issuer being able to stop the account entirely.
    //! * The blunt instrument that *does* work unilaterally is the freeze
    //!   authority: freezing halts deposits and transfers on that account, so funds
    //!   cannot leave while the issuer negotiates. Freeze contains; it does not
    //!   confiscate.
    //! * If unilateral confiscation of hidden balances is a hard regulatory
    //!   requirement, confidential transfers cannot satisfy it, and the honest
    //!   answer is to not ship them — no extension combination closes this.
}

/// The instructions that create a mint, plus the numbers the caller needs to
/// fund it.
pub struct MintCreation {
    /// Account length for the fixed-size extension set, from
    /// `try_calculate_account_len`.
    pub space: usize,
    /// Rent-exempt lamports for `space` (plus the variable-length metadata TLV,
    /// when metadata is written into the mint).
    pub lamports: u64,
    /// One transaction. The mint keypair signs it alongside the payer.
    ///
    /// Comfortably inside the packet limit for normal metadata; a very long
    /// `uri` is the only realistic way to overflow it, in which case split the
    /// trailing `TokenMetadataInstruction::Initialize` into its own
    /// transaction — it is already sequenced after `InitializeMint2` and does
    /// not depend on being in the same one.
    pub step: Step,
}

/// Shared parameters for both mints.
pub struct RemittanceMint<'a> {
    pub mint: Pubkey,
    pub payer: Pubkey,
    pub decimals: u8,
    /// Mints new supply, and signs the metadata initialisation.
    pub mint_authority: Pubkey,
    /// Thaws accounts once KYC clears, and flips the mint-level default state.
    pub freeze_authority: Pubkey,
    /// May change the fee schedule later; `None` freezes the schedule forever.
    pub transfer_fee_config_authority: Option<Pubkey>,
    /// Withdraws fees that transfers withheld in recipient accounts.
    pub withdraw_withheld_authority: Option<Pubkey>,
    /// Issuer revenue, in basis points of the transfer amount.
    pub transfer_fee_basis_points: u16,
    /// Absolute cap per transfer, so large remittances are not taxed linearly.
    pub maximum_fee: u64,
    /// May close the mint once supply is zero, i.e. decommission the token.
    pub close_authority: Pubkey,
    /// May repoint the metadata pointer later.
    pub metadata_authority: Option<Pubkey>,
    pub name: &'a str,
    pub symbol: &'a str,
    pub uri: &'a str,
}

/// **Task 1.** `TransferFeeConfig` + `MetadataPointer` (self-referential) +
/// `DefaultAccountState(Frozen)` + `MintCloseAuthority`.
pub fn create_remittance_mint_v1(cfg: &RemittanceMint, rent: &Rent) -> Result<MintCreation> {
    build(cfg, rent, None)
}

/// Extra configuration that only v2 carries.
pub struct ConfidentialConfig {
    /// Also the approver of new confidential accounts, since approval is
    /// manual. `None` makes the confidential configuration immutable.
    pub authority: Option<Pubkey>,
    /// Compliance read-access: holds the secret that decrypts every transfer
    /// amount on this mint. `None` means nobody can audit amounts — and,
    /// per [`gap_analysis`], being able to read them is still not being able
    /// to move them.
    pub auditor_elgamal_pubkey: Option<PodElGamalPubkey>,
    /// Withheld *confidential* fees are encrypted under this key, so only its
    /// holder can total up and withdraw them.
    pub withdraw_withheld_authority_elgamal_pubkey: PodElGamalPubkey,
    /// May rotate the key above.
    pub confidential_fee_authority: Option<Pubkey>,
    /// Seizure authority: can sign transfers out of any account on this mint.
    pub permanent_delegate: Pubkey,
}

/// **Task 5.** The v1 extension set carried forward, plus `PermanentDelegate`,
/// `ConfidentialTransferMint` with `approve_policy = manual`, and the
/// `ConfidentialTransferFeeConfig` that Token-2022 requires alongside a
/// transfer fee.
pub fn create_remittance_mint_v2(
    cfg: &RemittanceMint,
    confidential: &ConfidentialConfig,
    rent: &Rent,
) -> Result<MintCreation> {
    build(cfg, rent, Some(confidential))
}

fn build(
    cfg: &RemittanceMint,
    rent: &Rent,
    confidential: Option<&ConfidentialConfig>,
) -> Result<MintCreation> {
    let token_program = spl_token_2022_interface::id();

    // The extension set, in the order the TLV entries will exist. Every entry
    // here is fixed-size; `TokenMetadata` is deliberately absent (see below).
    let mut extensions = vec![
        ExtensionType::TransferFeeConfig,
        ExtensionType::MetadataPointer,
        ExtensionType::DefaultAccountState,
        ExtensionType::MintCloseAuthority,
    ];
    if confidential.is_some() {
        extensions.extend_from_slice(&[
            ExtensionType::PermanentDelegate,
            ExtensionType::ConfidentialTransferMint,
            // Mandatory companion to TransferFeeConfig on a confidential mint;
            // omitting it makes InitializeMint fail with
            // InvalidExtensionCombination.
            ExtensionType::ConfidentialTransferFeeConfig,
        ]);
    }

    // Size the account from the extension list rather than by summing struct
    // sizes: this accounts for the base mint, the account-type discriminator
    // and each TLV header, and it is the same function the on-chain processor
    // uses to validate the length.
    let space = ExtensionType::try_calculate_account_len::<Mint>(&extensions)?;

    // Metadata lives *in* the mint (the pointer below points at the mint
    // itself), and it is variable-length, so it cannot be part of
    // `try_calculate_account_len`. `TokenMetadataInstruction::Initialize`
    // reallocs the mint itself; it only needs the account to already hold rent
    // for the larger size, so that rent is pre-funded here.
    let metadata = TokenMetadata {
        // Only the fields that affect the encoded length matter for sizing.
        name: cfg.name.to_string(),
        symbol: cfg.symbol.to_string(),
        uri: cfg.uri.to_string(),
        ..Default::default()
    };
    let metadata_space = metadata.tlv_size_of()?;
    let lamports = rent.minimum_balance(space.saturating_add(metadata_space));

    let mut instructions = Vec::with_capacity(extensions.len() + 3);

    // 1. Allocate the account at full size, owned by Token-2022.
    instructions.push(system_instruction::create_account(
        &cfg.payer,
        &cfg.mint,
        lamports,
        space as u64,
        &token_program,
    ));

    // 2. Every extension initialiser, all strictly before InitializeMint.

    // Protocol fee on every transfer. Parked on the *recipient* account's own
    // extension and later harvested to the mint, so the fee never needs a
    // separate hop at transfer time.
    instructions.push(transfer_fee::instruction::initialize_transfer_fee_config(
        &token_program,
        &cfg.mint,
        cfg.transfer_fee_config_authority.as_ref(),
        cfg.withdraw_withheld_authority.as_ref(),
        cfg.transfer_fee_basis_points,
        cfg.maximum_fee,
    )?);

    // Metadata pointer aimed at the mint itself: wallets resolve name/symbol/
    // URI from this one account, with no off-chain registry in the trust path.
    instructions.push(metadata_pointer::instruction::initialize(
        &token_program,
        &cfg.mint,
        cfg.metadata_authority,
        Some(cfg.mint),
    )?);

    // New token accounts open Frozen. Nobody can receive or send until the
    // freeze authority thaws them individually — the KYC gate.
    instructions.push(
        default_account_state::instruction::initialize_default_account_state(
            &token_program,
            &cfg.mint,
            &AccountState::Frozen,
        )?,
    );

    // Lets the issuer close the mint (only at zero supply) when the token is
    // decommissioned — including when holders finish migrating v1 -> v2.
    instructions.push(token_instruction::initialize_mint_close_authority(
        &token_program,
        &cfg.mint,
        Some(&cfg.close_authority),
    )?);

    if let Some(c) = confidential {
        // Seizure authority. Unlike a normal delegate this is set at mint
        // creation, applies to every account, and cannot be revoked by holders.
        instructions.push(token_instruction::initialize_permanent_delegate(
            &token_program,
            &cfg.mint,
            &c.permanent_delegate,
        )?);

        // `auto_approve_new_accounts: false` is approve_policy = manual: a
        // configured account stays unusable for confidential operations until
        // the authority below sends ApproveAccount. That is the hook the issuer
        // uses to keep confidential access behind KYC too.
        instructions.push(confidential_transfer::instruction::initialize_mint(
            &token_program,
            &cfg.mint,
            c.authority,
            false,
            c.auditor_elgamal_pubkey,
        )?);

        // Required because this mint also has TransferFeeConfig. Fees withheld
        // by confidential transfers are ElGamal ciphertexts, so they need their
        // own authority and key.
        instructions.push(
            confidential_transfer_fee::instruction::initialize_confidential_transfer_fee_config(
                &token_program,
                &cfg.mint,
                c.confidential_fee_authority,
                &c.withdraw_withheld_authority_elgamal_pubkey,
            )?,
        );
    }

    // 3. Seal the mint. Nothing can be added to the TLV region after this.
    instructions.push(token_instruction::initialize_mint2(
        &token_program,
        &cfg.mint,
        &cfg.mint_authority,
        Some(&cfg.freeze_authority),
        cfg.decimals,
    )?);

    // 4. Write the metadata. This *must* come after InitializeMint — it is not
    // an extension initialiser but a token-metadata-interface call that needs
    // an initialised mint and a mint-authority signature, and it reallocs the
    // mint into the rent funded in step 1.
    instructions.push(spl_token_metadata_interface::instruction::initialize(
        &token_program,
        &cfg.mint, // metadata account == the mint
        &cfg.metadata_authority.unwrap_or(cfg.mint_authority),
        &cfg.mint,
        &cfg.mint_authority,
        cfg.name.to_string(),
        cfg.symbol.to_string(),
        cfg.uri.to_string(),
    ));

    Ok(MintCreation {
        space,
        lamports,
        step: Step::new(
            "create mint",
            instructions,
            // The mint address is a fresh keypair and signs its own allocation;
            // the mint authority signs the metadata write.
            vec![cfg.mint, cfg.mint_authority],
        ),
    })
}

/// Close a decommissioned mint and sweep its rent.
///
/// Token-2022 only allows this at zero supply, which is precisely what makes it
/// the last step of a v1 -> v2 migration.
pub fn close_mint(
    mint: &Pubkey,
    destination: &Pubkey,
    close_authority: &Pubkey,
) -> Result<Instruction> {
    Ok(token_instruction::close_account(
        &spl_token_2022_interface::id(),
        mint,
        destination,
        close_authority,
        &[],
    )?)
}

/// The extension checklist to carry forward when re-issuing.
///
/// Reads the live mint through `StateWithExtensions` so the answer comes from
/// the chain, not from a constant that can drift.
pub fn extensions_to_carry_forward(mint_data: &[u8]) -> Result<Vec<ExtensionType>> {
    state::extension_types(mint_data)
}
