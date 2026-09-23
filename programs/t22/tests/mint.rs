mod common;

use {
    anchor_lang::error::ErrorCode as AnchorError,
    common::*,
    solana_instruction::Instruction,
    solana_instruction_error::InstructionError,
    solana_keypair::Keypair,
    solana_pubkey::Pubkey,
    solana_signer::Signer,
    spl_token_metadata_interface::state::TokenMetadata,
    t22::accounts as t22_accounts,
    t22new::{
        error::TokenError,
        extension::{
            confidential_transfer::{self, ConfidentialTransferMint},
            confidential_transfer_fee::ConfidentialTransferFeeConfig,
            default_account_state::{self, DefaultAccountState},
            metadata_pointer::{self, MetadataPointer},
            mint_close_authority::MintCloseAuthority,
            permanent_delegate::PermanentDelegate,
            transfer_fee::{self, TransferFeeConfig},
            BaseStateWithExtensions, ExtensionType,
        },
        instruction as token_instruction,
        state::{AccountState, Mint as MintState},
    },
};

fn sorted(mut types: Vec<ExtensionType>) -> Vec<ExtensionType> {
    types.sort_by_key(|t| *t as u16);
    types
}

fn assert_supported_ix(mint: &Pubkey) -> Instruction {
    ix(
        t22_accounts::AssertSupportedMint {
            mint: *mint,
            token_program: token_program(),
        },
        t22::instruction::AssertSupportedMint {},
    )
}

fn close_mint_ix(mint: &Pubkey, destination: &Pubkey, authority: &Pubkey) -> Instruction {
    ix(
        t22_accounts::CloseMint {
            mint: *mint,
            destination: *destination,
            close_authority: *authority,
            token_program: token_program(),
        },
        t22::instruction::CloseMint {},
    )
}

/// create_remittance_mint, assert_supported_mint and close_mint: the whole life
/// of the v1 mint, from allocation to decommissioning.
#[test]
fn remittance_mint_from_creation_to_close() {
    let mut env = Env::new();
    let mint = new_mint(&mut env);
    let issuer = mint.issuer.pubkey();
    let issuer_before = env.lamports(&issuer);

    env.send(
        &[ix(create_mint_accounts(&mint), remittance_mint_data())],
        &[&mint.key, &mint.issuer],
    )
    .expect("create failed");

    let data = env.data(&mint.pubkey());
    let parsed = mint_state(&data);

    assert_eq!(
        sorted(parsed.get_extension_types().unwrap()),
        sorted(vec![
            ExtensionType::TransferFeeConfig,
            ExtensionType::MetadataPointer,
            ExtensionType::DefaultAccountState,
            ExtensionType::MintCloseAuthority,
            ExtensionType::TokenMetadata,
        ])
    );
    assert_eq!(parsed.base.decimals, DECIMALS);
    assert_eq!(parsed.base.supply, 0);
    assert_eq!(
        Option::<Pubkey>::from(parsed.base.mint_authority),
        Some(issuer)
    );
    assert_eq!(
        Option::<Pubkey>::from(parsed.base.freeze_authority),
        Some(issuer)
    );

    let fee = parsed.get_extension::<TransferFeeConfig>().unwrap();
    for schedule in [fee.older_transfer_fee, fee.newer_transfer_fee] {
        assert_eq!(u16::from(schedule.transfer_fee_basis_points), FEE_BPS);
        assert_eq!(u64::from(schedule.maximum_fee), MAX_FEE);
    }
    assert_eq!(
        Option::<Pubkey>::from(fee.transfer_fee_config_authority),
        Some(issuer)
    );
    assert_eq!(
        Option::<Pubkey>::from(fee.withdraw_withheld_authority),
        Some(issuer)
    );
    assert_eq!(u64::from(fee.withheld_amount), 0);

    let pointer = parsed.get_extension::<MetadataPointer>().unwrap();
    assert_eq!(Option::<Pubkey>::from(pointer.authority), Some(issuer));
    assert_eq!(
        Option::<Pubkey>::from(pointer.metadata_address),
        Some(mint.pubkey())
    );

    assert_eq!(
        parsed.get_extension::<DefaultAccountState>().unwrap().state,
        u8::from(AccountState::Frozen)
    );
    assert_eq!(
        Option::<Pubkey>::from(
            parsed
                .get_extension::<MintCloseAuthority>()
                .unwrap()
                .close_authority
        ),
        Some(issuer)
    );

    let metadata = parsed
        .get_variable_len_extension::<TokenMetadata>()
        .unwrap();
    assert_eq!(
        (
            metadata.name.as_str(),
            metadata.symbol.as_str(),
            metadata.uri.as_str()
        ),
        (NAME, SYMBOL, URI)
    );
    assert_eq!(metadata.mint, mint.pubkey());
    assert_eq!(
        Option::<Pubkey>::from(metadata.update_authority),
        Some(issuer)
    );

    // Fixed extensions sized by try_calculate_account_len, grown once by the
    // metadata into rent funded up front: exactly rent-exempt, and paid for by
    // the issuer to the lamport.
    let fixed = ExtensionType::try_calculate_account_len::<MintState>(&[
        ExtensionType::TransferFeeConfig,
        ExtensionType::MetadataPointer,
        ExtensionType::DefaultAccountState,
        ExtensionType::MintCloseAuthority,
    ])
    .unwrap();
    // 166 base + 221 of fixed TLV; the metadata adds its 4-byte header and 122
    // bytes of borsh (two keys, three strings, an empty vec).
    assert_eq!(fixed, 387);
    assert_eq!(data.len(), 387 + 4 + 122);
    let mint_lamports = env.lamports(&mint.pubkey());
    assert_eq!(
        mint_lamports,
        env.svm.minimum_balance_for_rent_exemption(data.len())
    );
    assert_eq!(issuer_before - env.lamports(&issuer), mint_lamports);

    // Creating again at the same address dies in the system program's
    // allocation and leaves the live mint exactly as it was.
    let hijacker = Keypair::new();
    env.svm.airdrop(&hijacker.pubkey(), 100 * SOL).unwrap();
    let mut again = create_mint_accounts(&mint);
    again.payer = hijacker.pubkey();
    env.rejects(
        &[ix(again, remittance_mint_data())],
        &[&mint.key, &hijacker],
        InstructionError::Custom(0), // SystemError::AccountAlreadyInUse
        &[mint.pubkey(), hijacker.pubkey()],
    );

    // The allowlist accepts the mint, and rejects both an account the token
    // program does not own and one it owns that is not a mint.
    env.send(&[assert_supported_ix(&mint.pubkey())], &[])
        .expect("the remittance mint should be supported");
    env.rejects(
        &[assert_supported_ix(&issuer)],
        &[],
        anchor(AnchorError::ConstraintOwner),
        &[issuer],
    );
    let alice = Keypair::new();
    let account = open_and_kyc(&mut env, &mint.pubkey(), &alice.pubkey(), &mint.issuer);
    env.rejects(
        &[assert_supported_ix(&account)],
        &[],
        InstructionError::InvalidAccountData,
        &[account],
    );

    // Closing is refused one unit away from zero supply, by the wrong
    // authority, and without a signature.
    mint_to(&mut env, &mint.pubkey(), &account, &mint.issuer, 1_000);
    let burn = |amount| {
        token_instruction::burn_checked(
            &token_program(),
            &account,
            &mint.pubkey(),
            &alice.pubkey(),
            &[],
            amount,
            DECIMALS,
        )
        .unwrap()
    };
    env.send(&[burn(999)], &[&alice]).expect("burn failed");
    assert_eq!(supply(&env, &mint.pubkey()), 1);
    env.rejects(
        &[close_mint_ix(&mint.pubkey(), &issuer, &issuer)],
        &[&mint.issuer],
        token(TokenError::MintHasSupply),
        &[mint.pubkey(), issuer],
    );
    env.send(&[burn(1)], &[&alice]).expect("burn failed");

    let impostor = Keypair::new();
    env.rejects(
        &[close_mint_ix(
            &mint.pubkey(),
            &impostor.pubkey(),
            &impostor.pubkey(),
        )],
        &[&impostor],
        token(TokenError::OwnerMismatch),
        &[mint.pubkey(), impostor.pubkey()],
    );
    env.rejects(
        &[unsigned(
            close_mint_ix(&mint.pubkey(), &issuer, &issuer),
            &issuer,
        )],
        &[],
        anchor(AnchorError::AccountNotSigner),
        &[mint.pubkey(), issuer],
    );

    // At zero supply it closes, and every lamport of rent reaches the
    // destination.
    let issuer_before = env.lamports(&issuer);
    env.send(
        &[close_mint_ix(&mint.pubkey(), &issuer, &issuer)],
        &[&mint.issuer],
    )
    .expect("a zero-supply mint should close");
    assert!(!env.exists(&mint.pubkey()));
    assert_eq!(env.lamports(&issuer) - issuer_before, mint_lamports);
}

/// create_confidential_mint, and the two Token-2022 rules that shape it: the
/// forced ConfidentialTransferFeeConfig, and that extensions cannot be added to
/// a live mint.
#[test]
fn confidential_mint_carries_the_forced_extension_and_cannot_be_retrofitted() {
    let mut env = Env::new();
    let withheld = [7u8; 32];
    let auditor = [9u8; 32];
    let v2 = create_confidential_mint(&mut env, withheld, Some(auditor));
    let issuer = v2.issuer.pubkey();

    let data = env.data(&v2.pubkey());
    let parsed = mint_state(&data);
    assert_eq!(
        sorted(parsed.get_extension_types().unwrap()),
        sorted(vec![
            ExtensionType::TransferFeeConfig,
            ExtensionType::MetadataPointer,
            ExtensionType::DefaultAccountState,
            ExtensionType::MintCloseAuthority,
            ExtensionType::PermanentDelegate,
            ExtensionType::ConfidentialTransferMint,
            ExtensionType::ConfidentialTransferFeeConfig,
            ExtensionType::TokenMetadata,
        ])
    );

    let confidential = parsed.get_extension::<ConfidentialTransferMint>().unwrap();
    assert_eq!(Option::<Pubkey>::from(confidential.authority), Some(issuer));
    assert!(!bool::from(confidential.auto_approve_new_accounts));
    assert!(confidential.auditor_elgamal_pubkey.equals(&auditor.into()));

    let fee = parsed
        .get_extension::<ConfidentialTransferFeeConfig>()
        .unwrap();
    assert_eq!(Option::<Pubkey>::from(fee.authority), Some(issuer));
    assert_eq!(
        fee.withdraw_withheld_authority_elgamal_pubkey,
        withheld.into()
    );
    assert_eq!(fee.withheld_amount, Default::default());

    assert_eq!(
        Option::<Pubkey>::from(
            parsed
                .get_extension::<PermanentDelegate>()
                .unwrap()
                .delegate
        ),
        Some(issuer)
    );
    assert_eq!(
        env.lamports(&v2.pubkey()),
        env.svm.minimum_balance_for_rent_exemption(data.len())
    );

    // The same set minus ConfidentialTransferFeeConfig, built by hand and
    // correctly sized, is refused at InitializeMint2. The whole transaction
    // reverts, so the account never comes into existence.
    let bare = new_mint(&mut env);
    let (program, address, authority) = (token_program(), bare.pubkey(), bare.issuer.pubkey());
    let space = ExtensionType::try_calculate_account_len::<MintState>(&[
        ExtensionType::TransferFeeConfig,
        ExtensionType::MetadataPointer,
        ExtensionType::DefaultAccountState,
        ExtensionType::MintCloseAuthority,
        ExtensionType::PermanentDelegate,
        ExtensionType::ConfidentialTransferMint,
    ])
    .unwrap();
    let instructions = [
        solana_system_interface::instruction::create_account(
            &authority,
            &address,
            env.svm.minimum_balance_for_rent_exemption(space),
            space as u64,
            &program,
        ),
        transfer_fee::instruction::initialize_transfer_fee_config(
            &program,
            &address,
            Some(&authority),
            Some(&authority),
            FEE_BPS,
            MAX_FEE,
        )
        .unwrap(),
        metadata_pointer::instruction::initialize(
            &program,
            &address,
            Some(authority),
            Some(address),
        )
        .unwrap(),
        default_account_state::instruction::initialize_default_account_state(
            &program,
            &address,
            &AccountState::Frozen,
        )
        .unwrap(),
        token_instruction::initialize_mint_close_authority(&program, &address, Some(&authority))
            .unwrap(),
        token_instruction::initialize_permanent_delegate(&program, &address, &authority).unwrap(),
        confidential_transfer::instruction::initialize_mint(
            &program,
            &address,
            Some(authority),
            false,
            None,
        )
        .unwrap(),
        token_instruction::initialize_mint2(
            &program,
            &address,
            &authority,
            Some(&authority),
            DECIMALS,
        )
        .unwrap(),
    ];
    env.rejects(
        &instructions,
        &[&bare.key, &bare.issuer],
        token(TokenError::InvalidExtensionCombination),
        &[address, authority],
    );
    assert!(!env.exists(&address));

    // Confidentiality cannot be bolted onto the live v1 mint, which is why v2
    // is a new address rather than an upgrade.
    let v1 = create_remittance_mint(&mut env);
    let late = confidential_transfer::instruction::initialize_mint(
        &program,
        &v1.pubkey(),
        Some(v1.issuer.pubkey()),
        false,
        None,
    )
    .unwrap();
    env.rejects(
        &[late],
        &[],
        token(TokenError::AlreadyInUse),
        &[v1.pubkey()],
    );
}
