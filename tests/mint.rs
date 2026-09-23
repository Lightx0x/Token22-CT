//! Tasks 1 and 5: the two mints, their sizing, their instruction ordering, and
//! the extension combination Token-2022 forces on the re-issued one.

mod common;

use {
    common::*,
    solana_keypair::Keypair,
    solana_program_pack::Pack,
    solana_rent::Rent,
    solana_signer::Signer,
    solana_system_interface::instruction as system_instruction,
    spl_token_2022_interface::{
        extension::{
            confidential_transfer, default_account_state, metadata_pointer, transfer_fee,
            BaseStateWithExtensions, ExtensionType, StateWithExtensions,
        },
        instruction::{self as token_instruction, TokenInstruction},
        state::{AccountState, Mint},
    },
    spl_token_metadata_interface::state::TokenMetadata,
    token22_ct::{mint, state},
};

/// Classify a built instruction by unpacking it with Token-2022's own decoder,
/// rather than by comparing magic discriminator bytes.
#[derive(Debug, PartialEq, Eq)]
enum Kind {
    CreateAccount,
    TransferFeeExtension,
    MetadataPointerExtension,
    DefaultAccountStateExtension,
    MintCloseAuthority,
    PermanentDelegate,
    ConfidentialTransferExtension,
    ConfidentialTransferFeeExtension,
    InitializeMint2,
    TokenMetadata,
}

fn classify(instruction: &solana_instruction::Instruction) -> Kind {
    if instruction.program_id == solana_system_interface::program::ID {
        return Kind::CreateAccount;
    }
    assert_eq!(
        instruction.program_id,
        spl_token_2022_interface::id(),
        "every non-system instruction must target Token-2022"
    );
    match TokenInstruction::unpack(&instruction.data) {
        Ok(TokenInstruction::TransferFeeExtension) => Kind::TransferFeeExtension,
        Ok(TokenInstruction::MetadataPointerExtension) => Kind::MetadataPointerExtension,
        Ok(TokenInstruction::DefaultAccountStateExtension) => Kind::DefaultAccountStateExtension,
        Ok(TokenInstruction::InitializeMintCloseAuthority { .. }) => Kind::MintCloseAuthority,
        Ok(TokenInstruction::InitializePermanentDelegate { .. }) => Kind::PermanentDelegate,
        Ok(TokenInstruction::ConfidentialTransferExtension) => Kind::ConfidentialTransferExtension,
        Ok(TokenInstruction::ConfidentialTransferFeeExtension) => {
            Kind::ConfidentialTransferFeeExtension
        }
        Ok(TokenInstruction::InitializeMint2 { .. }) => Kind::InitializeMint2,
        // The metadata write uses the token-metadata interface's 8-byte
        // discriminator, which is not a TokenInstruction tag at all.
        Err(_) => Kind::TokenMetadata,
        Ok(other) => panic!("unexpected instruction in mint creation: {other:?}"),
    }
}

fn kinds(creation: &mint::MintCreation) -> Vec<Kind> {
    creation.step.instructions.iter().map(classify).collect()
}

// --- Task 1: the remittance mint ----------------------------------------

#[test]
fn v1_stacks_the_four_extensions_before_initialize_mint() {
    let payer = Keypair::new().pubkey();
    let issuer = Keypair::new().pubkey();
    let mint_address = Keypair::new().pubkey();
    let creation = mint::create_remittance_mint_v1(
        &remittance_config(&mint_address, &payer, &issuer),
        &Rent::default(),
    )
    .unwrap();

    assert_eq!(
        kinds(&creation),
        vec![
            Kind::CreateAccount,
            Kind::TransferFeeExtension,
            Kind::MetadataPointerExtension,
            Kind::DefaultAccountStateExtension,
            Kind::MintCloseAuthority,
            Kind::InitializeMint2,
            // After InitializeMint2 on purpose: it is not an extension
            // initialiser, it needs an initialised mint and a mint-authority
            // signature.
            Kind::TokenMetadata,
        ]
    );
}

#[test]
fn v1_space_comes_from_try_calculate_account_len() {
    let payer = Keypair::new().pubkey();
    let issuer = Keypair::new().pubkey();
    let mint_address = Keypair::new().pubkey();
    let creation = mint::create_remittance_mint_v1(
        &remittance_config(&mint_address, &payer, &issuer),
        &Rent::default(),
    )
    .unwrap();

    let expected = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::TransferFeeConfig,
        ExtensionType::MetadataPointer,
        ExtensionType::DefaultAccountState,
        ExtensionType::MintCloseAuthority,
    ])
    .unwrap();
    assert_eq!(creation.space, expected);

    // The allocation in the transaction must match what was computed, and be
    // strictly larger than a bare mint.
    // CreateAccount data: 4-byte tag, 8-byte lamports, then 8-byte space.
    let data = &creation.step.instructions[0].data;
    let allocated = u64::from_le_bytes(data[12..20].try_into().unwrap());
    assert_eq!(allocated as usize, expected);
    assert!(expected > Mint::LEN);
}

#[test]
fn v1_funds_rent_for_the_variable_length_metadata_too() {
    let payer = Keypair::new().pubkey();
    let issuer = Keypair::new().pubkey();
    let mint_address = Keypair::new().pubkey();
    let rent = Rent::default();
    let creation =
        mint::create_remittance_mint_v1(&remittance_config(&mint_address, &payer, &issuer), &rent)
            .unwrap();

    // `TokenMetadata` is variable length, so it cannot be part of the account
    // length; instead the mint is pre-funded for the size it will realloc to.
    let metadata_space = TokenMetadata {
        name: NAME.to_string(),
        symbol: SYMBOL.to_string(),
        uri: URI.to_string(),
        ..Default::default()
    }
    .tlv_size_of()
    .unwrap();

    assert!(metadata_space > 0);
    assert_eq!(
        creation.lamports,
        rent.minimum_balance(creation.space + metadata_space)
    );
    assert!(creation.lamports > rent.minimum_balance(creation.space));
}

#[test]
fn v1_lands_on_chain_with_every_extension_readable() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let data = env.data(&v1.mint.pubkey());

    assert_eq!(state::decimals(&data).unwrap(), DECIMALS);

    let fee = state::transfer_fee_config(&data).unwrap();
    let schedule = fee.get_epoch_fee(env.epoch());
    assert_eq!(u16::from(schedule.transfer_fee_basis_points), FEE_BPS);
    assert_eq!(u64::from(schedule.maximum_fee), MAX_FEE);

    // The pointer aims at the mint itself: no off-chain registry in the path.
    let pointer = state::metadata_pointer(&data).unwrap();
    assert_eq!(
        Option::<solana_pubkey::Pubkey>::from(pointer.metadata_address),
        Some(v1.mint.pubkey())
    );

    assert_eq!(
        state::default_account_state(&data).unwrap().state,
        u8::from(AccountState::Frozen)
    );
    assert_eq!(
        Option::<solana_pubkey::Pubkey>::from(
            state::mint_close_authority(&data).unwrap().close_authority
        ),
        Some(v1.issuer.pubkey())
    );

    // The metadata itself, living in the mint the pointer names.
    let metadata = StateWithExtensions::<Mint>::unpack(&data)
        .unwrap()
        .get_variable_len_extension::<TokenMetadata>()
        .unwrap();
    assert_eq!(metadata.name, NAME);
    assert_eq!(metadata.symbol, SYMBOL);
    assert_eq!(metadata.uri, URI);
    assert_eq!(metadata.mint, v1.mint.pubkey());
}

#[test]
fn v1_carries_no_seizure_or_confidential_extensions() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let types = state::extension_types(&env.data(&v1.mint.pubkey())).unwrap();

    for absent in [
        ExtensionType::PermanentDelegate,
        ExtensionType::ConfidentialTransferMint,
        ExtensionType::ConfidentialTransferFeeConfig,
    ] {
        assert!(!types.contains(&absent), "v1 should not carry {absent:?}");
    }
    assert!(state::permanent_delegate(&env.data(&v1.mint.pubkey())).is_err());
}

// --- Task 5: the re-issued mint -----------------------------------------

#[test]
fn v2_carries_v1_forward_and_adds_seizure_and_confidentiality() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let v2 = create_mint_v2(&mut env);

    let v1_types = state::extension_types(&env.data(&v1.mint.pubkey())).unwrap();
    let v2_types = state::extension_types(&env.data(&v2.mint.pubkey())).unwrap();

    for carried in &v1_types {
        // TokenMetadata is written after InitializeMint; both mints have it.
        assert!(
            v2_types.contains(carried),
            "v2 dropped {carried:?} from the v1 set"
        );
    }
    for added in [
        ExtensionType::PermanentDelegate,
        ExtensionType::ConfidentialTransferMint,
        // Not requested by the brief — forced by Token-2022, see below.
        ExtensionType::ConfidentialTransferFeeConfig,
    ] {
        assert!(v2_types.contains(&added), "v2 is missing {added:?}");
    }
}

#[test]
fn v2_seizure_authority_and_auditor_are_recorded() {
    let mut env = Env::new();
    let v2 = create_mint_v2(&mut env);
    let data = env.data(&v2.mint.pubkey());

    assert_eq!(
        Option::<solana_pubkey::Pubkey>::from(state::permanent_delegate(&data).unwrap().delegate),
        Some(v2.delegate.pubkey())
    );

    let confidential = state::confidential_transfer_mint(&data).unwrap();
    assert!(
        confidential
            .auditor_elgamal_pubkey
            .equals(&(*v2.auditor_elgamal.pubkey()).into()),
        "the auditor key the issuer set should be the one stored"
    );
    assert_eq!(
        state::confidential_transfer_fee_config(&data)
            .unwrap()
            .withdraw_withheld_authority_elgamal_pubkey,
        (*v2.withheld_elgamal.pubkey()).into()
    );
}

#[test]
fn v2_approve_policy_is_manual() {
    let mut env = Env::new();
    let v2 = create_mint_v2(&mut env);
    let confidential = state::confidential_transfer_mint(&env.data(&v2.mint.pubkey())).unwrap();

    // approve_policy = manual is encoded as `auto_approve_new_accounts: false`:
    // a configured account stays unusable until the authority approves it.
    assert!(!bool::from(confidential.auto_approve_new_accounts));
    assert_eq!(
        Option::<solana_pubkey::Pubkey>::from(confidential.authority),
        Some(v2.issuer.pubkey())
    );
}

/// The first half of the gap: a fee-bearing confidential mint is rejected
/// unless `ConfidentialTransferFeeConfig` is initialised alongside.
///
/// Built by hand with exactly six extensions — correctly sized, correctly
/// ordered — so the only thing missing is the forced companion.
#[test]
fn fee_plus_confidentiality_without_the_fee_config_is_rejected() {
    let mut env = Env::new();
    let v2 = new_mint_v2_handle();
    let token_program = spl_token_2022_interface::id();
    let mint_address = v2.mint.pubkey();
    let confidential = v2.confidential_config();

    let six = [
        ExtensionType::TransferFeeConfig,
        ExtensionType::MetadataPointer,
        ExtensionType::DefaultAccountState,
        ExtensionType::MintCloseAuthority,
        ExtensionType::PermanentDelegate,
        ExtensionType::ConfidentialTransferMint,
    ];
    let space = ExtensionType::try_calculate_account_len::<Mint>(&six).unwrap();

    let instructions = vec![
        system_instruction::create_account(
            &env.payer.pubkey(),
            &mint_address,
            env.rent().minimum_balance(space),
            space as u64,
            &token_program,
        ),
        transfer_fee::instruction::initialize_transfer_fee_config(
            &token_program,
            &mint_address,
            Some(&v2.issuer.pubkey()),
            Some(&v2.issuer.pubkey()),
            FEE_BPS,
            MAX_FEE,
        )
        .unwrap(),
        metadata_pointer::instruction::initialize(
            &token_program,
            &mint_address,
            Some(v2.issuer.pubkey()),
            Some(mint_address),
        )
        .unwrap(),
        default_account_state::instruction::initialize_default_account_state(
            &token_program,
            &mint_address,
            &AccountState::Frozen,
        )
        .unwrap(),
        token_instruction::initialize_mint_close_authority(
            &token_program,
            &mint_address,
            Some(&v2.issuer.pubkey()),
        )
        .unwrap(),
        token_instruction::initialize_permanent_delegate(
            &token_program,
            &mint_address,
            &confidential.permanent_delegate,
        )
        .unwrap(),
        confidential_transfer::instruction::initialize_mint(
            &token_program,
            &mint_address,
            confidential.authority,
            false,
            confidential.auditor_elgamal_pubkey,
        )
        .unwrap(),
        token_instruction::initialize_mint2(
            &token_program,
            &mint_address,
            &v2.issuer.pubkey(),
            Some(&v2.issuer.pubkey()),
            DECIMALS,
        )
        .unwrap(),
    ];

    let result = env.send(&instructions, &[&v2.mint]);
    assert!(
        result.is_err(),
        "InitializeMint should reject TransferFeeConfig + ConfidentialTransferMint \
         without ConfidentialTransferFeeConfig"
    );

    // And the same set with the companion added does go through — proving the
    // rejection is about the combination, not about anything else in the list.
    env.svm.expire_blockhash();
    let repaired = new_mint_v2_handle();
    let creation = mint::create_remittance_mint_v2(
        &repaired.config(&env.payer.pubkey()),
        &repaired.confidential_config(),
        &env.rent(),
    )
    .unwrap();
    env.run(&creation.step, &[&repaired.mint, &repaired.issuer])
        .expect("the seven-extension mint should be accepted");
}

#[test]
fn confidentiality_cannot_be_added_to_a_live_mint() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);

    // Extensions initialise only on an uninitialised mint; v1 is sealed.
    let late = confidential_transfer::instruction::initialize_mint(
        &spl_token_2022_interface::id(),
        &v1.mint.pubkey(),
        Some(v1.issuer.pubkey()),
        false,
        None,
    )
    .unwrap();

    // No signer is required for the instruction itself — it is rejected because
    // the mint is already initialised, not for want of a signature.
    assert!(
        env.send(&[late], &[]).is_err(),
        "adding ConfidentialTransferMint after InitializeMint must fail — this is \
         why v2 is a new mint address rather than an upgrade"
    );
}

#[test]
fn a_decommissioned_mint_can_be_closed_at_zero_supply() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let owner = Keypair::new();
    let account = open_and_kyc(&mut env, &v1.mint.pubkey(), &owner.pubkey(), &v1.issuer);

    // With supply outstanding the mint is not closable.
    mint_to(&mut env, &v1.mint.pubkey(), &account, &v1.issuer, 1_000);
    let close =
        mint::close_mint(&v1.mint.pubkey(), &env.payer.pubkey(), &v1.issuer.pubkey()).unwrap();
    assert!(env
        .send(std::slice::from_ref(&close), &[&v1.issuer])
        .is_err());
    env.svm.expire_blockhash();

    // Burn it down, and the migration can be finished.
    let burn = token_instruction::burn_checked(
        &spl_token_2022_interface::id(),
        &account,
        &v1.mint.pubkey(),
        &owner.pubkey(),
        &[],
        1_000,
        DECIMALS,
    )
    .unwrap();
    env.send(&[burn], &[&owner]).expect("burn failed");
    env.svm.expire_blockhash();

    env.send(&[close], &[&v1.issuer])
        .expect("a zero-supply mint should close");
    assert!(!env.exists(&v1.mint.pubkey()));
}
