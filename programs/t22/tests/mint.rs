mod common;

use {
    common::*,
    solana_keypair::Keypair,
    solana_program_pack::Pack,
    solana_signer::Signer,
    t22::accounts as t22_accounts,
    t22new::{
        extension::{BaseStateWithExtensions, ExtensionType},
        state::Mint as MintState,
    },
};

fn extensions(env: &Env, mint: &solana_pubkey::Pubkey) -> Vec<ExtensionType> {
    mint_state(&env.data(mint)).get_extension_types().unwrap()
}

#[test]
fn remittance_mint_stacks_four_extensions_and_writes_its_own_metadata() {
    use t22new::extension::{
        default_account_state::DefaultAccountState, metadata_pointer::MetadataPointer,
        mint_close_authority::MintCloseAuthority, transfer_fee::TransferFeeConfig,
    };
    use t22new::state::AccountState;

    let mut env = Env::new();
    let mint = create_remittance_mint(&mut env);
    let data = env.data(&mint.pubkey());
    let parsed = mint_state(&data);

    assert_eq!(parsed.base.decimals, DECIMALS);

    let fee = parsed.get_extension::<TransferFeeConfig>().unwrap();
    let schedule = fee.get_epoch_fee(env.epoch());
    assert_eq!(u16::from(schedule.transfer_fee_basis_points), FEE_BPS);
    assert_eq!(u64::from(schedule.maximum_fee), MAX_FEE);

    let pointer = parsed.get_extension::<MetadataPointer>().unwrap();
    assert_eq!(
        Option::<solana_pubkey::Pubkey>::from(pointer.metadata_address),
        Some(mint.pubkey())
    );

    assert_eq!(
        parsed.get_extension::<DefaultAccountState>().unwrap().state,
        u8::from(AccountState::Frozen)
    );
    assert!(parsed.get_extension::<MintCloseAuthority>().is_ok());

    let metadata = parsed
        .get_variable_len_extension::<spl_token_metadata_interface::state::TokenMetadata>()
        .unwrap();
    assert_eq!(metadata.name, NAME);
    assert_eq!(metadata.symbol, SYMBOL);
    assert_eq!(metadata.uri, URI);
    assert_eq!(metadata.mint, mint.pubkey());
}

#[test]
fn the_allocation_matches_try_calculate_account_len() {
    let mut env = Env::new();
    let mint = create_remittance_mint(&mut env);

    let fixed = ExtensionType::try_calculate_account_len::<MintState>(&[
        ExtensionType::TransferFeeConfig,
        ExtensionType::MetadataPointer,
        ExtensionType::DefaultAccountState,
        ExtensionType::MintCloseAuthority,
    ])
    .unwrap();

    let len = env.data(&mint.pubkey()).len();
    assert!(len > fixed, "metadata should have reallocated the mint");
    assert!(fixed > MintState::LEN);

    let account = env.svm.get_account(&mint.pubkey()).unwrap();
    assert!(account.lamports >= env.svm.minimum_balance_for_rent_exemption(len));
}

#[test]
fn a_remittance_mint_carries_no_seizure_or_confidential_extensions() {
    let mut env = Env::new();
    let mint = create_remittance_mint(&mut env);
    let types = extensions(&env, &mint.pubkey());

    for absent in [
        ExtensionType::PermanentDelegate,
        ExtensionType::ConfidentialTransferMint,
        ExtensionType::ConfidentialTransferFeeConfig,
    ] {
        assert!(!types.contains(&absent), "v1 should not carry {absent:?}");
    }
}

#[test]
fn the_reissued_mint_carries_v1_forward_and_adds_the_new_pair() {
    let mut env = Env::new();
    let v1 = create_remittance_mint(&mut env);
    let v2 = create_confidential_mint(&mut env, [1u8; 32], None);

    let v1_types = extensions(&env, &v1.pubkey());
    let v2_types = extensions(&env, &v2.pubkey());

    for carried in &v1_types {
        assert!(
            v2_types.contains(carried),
            "v2 dropped {carried:?} from the v1 set"
        );
    }
    for added in [
        ExtensionType::PermanentDelegate,
        ExtensionType::ConfidentialTransferMint,
        // Not requested by anyone — forced by Token-2022.
        ExtensionType::ConfidentialTransferFeeConfig,
    ] {
        assert!(v2_types.contains(&added), "v2 is missing {added:?}");
    }
}

#[test]
fn approve_policy_is_manual_and_the_auditor_key_is_recorded() {
    use t22new::extension::{
        confidential_transfer::ConfidentialTransferMint,
        confidential_transfer_fee::ConfidentialTransferFeeConfig,
        permanent_delegate::PermanentDelegate,
    };

    let mut env = Env::new();
    let withheld = [7u8; 32];
    let auditor = [9u8; 32];
    let v2 = create_confidential_mint(&mut env, withheld, Some(auditor));
    let data = env.data(&v2.pubkey());
    let parsed = mint_state(&data);

    let confidential = parsed.get_extension::<ConfidentialTransferMint>().unwrap();
    assert!(!bool::from(confidential.auto_approve_new_accounts));
    assert!(confidential.auditor_elgamal_pubkey.equals(&auditor.into()));

    assert_eq!(
        parsed
            .get_extension::<ConfidentialTransferFeeConfig>()
            .unwrap()
            .withdraw_withheld_authority_elgamal_pubkey,
        withheld.into()
    );

    let delegate = parsed.get_extension::<PermanentDelegate>().unwrap();
    assert_eq!(
        Option::<solana_pubkey::Pubkey>::from(delegate.delegate),
        Some(v2.issuer.pubkey())
    );
}

#[test]
fn confidentiality_cannot_be_added_to_a_live_mint() {
    let mut env = Env::new();
    let v1 = create_remittance_mint(&mut env);

    let late = t22new::extension::confidential_transfer::instruction::initialize_mint(
        &token_program(),
        &v1.pubkey(),
        Some(v1.issuer.pubkey()),
        false,
        None,
    )
    .unwrap();

    assert!(
        env.send(&[late], &[]).is_err(),
        "an extension cannot be initialized on a sealed mint"
    );
}

#[test]
fn a_supported_mint_is_accepted_and_a_foreign_account_is_not() {
    let mut env = Env::new();
    let v1 = create_remittance_mint(&mut env);
    let v2 = create_confidential_mint(&mut env, [3u8; 32], None);

    for mint in [v1.pubkey(), v2.pubkey()] {
        env.call(
            t22_accounts::AssertSupportedMint {
                mint,
                token_program: token_program(),
            },
            t22::instruction::AssertSupportedMint {},
            &[],
        )
        .expect("both mints should be recognised");
    }

    let owner = Keypair::new();
    let account = create_ata(&mut env, &v1.pubkey(), &owner.pubkey());
    assert!(env
        .call(
            t22_accounts::AssertSupportedMint {
                mint: account,
                token_program: token_program(),
            },
            t22::instruction::AssertSupportedMint {},
            &[],
        )
        .is_err());
}
