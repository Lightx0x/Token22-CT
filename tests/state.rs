//! Task 3: state is read through `StateWithExtensions`, never a raw unpack.

mod common;

use {
    common::*,
    solana_keypair::Keypair,
    solana_program_pack::Pack,
    solana_signer::Signer,
    spl_token_2022_interface::{
        extension::ExtensionType,
        state::{Account, Mint},
    },
    token22_ct::state,
};

/// The reason this crate has a single reader module.
#[test]
fn raw_unpack_cannot_read_an_extended_mint() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let data = env.data(&v1.mint.pubkey());

    // An extended mint is longer than a bare one, so `Pack::unpack` — correct
    // for the original Token program — refuses it outright.
    assert!(data.len() > Mint::LEN);
    assert!(
        Mint::unpack(&data).is_err(),
        "raw unpack should not accept an extended mint"
    );

    // The extension-aware reader gets both the base state and the TLV region.
    let parsed = state::mint(&data).unwrap();
    assert_eq!(parsed.base.decimals, DECIMALS);
    assert!(state::transfer_fee_config(&data).is_ok());
}

#[test]
fn raw_unpack_cannot_read_an_extended_token_account() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let owner = Keypair::new();
    let account = open_and_kyc(&mut env, &v1.mint.pubkey(), &owner.pubkey(), &v1.issuer);
    let data = env.data(&account);

    // A fee-mint account carries TransferFeeAmount, so it is over-length too.
    assert!(data.len() > Account::LEN);
    assert!(Account::unpack(&data).is_err());

    let parsed = state::token_account(&data).unwrap();
    assert_eq!(parsed.base.owner, owner.pubkey());
    assert_eq!(parsed.base.mint, v1.mint.pubkey());
}

#[test]
fn extension_types_report_what_was_initialised() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let mut types = state::extension_types(&env.data(&v1.mint.pubkey())).unwrap();
    types.sort_by_key(|t| *t as u16);

    let mut expected = vec![
        ExtensionType::TransferFeeConfig,
        ExtensionType::MetadataPointer,
        ExtensionType::DefaultAccountState,
        ExtensionType::MintCloseAuthority,
        ExtensionType::TokenMetadata,
    ];
    expected.sort_by_key(|t| *t as u16);
    assert_eq!(types, expected);
}

#[test]
fn a_missing_extension_is_a_named_error_not_a_panic() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let data = env.data(&v1.mint.pubkey());

    let err = state::confidential_transfer_mint(&data).unwrap_err();
    assert!(
        format!("{err}").contains("ConfidentialTransferMint"),
        "the error should name the missing extension, got: {err}"
    );
}

#[test]
fn decimals_come_from_the_mint() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    // Reading decimals off the mint is what keeps every `*_checked`
    // instruction from failing with MintDecimalsMismatch.
    assert_eq!(
        state::decimals(&env.data(&v1.mint.pubkey())).unwrap(),
        DECIMALS
    );
}

#[test]
fn has_transfer_fee_distinguishes_the_two_mints() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let v2 = create_mint_v2(&mut env);

    // Both carry a fee; this is the switch that forces TransferWithFee on v2.
    assert!(state::has_transfer_fee(&env.data(&v1.mint.pubkey())).unwrap());
    assert!(state::has_transfer_fee(&env.data(&v2.mint.pubkey())).unwrap());
}
