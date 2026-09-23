//! Task 4: the unfreeze path, and its separation from the mint-level default.

mod common;

use {
    common::*,
    solana_keypair::Keypair,
    solana_signer::Signer,
    spl_token_2022_interface::state::AccountState,
    token22_ct::{confidential, kyc, state},
};

fn create_ata(
    env: &mut Env,
    mint: &solana_pubkey::Pubkey,
    owner: &solana_pubkey::Pubkey,
) -> solana_pubkey::Pubkey {
    let account = confidential::associated_token_address(owner, mint);
    let create =
        spl_associated_token_account_interface::instruction::create_associated_token_account(
            &env.payer.pubkey(),
            owner,
            mint,
            &spl_token_2022_interface::id(),
        );
    env.send(&[create], &[]).expect("ATA creation failed");
    env.svm.expire_blockhash();
    account
}

#[test]
fn new_accounts_open_frozen() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let alice = Keypair::new();
    let account = create_ata(&mut env, &v1.mint.pubkey(), &alice.pubkey());

    assert!(kyc::needs_thaw(&env.data(&account)).unwrap());
    assert!(state::is_frozen(&env.data(&account)).unwrap());
}

#[test]
fn a_frozen_account_cannot_receive() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let alice = Keypair::new();
    let account = create_ata(&mut env, &v1.mint.pubkey(), &alice.pubkey());

    let mint_to = spl_token_2022_interface::instruction::mint_to_checked(
        &spl_token_2022_interface::id(),
        &v1.mint.pubkey(),
        &account,
        &v1.issuer.pubkey(),
        &[],
        1_000,
        DECIMALS,
    )
    .unwrap();
    assert!(
        env.send(&[mint_to], &[&v1.issuer]).is_err(),
        "the KYC gate should hold until the account is thawed"
    );
}

#[test]
fn thaw_after_kyc_unfreezes_exactly_one_account() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let alice = Keypair::new();
    let bob = Keypair::new();
    let alice_account = create_ata(&mut env, &v1.mint.pubkey(), &alice.pubkey());
    let bob_account = create_ata(&mut env, &v1.mint.pubkey(), &bob.pubkey());

    let thaw = kyc::thaw_after_kyc(&v1.mint.pubkey(), &alice_account, &v1.issuer.pubkey()).unwrap();
    env.send(&[thaw], &[&v1.issuer]).expect("thaw failed");
    env.svm.expire_blockhash();

    assert!(!state::is_frozen(&env.data(&alice_account)).unwrap());
    assert!(
        state::is_frozen(&env.data(&bob_account)).unwrap(),
        "thawing Alice must not clear Bob"
    );

    // And Alice can now be funded.
    mint_to(
        &mut env,
        &v1.mint.pubkey(),
        &alice_account,
        &v1.issuer,
        1_000,
    );
    assert_eq!(balance(&env, &alice_account), 1_000);
}

#[test]
fn only_the_freeze_authority_can_thaw() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let alice = env.funded_key();
    let account = create_ata(&mut env, &v1.mint.pubkey(), &alice.pubkey());

    // The account owner cannot thaw their own account — that is the point of
    // a KYC gate.
    let thaw = kyc::thaw_after_kyc(&v1.mint.pubkey(), &account, &alice.pubkey()).unwrap();
    assert!(env.send(&[thaw], &[&alice]).is_err());
}

/// The distinction that matters: the mint-level default governs *future*
/// accounts and never touches existing ones.
#[test]
fn changing_the_default_state_does_not_thaw_existing_accounts() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let alice = Keypair::new();
    let bob = Keypair::new();
    let alice_account = create_ata(&mut env, &v1.mint.pubkey(), &alice.pubkey());

    // Policy change: drop the KYC requirement for new holders.
    let update = kyc::set_default_account_state(
        &v1.mint.pubkey(),
        &v1.issuer.pubkey(),
        AccountState::Initialized,
    )
    .unwrap();
    env.send(&[update], &[&v1.issuer])
        .expect("default state update failed");
    env.svm.expire_blockhash();

    assert_eq!(
        state::default_account_state(&env.data(&v1.mint.pubkey()))
            .unwrap()
            .state,
        u8::from(AccountState::Initialized)
    );

    // Alice, who already existed, is untouched.
    assert!(
        state::is_frozen(&env.data(&alice_account)).unwrap(),
        "an existing frozen account must stay frozen across a policy change"
    );

    // Bob, created afterwards, opens usable.
    let bob_account = create_ata(&mut env, &v1.mint.pubkey(), &bob.pubkey());
    assert!(!state::is_frozen(&env.data(&bob_account)).unwrap());

    // Alice still needs her individual thaw.
    let thaw = kyc::thaw_after_kyc(&v1.mint.pubkey(), &alice_account, &v1.issuer.pubkey()).unwrap();
    env.send(&[thaw], &[&v1.issuer]).expect("thaw failed");
    env.svm.expire_blockhash();
    assert!(!state::is_frozen(&env.data(&alice_account)).unwrap());
}

#[test]
fn freezing_contains_a_sanctioned_account() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let alice = Keypair::new();
    let bob = Keypair::new();
    let alice_account = open_and_kyc(&mut env, &v1.mint.pubkey(), &alice.pubkey(), &v1.issuer);
    let bob_account = open_and_kyc(&mut env, &v1.mint.pubkey(), &bob.pubkey(), &v1.issuer);
    mint_to(
        &mut env,
        &v1.mint.pubkey(),
        &alice_account,
        &v1.issuer,
        100_000,
    );

    let freeze = kyc::freeze(&v1.mint.pubkey(), &alice_account, &v1.issuer.pubkey()).unwrap();
    env.send(&[freeze], &[&v1.issuer]).expect("freeze failed");
    env.svm.expire_blockhash();

    let (transfer, _) = token22_ct::transfer::transfer_checked_with_fee(
        &v1.mint.pubkey(),
        &env.data(&v1.mint.pubkey()),
        &alice_account,
        &bob_account,
        &alice.pubkey(),
        &[],
        10_000,
        env.epoch(),
    )
    .unwrap();

    assert!(
        env.send(&[transfer], &[&alice]).is_err(),
        "a frozen account must not be able to move funds out"
    );
    assert_eq!(balance(&env, &alice_account), 100_000);
}
