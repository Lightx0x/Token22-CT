mod common;

use {
    common::*,
    solana_keypair::Keypair,
    solana_signer::Signer,
    t22::accounts as t22_accounts,
    t22new::{
        extension::{
            transfer_fee::TransferFeeAmount, BaseStateWithExtensions, StateWithExtensions,
        },
        state::{Account as TokenAccountState, AccountState},
    },
};

fn is_frozen(env: &Env, account: &solana_pubkey::Pubkey) -> bool {
    StateWithExtensions::<TokenAccountState>::unpack(&env.data(account))
        .unwrap()
        .base
        .state
        == AccountState::Frozen
}

fn withheld(env: &Env, account: &solana_pubkey::Pubkey) -> u64 {
    let data = env.data(account);
    let parsed = StateWithExtensions::<TokenAccountState>::unpack(&data).unwrap();
    u64::from(
        parsed
            .get_extension::<TransferFeeAmount>()
            .unwrap()
            .withheld_amount,
    )
}

#[test]
fn new_accounts_open_frozen_and_cannot_receive() {
    let mut env = Env::new();
    let mint = create_remittance_mint(&mut env);
    let alice = Keypair::new();
    let account = create_ata(&mut env, &mint.pubkey(), &alice.pubkey());

    assert!(is_frozen(&env, &account));

    let mint_to = t22new::instruction::mint_to_checked(
        &token_program(),
        &mint.pubkey(),
        &account,
        &mint.issuer.pubkey(),
        &[],
        1_000,
        DECIMALS,
    )
    .unwrap();
    assert!(
        env.send(&[mint_to], &[&mint.issuer]).is_err(),
        "the KYC gate should hold until the account is thawed"
    );
}

#[test]
fn thawing_clears_exactly_one_account() {
    let mut env = Env::new();
    let mint = create_remittance_mint(&mut env);
    let alice = Keypair::new();
    let bob = Keypair::new();
    let alice_account = create_ata(&mut env, &mint.pubkey(), &alice.pubkey());
    let bob_account = create_ata(&mut env, &mint.pubkey(), &bob.pubkey());

    env.call(
        t22_accounts::ThawAfterKyc {
            token_account: alice_account,
            mint: mint.pubkey(),
            freeze_authority: mint.issuer.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::ThawAfterKyc {},
        &[&mint.issuer],
    )
    .expect("thaw failed");

    assert!(!is_frozen(&env, &alice_account));
    assert!(
        is_frozen(&env, &bob_account),
        "thawing Alice must not clear Bob"
    );

    mint_to(
        &mut env,
        &mint.pubkey(),
        &alice_account,
        &mint.issuer,
        1_000,
    );
    assert_eq!(balance(&env, &alice_account), 1_000);
}

#[test]
fn an_account_owner_cannot_thaw_their_own_account() {
    let mut env = Env::new();
    let mint = create_remittance_mint(&mut env);
    let alice = Keypair::new();
    let account = create_ata(&mut env, &mint.pubkey(), &alice.pubkey());

    assert!(env
        .call(
            t22_accounts::ThawAfterKyc {
                token_account: account,
                mint: mint.pubkey(),
                freeze_authority: alice.pubkey(),
                token_program: token_program(),
            },
            t22::instruction::ThawAfterKyc {},
            &[&alice],
        )
        .is_err());
}

#[test]
fn changing_the_default_state_does_not_thaw_existing_accounts() {
    let mut env = Env::new();
    let mint = create_remittance_mint(&mut env);
    let alice = Keypair::new();
    let bob = Keypair::new();
    let alice_account = create_ata(&mut env, &mint.pubkey(), &alice.pubkey());

    env.call(
        t22_accounts::SetDefaultState {
            mint: mint.pubkey(),
            freeze_authority: mint.issuer.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::SetDefaultAccountState { frozen: false },
        &[&mint.issuer],
    )
    .expect("default state update failed");

    assert!(
        is_frozen(&env, &alice_account),
        "a policy change must not thaw an existing account"
    );

    let bob_account = create_ata(&mut env, &mint.pubkey(), &bob.pubkey());
    assert!(!is_frozen(&env, &bob_account));
}

#[test]
fn a_transfer_debits_the_gross_and_parks_the_fee_on_the_destination() {
    let mut env = Env::new();
    let mint = create_remittance_mint(&mut env);
    let alice = Keypair::new();
    let bob = Keypair::new();
    let source = open_and_kyc(&mut env, &mint.pubkey(), &alice.pubkey(), &mint.issuer);
    let destination = open_and_kyc(&mut env, &mint.pubkey(), &bob.pubkey(), &mint.issuer);
    mint_to(&mut env, &mint.pubkey(), &source, &mint.issuer, 1_000_000);

    let amount = 100_000;
    env.call(
        t22_accounts::TransferWithFee {
            source,
            mint: mint.pubkey(),
            destination,
            authority: alice.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::TransferWithFee { amount },
        &[&alice],
    )
    .expect("transfer failed");

    let fee = 500; // 0.5% of 100_000, under the cap
    assert_eq!(balance(&env, &source), 1_000_000 - amount);
    // The destination gets the net; the fee sits beside it, not inside it.
    assert_eq!(balance(&env, &destination), amount - fee);
    assert_eq!(withheld(&env, &destination), fee);
    assert_eq!(
        balance(&env, &destination) + withheld(&env, &destination),
        amount
    );
}

#[test]
fn the_fee_is_capped() {
    let mut env = Env::new();
    let mint = create_remittance_mint(&mut env);
    let alice = Keypair::new();
    let source = open_and_kyc(&mut env, &mint.pubkey(), &alice.pubkey(), &mint.issuer);
    let destination = open_and_kyc(
        &mut env,
        &mint.pubkey(),
        &Keypair::new().pubkey(),
        &mint.issuer,
    );
    mint_to(&mut env, &mint.pubkey(), &source, &mint.issuer, 100_000_000);

    env.call(
        t22_accounts::TransferWithFee {
            source,
            mint: mint.pubkey(),
            destination,
            authority: alice.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::TransferWithFee { amount: 50_000_000 },
        &[&alice],
    )
    .expect("transfer failed");

    assert_eq!(withheld(&env, &destination), MAX_FEE);
}

#[test]
fn a_frozen_account_cannot_send() {
    let mut env = Env::new();
    let mint = create_remittance_mint(&mut env);
    let alice = Keypair::new();
    let source = open_and_kyc(&mut env, &mint.pubkey(), &alice.pubkey(), &mint.issuer);
    let destination = open_and_kyc(
        &mut env,
        &mint.pubkey(),
        &Keypair::new().pubkey(),
        &mint.issuer,
    );
    mint_to(&mut env, &mint.pubkey(), &source, &mint.issuer, 100_000);

    let freeze = t22new::instruction::freeze_account(
        &token_program(),
        &source,
        &mint.pubkey(),
        &mint.issuer.pubkey(),
        &[],
    )
    .unwrap();
    env.send(&[freeze], &[&mint.issuer]).expect("freeze failed");

    assert!(env
        .call(
            t22_accounts::TransferWithFee {
                source,
                mint: mint.pubkey(),
                destination,
                authority: alice.pubkey(),
                token_program: token_program(),
            },
            t22::instruction::TransferWithFee { amount: 10_000 },
            &[&alice],
        )
        .is_err());
    assert_eq!(balance(&env, &source), 100_000);
}

#[test]
fn the_permanent_delegate_moves_funds_without_the_owner() {
    let mut env = Env::new();
    let mint = create_confidential_mint(&mut env, [5u8; 32], None);
    let alice = Keypair::new();
    let sanctioned = open_and_kyc(&mut env, &mint.pubkey(), &alice.pubkey(), &mint.issuer);
    let treasury = open_and_kyc(
        &mut env,
        &mint.pubkey(),
        &mint.issuer.pubkey(),
        &mint.issuer,
    );
    mint_to(
        &mut env,
        &mint.pubkey(),
        &sanctioned,
        &mint.issuer,
        1_000_000,
    );

    env.call(
        t22_accounts::Seize {
            source: sanctioned,
            mint: mint.pubkey(),
            destination: treasury,
            permanent_delegate: mint.issuer.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::Seize { amount: 250_000 },
        &[&mint.issuer],
    )
    .expect("seizure failed");

    assert_eq!(balance(&env, &sanctioned), 750_000);
    // The fee applies to a seizure too: 0.5% of 250_000 is 1_250, under the cap.
    assert_eq!(withheld(&env, &treasury), 1_250);
    assert_eq!(balance(&env, &treasury), 250_000 - 1_250);
}

#[test]
fn seizure_is_refused_for_a_key_that_is_not_the_delegate() {
    let mut env = Env::new();
    let mint = create_confidential_mint(&mut env, [5u8; 32], None);
    let alice = Keypair::new();
    let impostor = Keypair::new();
    env.svm.airdrop(&impostor.pubkey(), 1_000_000_000).unwrap();
    let sanctioned = open_and_kyc(&mut env, &mint.pubkey(), &alice.pubkey(), &mint.issuer);
    let treasury = open_and_kyc(
        &mut env,
        &mint.pubkey(),
        &mint.issuer.pubkey(),
        &mint.issuer,
    );
    mint_to(
        &mut env,
        &mint.pubkey(),
        &sanctioned,
        &mint.issuer,
        1_000_000,
    );

    assert!(env
        .call(
            t22_accounts::Seize {
                source: sanctioned,
                mint: mint.pubkey(),
                destination: treasury,
                permanent_delegate: impostor.pubkey(),
                token_program: token_program(),
            },
            t22::instruction::Seize { amount: 1 },
            &[&impostor],
        )
        .is_err());
    assert_eq!(balance(&env, &sanctioned), 1_000_000);
}

#[test]
fn a_mint_without_a_delegate_cannot_be_seized_from() {
    let mut env = Env::new();
    let mint = create_remittance_mint(&mut env);
    let alice = Keypair::new();
    let account = open_and_kyc(&mut env, &mint.pubkey(), &alice.pubkey(), &mint.issuer);

    assert!(env
        .call(
            t22_accounts::Seize {
                source: account,
                mint: mint.pubkey(),
                destination: account,
                permanent_delegate: mint.issuer.pubkey(),
                token_program: token_program(),
            },
            t22::instruction::Seize { amount: 1 },
            &[&mint.issuer],
        )
        .is_err());
}

#[test]
fn seizure_cannot_reach_a_frozen_account() {
    let mut env = Env::new();
    let mint = create_confidential_mint(&mut env, [5u8; 32], None);
    let alice = Keypair::new();
    let sanctioned = open_and_kyc(&mut env, &mint.pubkey(), &alice.pubkey(), &mint.issuer);
    let treasury = open_and_kyc(
        &mut env,
        &mint.pubkey(),
        &mint.issuer.pubkey(),
        &mint.issuer,
    );
    mint_to(
        &mut env,
        &mint.pubkey(),
        &sanctioned,
        &mint.issuer,
        1_000_000,
    );

    let freeze = t22new::instruction::freeze_account(
        &token_program(),
        &sanctioned,
        &mint.pubkey(),
        &mint.issuer.pubkey(),
        &[],
    )
    .unwrap();
    env.send(&[freeze], &[&mint.issuer]).expect("freeze failed");

    assert!(env
        .call(
            t22_accounts::Seize {
                source: sanctioned,
                mint: mint.pubkey(),
                destination: treasury,
                permanent_delegate: mint.issuer.pubkey(),
                token_program: token_program(),
            },
            t22::instruction::Seize { amount: 250_000 },
            &[&mint.issuer],
        )
        .is_err());
    assert_eq!(balance(&env, &sanctioned), 1_000_000);
}
