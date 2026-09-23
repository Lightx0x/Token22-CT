//! Task 6: the confidential lifecycle on the re-issued mint, and the gap
//! between a seizure authority and a hidden balance.

mod common;

use {
    common::*,
    solana_keypair::Keypair,
    solana_pubkey::Pubkey,
    solana_signer::Signer,
    token22_ct::{
        confidential::{self, ConfidentialKeys, TransferProofAccounts, WithdrawProofAccounts},
        kyc, state, transfer, Error,
    },
};

struct Holder {
    owner: Keypair,
    account: Pubkey,
    keys: ConfidentialKeys,
}

/// Steps 1–5: open, KYC, reallocate, configure, approve.
fn onboard(env: &mut Env, v2: &MintV2) -> Holder {
    let owner = Keypair::new();
    let mint = v2.mint.pubkey();
    let mint_data = env.data(&mint);

    let (account, open) =
        confidential::open_account(&env.payer.pubkey(), &owner.pubkey(), &mint, &mint_data)
            .unwrap();
    env.run_all(&open, &[&owner]);

    let thaw = kyc::thaw_after_kyc(&mint, &account, &v2.issuer.pubkey()).unwrap();
    env.send(&[thaw], &[&v2.issuer]).expect("thaw failed");
    env.svm.expire_blockhash();

    let keys = ConfidentialKeys::derive(&owner, &account).unwrap();
    let configure =
        confidential::configure_account(&account, &mint, &owner.pubkey(), &keys, None).unwrap();
    env.run(&configure, &[&owner]).expect("configure failed");
    env.svm.expire_blockhash();

    let approve = confidential::approve_account(&account, &mint, &v2.issuer.pubkey()).unwrap();
    env.run(&approve, &[&v2.issuer]).expect("approve failed");
    env.svm.expire_blockhash();

    Holder {
        owner,
        account,
        keys,
    }
}

fn balances(env: &Env, holder: &Holder) -> confidential::ConfidentialBalances {
    confidential::decrypt_balances(&env.data(&holder.account), &holder.keys).unwrap()
}

fn deposit_and_apply(env: &mut Env, v2: &MintV2, holder: &Holder, amount: u64) {
    let mint = v2.mint.pubkey();
    let deposit = confidential::deposit(
        &holder.account,
        &mint,
        &env.data(&mint),
        &holder.owner.pubkey(),
        amount,
    )
    .unwrap();
    env.run(&deposit, &[&holder.owner]).expect("deposit failed");
    env.svm.expire_blockhash();

    let apply = confidential::apply_pending_balance(
        &holder.account,
        &env.data(&holder.account),
        &holder.owner.pubkey(),
        &holder.keys,
    )
    .unwrap();
    env.run(&apply, &[&holder.owner]).expect("apply failed");
    env.svm.expire_blockhash();
}

// --- the authority model -------------------------------------------------

/// Step 1 is permissionless; step 4 is not.
#[test]
fn opening_an_account_is_permissionless_but_configuring_it_is_owner_only() {
    let mut env = Env::new();
    let v2 = create_mint_v2(&mut env);
    let owner = Keypair::new();
    let mint = v2.mint.pubkey();
    let mint_data = env.data(&mint);

    let (account, open) =
        confidential::open_account(&env.payer.pubkey(), &owner.pubkey(), &mint, &mint_data)
            .unwrap();

    // Creating the ATA needs nobody but the payer — a relayer can open an
    // account for a user who holds no SOL.
    assert!(open[0].signers.is_empty());
    // Growing it does need the owner.
    assert_eq!(open[1].signers, vec![owner.pubkey()]);
    env.run_all(&open, &[&owner]);

    let keys = ConfidentialKeys::derive(&owner, &account).unwrap();
    let configure =
        confidential::configure_account(&account, &mint, &owner.pubkey(), &keys, None).unwrap();
    assert_eq!(configure.signers, vec![owner.pubkey()]);

    // The payer that created the account cannot configure it: the processor
    // validates the authority against the token account's own owner field.
    let payer_keys = ConfidentialKeys::derive(&env.payer, &account).unwrap();
    let impostor =
        confidential::configure_account(&account, &mint, &env.payer.pubkey(), &payer_keys, None)
            .unwrap();
    assert!(
        env.send(&impostor.instructions, &[]).is_err(),
        "ConfigureAccount must reject an authority that is not the account owner"
    );
    env.svm.expire_blockhash();

    env.run(&configure, &[&owner]).expect("configure failed");
}

/// Reallocate, configure and approve all work on a frozen account; only value
/// movement checks the freeze flag.
#[test]
fn confidential_setup_precedes_the_kyc_thaw() {
    let mut env = Env::new();
    let v2 = create_mint_v2(&mut env);
    let owner = Keypair::new();
    let mint = v2.mint.pubkey();
    let mint_data = env.data(&mint);

    let (account, open) =
        confidential::open_account(&env.payer.pubkey(), &owner.pubkey(), &mint, &mint_data)
            .unwrap();
    env.run_all(&open, &[&owner]);
    assert!(state::is_frozen(&env.data(&account)).unwrap());

    let keys = ConfidentialKeys::derive(&owner, &account).unwrap();
    let configure =
        confidential::configure_account(&account, &mint, &owner.pubkey(), &keys, None).unwrap();
    env.run(&configure, &[&owner])
        .expect("ConfigureAccount should not care about the freeze flag");
    env.svm.expire_blockhash();

    let approve = confidential::approve_account(&account, &mint, &v2.issuer.pubkey()).unwrap();
    env.run(&approve, &[&v2.issuer])
        .expect("ApproveAccount should not care about the freeze flag");
    env.svm.expire_blockhash();

    // Depositing does.
    let deposit = confidential::deposit(&account, &mint, &mint_data, &owner.pubkey(), 1).unwrap();
    assert!(env.run(&deposit, &[&owner]).is_err());
}

/// approve_policy = manual means a configured account is inert until approved.
#[test]
fn an_unapproved_account_cannot_take_a_deposit() {
    let mut env = Env::new();
    let v2 = create_mint_v2(&mut env);
    let owner = Keypair::new();
    let mint = v2.mint.pubkey();
    let mint_data = env.data(&mint);

    let (account, open) =
        confidential::open_account(&env.payer.pubkey(), &owner.pubkey(), &mint, &mint_data)
            .unwrap();
    env.run_all(&open, &[&owner]);
    let thaw = kyc::thaw_after_kyc(&mint, &account, &v2.issuer.pubkey()).unwrap();
    env.send(&[thaw], &[&v2.issuer]).expect("thaw failed");
    env.svm.expire_blockhash();

    let keys = ConfidentialKeys::derive(&owner, &account).unwrap();
    let configure =
        confidential::configure_account(&account, &mint, &owner.pubkey(), &keys, None).unwrap();
    env.run(&configure, &[&owner]).expect("configure failed");
    env.svm.expire_blockhash();

    assert!(
        !bool::from(
            state::confidential_transfer_account(&env.data(&account))
                .unwrap()
                .approved
        ),
        "manual policy must leave the account unapproved"
    );

    mint_to(&mut env, &mint, &account, &v2.issuer, 10_000);
    let deposit =
        confidential::deposit(&account, &mint, &mint_data, &owner.pubkey(), 1_000).unwrap();
    assert!(
        env.run(&deposit, &[&owner]).is_err(),
        "an unapproved account must not accept confidential credits"
    );
    env.svm.expire_blockhash();

    // The issuer's approval is what opens it.
    let approve = confidential::approve_account(&account, &mint, &v2.issuer.pubkey()).unwrap();
    env.run(&approve, &[&v2.issuer]).expect("approve failed");
    env.svm.expire_blockhash();
    let deposit =
        confidential::deposit(&account, &mint, &mint_data, &owner.pubkey(), 1_000).unwrap();
    env.run(&deposit, &[&owner])
        .expect("an approved account should accept a deposit");
}

// --- deposit, apply, withdraw -------------------------------------------

#[test]
fn deposit_lands_in_pending_and_apply_makes_it_spendable() {
    let mut env = Env::new();
    let v2 = create_mint_v2(&mut env);
    let alice = onboard(&mut env, &v2);
    let mint = v2.mint.pubkey();
    mint_to(&mut env, &mint, &alice.account, &v2.issuer, 1_000_000);

    let deposit = confidential::deposit(
        &alice.account,
        &mint,
        &env.data(&mint),
        &alice.owner.pubkey(),
        600_000,
    )
    .unwrap();
    env.run(&deposit, &[&alice.owner]).expect("deposit failed");
    env.svm.expire_blockhash();

    // The public balance shrank; the value is pending, not yet spendable.
    assert_eq!(balance(&env, &alice.account), 400_000);
    let before = balances(&env, &alice);
    assert_eq!(before.available, 0);
    assert_eq!(before.pending, 600_000);
    assert_eq!(before.pending_credit_counter, 1);

    let apply = confidential::apply_pending_balance(
        &alice.account,
        &env.data(&alice.account),
        &alice.owner.pubkey(),
        &alice.keys,
    )
    .unwrap();
    env.run(&apply, &[&alice.owner]).expect("apply failed");
    env.svm.expire_blockhash();

    let after = balances(&env, &alice);
    assert_eq!(after.available, 600_000);
    assert_eq!(after.pending, 0);
    // The counter the caller quoted is the counter that applied: no credit
    // slipped in between reading and submitting.
    assert_eq!(
        after.last_expected_credit_counter,
        after.last_applied_credit_counter
    );
}

#[test]
fn withdraw_returns_value_to_the_public_balance() {
    let mut env = Env::new();
    let v2 = create_mint_v2(&mut env);
    let alice = onboard(&mut env, &v2);
    let mint = v2.mint.pubkey();
    mint_to(&mut env, &mint, &alice.account, &v2.issuer, 1_000_000);
    deposit_and_apply(&mut env, &v2, &alice, 600_000);

    let contexts = (Keypair::new(), Keypair::new());
    let steps = confidential::withdraw(
        &env.payer.pubkey(),
        &alice.account,
        &env.data(&alice.account),
        &mint,
        &env.data(&mint),
        &alice.owner.pubkey(),
        &alice.keys,
        200_000,
        &WithdrawProofAccounts {
            equality: contexts.0.pubkey(),
            range: contexts.1.pubkey(),
        },
        &env.rent(),
    )
    .unwrap();
    env.run_all(&steps, &[&alice.owner, &contexts.0, &contexts.1]);

    assert_eq!(balance(&env, &alice.account), 400_000 + 200_000);
    assert_eq!(balances(&env, &alice).available, 400_000);

    // The proof context accounts were closed again, so their rent came back.
    assert!(env
        .svm
        .get_account(&contexts.0.pubkey())
        .is_none_or(|a| a.lamports == 0));
    assert!(env
        .svm
        .get_account(&contexts.1.pubkey())
        .is_none_or(|a| a.lamports == 0));
}

/// Withdrawal spends the available balance, so a pending credit would make the
/// equality proof stale. The builder refuses rather than producing one.
#[test]
fn withdraw_refuses_while_a_pending_balance_is_unapplied() {
    let mut env = Env::new();
    let v2 = create_mint_v2(&mut env);
    let alice = onboard(&mut env, &v2);
    let mint = v2.mint.pubkey();
    mint_to(&mut env, &mint, &alice.account, &v2.issuer, 1_000_000);

    let deposit = confidential::deposit(
        &alice.account,
        &mint,
        &env.data(&mint),
        &alice.owner.pubkey(),
        600_000,
    )
    .unwrap();
    env.run(&deposit, &[&alice.owner]).expect("deposit failed");
    env.svm.expire_blockhash();

    let err = confidential::withdraw(
        &env.payer.pubkey(),
        &alice.account,
        &env.data(&alice.account),
        &mint,
        &env.data(&mint),
        &alice.owner.pubkey(),
        &alice.keys,
        100_000,
        &WithdrawProofAccounts {
            equality: Keypair::new().pubkey(),
            range: Keypair::new().pubkey(),
        },
        &env.rent(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::PendingBalanceNotApplied), "got {err}");

    // Applying first clears the way.
    let apply = confidential::apply_pending_balance(
        &alice.account,
        &env.data(&alice.account),
        &alice.owner.pubkey(),
        &alice.keys,
    )
    .unwrap();
    env.run(&apply, &[&alice.owner]).expect("apply failed");
    env.svm.expire_blockhash();

    let contexts = (Keypair::new(), Keypair::new());
    let steps = confidential::withdraw(
        &env.payer.pubkey(),
        &alice.account,
        &env.data(&alice.account),
        &mint,
        &env.data(&mint),
        &alice.owner.pubkey(),
        &alice.keys,
        100_000,
        &WithdrawProofAccounts {
            equality: contexts.0.pubkey(),
            range: contexts.1.pubkey(),
        },
        &env.rent(),
    )
    .unwrap();
    env.run_all(&steps, &[&alice.owner, &contexts.0, &contexts.1]);
    assert_eq!(balances(&env, &alice).available, 500_000);
}

#[test]
fn withdraw_refuses_more_than_the_available_balance() {
    let mut env = Env::new();
    let v2 = create_mint_v2(&mut env);
    let alice = onboard(&mut env, &v2);
    let mint = v2.mint.pubkey();
    mint_to(&mut env, &mint, &alice.account, &v2.issuer, 1_000_000);
    deposit_and_apply(&mut env, &v2, &alice, 100_000);

    let err = confidential::withdraw(
        &env.payer.pubkey(),
        &alice.account,
        &env.data(&alice.account),
        &mint,
        &env.data(&mint),
        &alice.owner.pubkey(),
        &alice.keys,
        100_001,
        &WithdrawProofAccounts {
            equality: Keypair::new().pubkey(),
            range: Keypair::new().pubkey(),
        },
        &env.rent(),
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            Error::InsufficientConfidentialBalance {
                available: 100_000,
                requested: 100_001
            }
        ),
        "got {err}"
    );
}

// --- the transfer --------------------------------------------------------

#[test]
fn a_confidential_transfer_moves_value_without_publishing_the_amount() {
    let mut env = Env::new();
    let v2 = create_mint_v2(&mut env);
    let alice = onboard(&mut env, &v2);
    let bob = onboard(&mut env, &v2);
    let mint = v2.mint.pubkey();

    mint_to(&mut env, &mint, &alice.account, &v2.issuer, 1_000_000);
    deposit_and_apply(&mut env, &v2, &alice, 1_000_000);
    assert_eq!(balance(&env, &alice.account), 0);

    let amount = 100_000;
    let expected_fee = transfer::quote(&env.data(&mint), env.epoch(), amount)
        .unwrap()
        .fee;

    // One fresh account per proof. Five of them, because the mint charges a
    // fee — see `transfer_on_a_fee_mint_needs_the_fee_proof_contexts`.
    let ctx: Vec<Keypair> = (0..5).map(|_| Keypair::new()).collect();
    let steps = confidential::transfer(
        &env.payer.pubkey(),
        &alice.account,
        &env.data(&alice.account),
        &bob.account,
        &env.data(&bob.account),
        &mint,
        &env.data(&mint),
        &alice.owner.pubkey(),
        &alice.keys,
        amount,
        env.epoch(),
        &TransferProofAccounts {
            equality: ctx[0].pubkey(),
            transfer_amount_validity: ctx[1].pubkey(),
            range: ctx[2].pubkey(),
            fee_sigma: Some(ctx[3].pubkey()),
            fee_validity: Some(ctx[4].pubkey()),
        },
        &env.rent(),
    )
    .unwrap();

    let mut signers: Vec<&Keypair> = vec![&alice.owner];
    signers.extend(ctx.iter());
    env.run_all(&steps, &signers);

    // The sender is debited the full amount; the fee is taken on the far side.
    assert_eq!(balances(&env, &alice).available, 900_000);

    // Nothing about the amount is visible in either public balance.
    assert_eq!(balance(&env, &alice.account), 0);
    assert_eq!(balance(&env, &bob.account), 0);

    // Bob sees it as a pending credit until he applies it.
    let bob_pending = balances(&env, &bob);
    assert_eq!(bob_pending.available, 0);
    assert_eq!(bob_pending.pending, amount - expected_fee);

    let apply = confidential::apply_pending_balance(
        &bob.account,
        &env.data(&bob.account),
        &bob.owner.pubkey(),
        &bob.keys,
    )
    .unwrap();
    env.run(&apply, &[&bob.owner]).expect("apply failed");
    env.svm.expire_blockhash();
    assert_eq!(balances(&env, &bob).available, amount - expected_fee);
}

/// On a fee-bearing mint only `TransferWithFee` is accepted, and it needs two
/// extra proof contexts. The builder says so instead of emitting a transfer the
/// chain would reject.
#[test]
fn transfer_on_a_fee_mint_needs_the_fee_proof_contexts() {
    let mut env = Env::new();
    let v2 = create_mint_v2(&mut env);
    let alice = onboard(&mut env, &v2);
    let bob = onboard(&mut env, &v2);
    let mint = v2.mint.pubkey();
    mint_to(&mut env, &mint, &alice.account, &v2.issuer, 1_000_000);
    deposit_and_apply(&mut env, &v2, &alice, 1_000_000);

    let err = confidential::transfer(
        &env.payer.pubkey(),
        &alice.account,
        &env.data(&alice.account),
        &bob.account,
        &env.data(&bob.account),
        &mint,
        &env.data(&mint),
        &alice.owner.pubkey(),
        &alice.keys,
        10_000,
        env.epoch(),
        &TransferProofAccounts {
            equality: Keypair::new().pubkey(),
            transfer_amount_validity: Keypair::new().pubkey(),
            range: Keypair::new().pubkey(),
            fee_sigma: None,
            fee_validity: None,
        },
        &env.rent(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::MissingExtension(_)), "got {err}");
}

// --- the gap -------------------------------------------------------------

/// The second half of the gap: the seizure authority cannot follow funds into
/// a confidential balance.
#[test]
fn the_permanent_delegate_cannot_reach_a_confidential_balance() {
    let mut env = Env::new();
    let v2 = create_mint_v2(&mut env);
    let alice = onboard(&mut env, &v2);
    let mint = v2.mint.pubkey();
    let treasury = open_and_kyc(&mut env, &mint, &v2.issuer.pubkey(), &v2.issuer);
    mint_to(&mut env, &mint, &alice.account, &v2.issuer, 1_000_000);

    // While the balance is public, seizure works.
    let (seize, _) = transfer::seize_with_permanent_delegate(
        &mint,
        &env.data(&mint),
        &alice.account,
        &treasury,
        &v2.delegate.pubkey(),
        100_000,
        env.epoch(),
    )
    .unwrap();
    env.send(&[seize], &[&v2.delegate])
        .expect("seizing a public balance should work");
    env.svm.expire_blockhash();
    assert_eq!(balance(&env, &alice.account), 900_000);

    // Alice moves the rest into her confidential balance.
    deposit_and_apply(&mut env, &v2, &alice, 900_000);
    assert_eq!(balance(&env, &alice.account), 0);
    assert_eq!(balances(&env, &alice).available, 900_000);

    // The same seizure now has nothing to take: the tokens are still in the
    // account, but only as ciphertext.
    let (seize, _) = transfer::seize_with_permanent_delegate(
        &mint,
        &env.data(&mint),
        &alice.account,
        &treasury,
        &v2.delegate.pubkey(),
        100_000,
        env.epoch(),
    )
    .unwrap();
    assert!(
        env.send(&[seize], &[&v2.delegate]).is_err(),
        "the permanent delegate should not be able to seize a confidential balance"
    );
    env.svm.expire_blockhash();

    // Nor can the delegate build a confidential transfer: the proofs need
    // Alice's ElGamal secret, and keys derived from the delegate's wallet
    // decrypt nothing.
    let delegate_keys = ConfidentialKeys::derive(&v2.delegate, &alice.account).unwrap();
    assert!(
        confidential::decrypt_balances(&env.data(&alice.account), &delegate_keys).is_err(),
        "the delegate must not be able to read the balance it would need to prove over"
    );

    // What the issuer *can* still do unilaterally is contain the account.
    let freeze = kyc::freeze(&mint, &alice.account, &v2.issuer.pubkey()).unwrap();
    env.send(&[freeze], &[&v2.issuer]).expect("freeze failed");
    env.svm.expire_blockhash();
    assert!(state::is_frozen(&env.data(&alice.account)).unwrap());

    // Frozen, Alice cannot withdraw the hidden balance back out either.
    let contexts = (Keypair::new(), Keypair::new());
    let steps = confidential::withdraw(
        &env.payer.pubkey(),
        &alice.account,
        &env.data(&alice.account),
        &mint,
        &env.data(&mint),
        &alice.owner.pubkey(),
        &alice.keys,
        900_000,
        &WithdrawProofAccounts {
            equality: contexts.0.pubkey(),
            range: contexts.1.pubkey(),
        },
        &env.rent(),
    )
    .unwrap();
    let last = steps.len() - 2; // the withdraw itself, before the close step
    for step in &steps[..last] {
        env.run(step, &[&alice.owner, &contexts.0, &contexts.1])
            .expect("proof setup should still work");
        env.svm.expire_blockhash();
    }
    assert!(
        env.run(&steps[last], &[&alice.owner]).is_err(),
        "a frozen account cannot move value, confidential or not"
    );
}
