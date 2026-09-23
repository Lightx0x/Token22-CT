//! Task 2: `TransferCheckedWithFee`, an epoch-accurate fee, and the
//! permanent-delegate seizure that reuses the same instruction.

mod common;

use {
    common::*,
    solana_keypair::Keypair,
    solana_signer::Signer,
    spl_token_2022_interface::{
        extension::{
            transfer_fee::{self, TransferFeeAmount},
            BaseStateWithExtensions,
        },
        instruction::TokenInstruction,
    },
    token22_ct::{state, transfer, Error},
};

fn withheld(env: &Env, account: &solana_pubkey::Pubkey) -> u64 {
    let data = env.data(account);
    let parsed = state::token_account(&data).unwrap();
    u64::from(
        parsed
            .get_extension::<TransferFeeAmount>()
            .unwrap()
            .withheld_amount,
    )
}

// --- the fee calculation -------------------------------------------------

#[test]
fn quote_agrees_with_the_extension_for_every_shape_of_amount() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let data = env.data(&v1.mint.pubkey());
    let config = state::transfer_fee_config(&data).unwrap();
    let epoch = env.epoch();

    for amount in [
        0,
        1,
        199,        // rounds up: 0.5% of 199 is 0.995
        200,        // exactly 1
        100_000,    // 500, under the cap
        1_000_000,  // 5_000, exactly the cap
        50_000_000, // far over the cap
        u64::MAX / 2,
    ] {
        let quote = transfer::quote(&data, epoch, amount).unwrap();
        assert_eq!(
            quote.fee,
            config.calculate_epoch_fee(epoch, amount).unwrap(),
            "quote disagreed with the extension at amount {amount}"
        );
        assert_eq!(quote.amount, amount);
        assert_eq!(quote.net_received, amount - quote.fee);
        assert!(quote.fee <= MAX_FEE);
    }
}

/// The reason a cached rate is not good enough.
///
/// `SetTransferFee` writes the new schedule as `newer_transfer_fee`, tagged
/// with the epoch it activates in, and leaves the current one in place as
/// `older_transfer_fee`. One mint account therefore answers differently
/// depending on the epoch asked about.
#[test]
fn the_fee_follows_the_epoch_schedule_not_a_cached_rate() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let epoch = env.epoch();

    let new_bps = 250u16;
    let new_cap = 90_000u64;
    let set = transfer_fee::instruction::set_transfer_fee(
        &spl_token_2022_interface::id(),
        &v1.mint.pubkey(),
        &v1.issuer.pubkey(),
        &[],
        new_bps,
        new_cap,
    )
    .unwrap();
    env.send(&[set], &[&v1.issuer])
        .expect("set_transfer_fee failed");
    env.svm.expire_blockhash();

    let data = env.data(&v1.mint.pubkey());
    let config = state::transfer_fee_config(&data).unwrap();
    let activation: u64 = config.newer_transfer_fee.epoch.into();
    assert!(
        activation > epoch,
        "a new schedule should activate in a later epoch, not immediately"
    );

    let amount = 1_000_000;
    // Same account data, two different answers.
    let now = transfer::quote(&data, epoch, amount).unwrap();
    let later = transfer::quote(&data, activation, amount).unwrap();

    assert_eq!(
        now.fee, MAX_FEE,
        "the old schedule still applies this epoch"
    );
    assert_eq!(later.fee, amount * u64::from(new_bps) / 10_000);
    assert_ne!(now.fee, later.fee);
    assert_eq!(now.epoch, epoch);
    assert_eq!(later.epoch, activation);
}

// --- the instruction itself ---------------------------------------------

#[test]
fn transfers_use_transfer_checked_with_fee() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let alice = Keypair::new();
    let (source, destination) = (
        open_and_kyc(&mut env, &v1.mint.pubkey(), &alice.pubkey(), &v1.issuer),
        open_and_kyc(
            &mut env,
            &v1.mint.pubkey(),
            &Keypair::new().pubkey(),
            &v1.issuer,
        ),
    );

    let (instruction, _) = transfer::transfer_checked_with_fee(
        &v1.mint.pubkey(),
        &env.data(&v1.mint.pubkey()),
        &source,
        &destination,
        &alice.pubkey(),
        &[],
        100_000,
        env.epoch(),
    )
    .unwrap();

    // Not `Transfer` (tag 3) and not `TransferChecked` (tag 12): this is the
    // transfer-fee extension's own variant.
    assert!(matches!(
        TokenInstruction::unpack(&instruction.data),
        Ok(TokenInstruction::TransferFeeExtension)
    ));
    // Sub-discriminator 1 inside that extension is TransferCheckedWithFee
    // (0 is InitializeTransferFeeConfig).
    assert_eq!(instruction.data[1], 1);
    // Decimals were read from the mint, not taken on trust.
    assert_eq!(instruction.data[10], DECIMALS);
}

#[test]
fn a_transfer_debits_the_amount_and_withholds_the_fee_in_the_destination() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let alice = Keypair::new();
    let bob = Keypair::new();
    let source = open_and_kyc(&mut env, &v1.mint.pubkey(), &alice.pubkey(), &v1.issuer);
    let destination = open_and_kyc(&mut env, &v1.mint.pubkey(), &bob.pubkey(), &v1.issuer);
    mint_to(&mut env, &v1.mint.pubkey(), &source, &v1.issuer, 1_000_000);

    let amount = 100_000;
    let (instruction, quote) = transfer::transfer_checked_with_fee(
        &v1.mint.pubkey(),
        &env.data(&v1.mint.pubkey()),
        &source,
        &destination,
        &alice.pubkey(),
        &[],
        amount,
        env.epoch(),
    )
    .unwrap();
    env.send(&[instruction], &[&alice])
        .expect("transfer failed");
    env.svm.expire_blockhash();

    assert_eq!(quote.fee, 500); // 0.5% of 100_000, under the cap
                                // The source is debited the gross amount.
    assert_eq!(balance(&env, &source), 1_000_000 - amount);
    // The destination's spendable balance is the *net*: the withheld fee is
    // tracked in the TransferFeeAmount extension, outside `amount`, until the
    // issuer harvests it. So the two together account for the gross.
    assert_eq!(balance(&env, &destination), quote.net_received);
    assert_eq!(withheld(&env, &destination), quote.fee);
    assert_eq!(
        balance(&env, &destination) + withheld(&env, &destination),
        amount
    );
}

/// The whole reason for choosing the explicit-fee variant.
#[test]
fn an_incorrect_fee_is_rejected_rather_than_silently_adjusted() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let alice = Keypair::new();
    let source = open_and_kyc(&mut env, &v1.mint.pubkey(), &alice.pubkey(), &v1.issuer);
    let destination = open_and_kyc(
        &mut env,
        &v1.mint.pubkey(),
        &Keypair::new().pubkey(),
        &v1.issuer,
    );
    mint_to(&mut env, &v1.mint.pubkey(), &source, &v1.issuer, 1_000_000);

    let amount = 100_000;
    let correct = transfer::quote(&env.data(&v1.mint.pubkey()), env.epoch(), amount)
        .unwrap()
        .fee;

    // A caller working from a stale rate would quote a different fee here.
    let stale = transfer_fee::instruction::transfer_checked_with_fee(
        &spl_token_2022_interface::id(),
        &source,
        &v1.mint.pubkey(),
        &destination,
        &alice.pubkey(),
        &[],
        amount,
        DECIMALS,
        correct - 1,
    )
    .unwrap();

    assert!(
        env.send(&[stale], &[&alice]).is_err(),
        "the program must reject a fee that disagrees with its own calculation"
    );
    assert_eq!(balance(&env, &source), 1_000_000);
}

#[test]
fn withheld_fees_harvest_back_to_the_issuer() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let alice = Keypair::new();
    let source = open_and_kyc(&mut env, &v1.mint.pubkey(), &alice.pubkey(), &v1.issuer);
    let destination = open_and_kyc(
        &mut env,
        &v1.mint.pubkey(),
        &Keypair::new().pubkey(),
        &v1.issuer,
    );
    let treasury = open_and_kyc(&mut env, &v1.mint.pubkey(), &v1.issuer.pubkey(), &v1.issuer);
    mint_to(&mut env, &v1.mint.pubkey(), &source, &v1.issuer, 1_000_000);

    let (instruction, quote) = transfer::transfer_checked_with_fee(
        &v1.mint.pubkey(),
        &env.data(&v1.mint.pubkey()),
        &source,
        &destination,
        &alice.pubkey(),
        &[],
        400_000,
        env.epoch(),
    )
    .unwrap();
    env.send(&[instruction], &[&alice])
        .expect("transfer failed");
    env.svm.expire_blockhash();

    // Harvesting is permissionless — the payer alone can do it.
    let harvest = transfer::harvest_withheld_to_mint(&v1.mint.pubkey(), &[&destination]).unwrap();
    env.send(&[harvest], &[]).expect("harvest failed");
    env.svm.expire_blockhash();
    assert_eq!(withheld(&env, &destination), 0);

    // Collecting is not: it takes the withdraw-withheld authority.
    let withdraw =
        transfer::withdraw_withheld_from_mint(&v1.mint.pubkey(), &treasury, &v1.issuer.pubkey())
            .unwrap();
    env.send(&[withdraw], &[&v1.issuer])
        .expect("withdraw failed");
    env.svm.expire_blockhash();
    assert_eq!(balance(&env, &treasury), quote.fee);
}

// --- seizure -------------------------------------------------------------

#[test]
fn the_permanent_delegate_moves_funds_without_the_owner() {
    let mut env = Env::new();
    let v2 = create_mint_v2(&mut env);
    let alice = Keypair::new();
    let sanctioned = open_and_kyc(&mut env, &v2.mint.pubkey(), &alice.pubkey(), &v2.issuer);
    let treasury = open_and_kyc(&mut env, &v2.mint.pubkey(), &v2.issuer.pubkey(), &v2.issuer);
    mint_to(
        &mut env,
        &v2.mint.pubkey(),
        &sanctioned,
        &v2.issuer,
        1_000_000,
    );

    let (instruction, quote) = transfer::seize_with_permanent_delegate(
        &v2.mint.pubkey(),
        &env.data(&v2.mint.pubkey()),
        &sanctioned,
        &treasury,
        &v2.delegate.pubkey(),
        250_000,
        env.epoch(),
    )
    .unwrap();

    // Alice never signs.
    env.send(&[instruction], &[&v2.delegate])
        .expect("seizure failed");
    env.svm.expire_blockhash();

    assert_eq!(balance(&env, &sanctioned), 750_000);
    // The fee applies to a seizure too, so the treasury does not receive the
    // gross amount: 0.5% of 250_000 is 1_250, still under the 5_000 cap.
    assert_eq!(quote.fee, 1_250);
    assert!(quote.fee < MAX_FEE);
    assert_eq!(balance(&env, &treasury), quote.net_received);
    assert_eq!(withheld(&env, &treasury), quote.fee);
}

#[test]
fn seizure_is_refused_for_a_key_that_is_not_the_delegate() {
    let mut env = Env::new();
    let v2 = create_mint_v2(&mut env);
    let alice = Keypair::new();
    let account = open_and_kyc(&mut env, &v2.mint.pubkey(), &alice.pubkey(), &v2.issuer);
    let treasury = open_and_kyc(&mut env, &v2.mint.pubkey(), &v2.issuer.pubkey(), &v2.issuer);

    // Holding the mint authority is not holding the seizure authority.
    let err = transfer::seize_with_permanent_delegate(
        &v2.mint.pubkey(),
        &env.data(&v2.mint.pubkey()),
        &account,
        &treasury,
        &v2.issuer.pubkey(),
        1,
        env.epoch(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::MissingExtension(_)), "got {err}");
}

#[test]
fn seizure_needs_a_mint_that_has_a_delegate_at_all() {
    let mut env = Env::new();
    let v1 = create_mint_v1(&mut env);
    let account = open_and_kyc(
        &mut env,
        &v1.mint.pubkey(),
        &Keypair::new().pubkey(),
        &v1.issuer,
    );

    let err = transfer::seize_with_permanent_delegate(
        &v1.mint.pubkey(),
        &env.data(&v1.mint.pubkey()),
        &account,
        &account,
        &Keypair::new().pubkey(),
        1,
        env.epoch(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::MissingExtension(_)), "got {err}");
}

#[test]
fn seizure_cannot_reach_a_frozen_account() {
    let mut env = Env::new();
    let v2 = create_mint_v2(&mut env);
    let alice = Keypair::new();
    let sanctioned = open_and_kyc(&mut env, &v2.mint.pubkey(), &alice.pubkey(), &v2.issuer);
    let treasury = open_and_kyc(&mut env, &v2.mint.pubkey(), &v2.issuer.pubkey(), &v2.issuer);
    mint_to(
        &mut env,
        &v2.mint.pubkey(),
        &sanctioned,
        &v2.issuer,
        1_000_000,
    );

    let freeze =
        token22_ct::kyc::freeze(&v2.mint.pubkey(), &sanctioned, &v2.issuer.pubkey()).unwrap();
    env.send(&[freeze], &[&v2.issuer]).expect("freeze failed");
    env.svm.expire_blockhash();

    let (instruction, _) = transfer::seize_with_permanent_delegate(
        &v2.mint.pubkey(),
        &env.data(&v2.mint.pubkey()),
        &sanctioned,
        &treasury,
        &v2.delegate.pubkey(),
        250_000,
        env.epoch(),
    )
    .unwrap();

    // Freeze first, seize second is the wrong order — the delegate is blocked
    // by the freeze just like the owner is.
    assert!(env.send(&[instruction], &[&v2.delegate]).is_err());
    assert_eq!(balance(&env, &sanctioned), 1_000_000);
}
