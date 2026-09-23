mod common;

use {
    anchor_lang::error::ErrorCode as AnchorError,
    common::*,
    solana_instruction::{AccountMeta, Instruction},
    solana_keypair::Keypair,
    solana_pubkey::Pubkey,
    solana_signer::Signer,
    t22::accounts as t22_accounts,
    t22new::{
        error::TokenError,
        extension::{
            default_account_state::DefaultAccountState, transfer_fee::TransferFeeConfig,
            BaseStateWithExtensions,
        },
        state::AccountState,
    },
};

fn set_default_ix(mint: &Pubkey, authority: &Pubkey, frozen: bool) -> Instruction {
    ix(
        t22_accounts::SetDefaultState {
            mint: *mint,
            freeze_authority: *authority,
            token_program: token_program(),
        },
        t22::instruction::SetDefaultAccountState { frozen },
    )
}

fn default_state(env: &Env, mint: &Pubkey) -> u8 {
    let data = env.data(mint);
    mint_state(&data)
        .get_extension::<DefaultAccountState>()
        .unwrap()
        .state
}

fn harvest_ix(mint: &Pubkey, sources: &[Pubkey]) -> Instruction {
    let mut instruction = ix(
        t22_accounts::HarvestFees {
            mint: *mint,
            token_program: token_program(),
        },
        t22::instruction::HarvestFees {},
    );
    instruction
        .accounts
        .extend(sources.iter().map(|s| AccountMeta::new(*s, false)));
    instruction
}

fn collect_ix(mint: &Pubkey, destination: &Pubkey, authority: &Pubkey) -> Instruction {
    ix(
        t22_accounts::CollectFees {
            mint: *mint,
            destination: *destination,
            withdraw_withheld_authority: *authority,
            token_program: token_program(),
        },
        t22::instruction::CollectFees {},
    )
}

/// thaw_after_kyc and set_default_account_state: thawing clears exactly one
/// account, and the default only ever governs accounts opened afterwards.
#[test]
fn kyc_thaws_one_account_and_the_default_only_governs_new_ones() {
    let mut env = Env::new();
    let mint = create_remittance_mint(&mut env);
    let (m, issuer) = (mint.pubkey(), mint.issuer.pubkey());
    let (alice, bob) = (Keypair::new(), Keypair::new());
    let a = create_ata(&mut env, &m, &alice.pubkey());
    let b = create_ata(&mut env, &m, &bob.pubkey());
    assert_eq!(state(&env, &a), AccountState::Frozen);
    assert_eq!(state(&env, &b), AccountState::Frozen);

    // Until KYC clears, the account cannot even be funded.
    env.rejects(
        &[mint_to_ix(&m, &a, &issuer, 1_000)],
        &[&mint.issuer],
        token(TokenError::AccountFrozen),
        &[a, m],
    );

    // An owner cannot clear their own KYC, and the freeze authority must sign.
    env.rejects(
        &[thaw_ix(&a, &m, &alice.pubkey())],
        &[&alice],
        token(TokenError::OwnerMismatch),
        &[a, b, m],
    );
    env.rejects(
        &[unsigned(thaw_ix(&a, &m, &issuer), &issuer)],
        &[],
        anchor(AnchorError::AccountNotSigner),
        &[a, b, m],
    );

    let untouched = env.snapshot(&[b, m]);
    env.send(&[thaw_ix(&a, &m, &issuer)], &[&mint.issuer])
        .expect("thaw failed");
    let thawed = token_account(&env.data(&a)).base;
    assert_eq!(thawed.state, AccountState::Initialized);
    assert_eq!(
        (thawed.owner, thawed.mint, thawed.amount),
        (alice.pubkey(), m, 0)
    );
    env.assert_unchanged(&untouched);

    mint_to(&mut env, &m, &a, &mint.issuer, 1_000);
    assert_eq!(balance(&env, &a), 1_000);

    // Only the freeze authority changes the policy, and only with a signature.
    env.rejects(
        &[set_default_ix(&m, &alice.pubkey(), false)],
        &[&alice],
        token(TokenError::OwnerMismatch),
        &[m],
    );
    env.rejects(
        &[unsigned(set_default_ix(&m, &issuer, false), &issuer)],
        &[],
        anchor(AnchorError::AccountNotSigner),
        &[m],
    );

    // Dropping the KYC requirement leaves every existing account exactly as it
    // was: Bob is still frozen. Only accounts opened afterwards are affected.
    let existing = env.snapshot(&[a, b]);
    env.send(&[set_default_ix(&m, &issuer, false)], &[&mint.issuer])
        .expect("policy change failed");
    assert_eq!(default_state(&env, &m), u8::from(AccountState::Initialized));
    env.assert_unchanged(&existing);
    let carol = create_ata(&mut env, &m, &Keypair::new().pubkey());
    assert_eq!(state(&env, &carol), AccountState::Initialized);

    env.send(&[set_default_ix(&m, &issuer, true)], &[&mint.issuer])
        .expect("policy change failed");
    let dave = create_ata(&mut env, &m, &Keypair::new().pubkey());
    assert_eq!(state(&env, &dave), AccountState::Frozen);
    assert_eq!(state(&env, &carol), AccountState::Initialized);
}

/// transfer_with_fee, harvest_fees and collect_fees: every trust assumption on
/// a transfer, the fee at each rounding and cap boundary, the epoch switch, and
/// the revenue making it all the way to the issuer.
#[test]
fn fees_are_exact_at_every_boundary_and_reach_the_issuer() {
    let mut env = Env::new();
    let mint = create_remittance_mint(&mut env);
    let other = create_confidential_mint(&mut env, [1u8; 32], None);
    let (m, issuer) = (mint.pubkey(), mint.issuer.pubkey());

    let alice = Keypair::new();
    let source = open_and_kyc(&mut env, &m, &alice.pubkey(), &mint.issuer);
    mint_to(&mut env, &m, &source, &mint.issuer, 20_000_000);
    let bystander = open_and_kyc(&mut env, &m, &Keypair::new().pubkey(), &mint.issuer);
    mint_to(&mut env, &m, &bystander, &mint.issuer, 777);
    let sink = open_and_kyc(&mut env, &m, &Keypair::new().pubkey(), &mint.issuer);
    let mut accounts = vec![source, bystander, sink];
    let mut expected_fees = 0u64;

    // Trust assumptions, broken one at a time. Nothing moves in any of them.
    let watched = [source, sink, bystander, m];
    let mallory = Keypair::new();
    env.rejects(
        &[transfer_ix(&source, &m, &sink, &mallory.pubkey(), 1_000)],
        &[&mallory],
        token(TokenError::OwnerMismatch),
        &watched,
    );
    env.rejects(
        &[unsigned(
            transfer_ix(&source, &m, &sink, &alice.pubkey(), 1_000),
            &alice.pubkey(),
        )],
        &[],
        anchor(AnchorError::AccountNotSigner),
        &watched,
    );
    env.rejects(
        &[transfer_ix(&source, &issuer, &sink, &alice.pubkey(), 1_000)],
        &[&alice],
        anchor(AnchorError::ConstraintOwner),
        &watched,
    );
    env.rejects(
        &[transfer_ix(
            &source,
            &other.pubkey(),
            &sink,
            &alice.pubkey(),
            1_000,
        )],
        &[&alice],
        token(TokenError::MintMismatch),
        &watched,
    );
    let mut hijacked = transfer_ix(&source, &m, &sink, &alice.pubkey(), 1_000);
    hijacked.accounts[4].pubkey = solana_system_interface::program::ID;
    env.rejects(
        &[hijacked],
        &[&alice],
        anchor(AnchorError::InvalidProgramId),
        &watched,
    );

    // ceil(amount × 0.5%), capped at 5 000 — worked out by hand, not by
    // re-running the formula.
    let boundaries: [(u64, u64); 6] = [
        (1, 1),             // 0.005 rounds up; the recipient receives nothing
        (200, 1),           // exactly 1
        (201, 2),           // 1.005 rounds up
        (999_800, 4_999),   // exactly 4 999, one below the cap
        (999_801, 5_000),   // 4 999.005 rounds up to the cap
        (1_000_001, 5_000), // 5 000.005 would round to 5 001; the cap holds
    ];
    for (amount, fee) in boundaries {
        let destination = open_and_kyc(&mut env, &m, &Keypair::new().pubkey(), &mint.issuer);
        accounts.push(destination);
        let (source_before, supply_before) = (balance(&env, &source), supply(&env, &m));
        let untouched = env.snapshot(&[bystander, sink]);

        env.send(
            &[transfer_ix(
                &source,
                &m,
                &destination,
                &alice.pubkey(),
                amount,
            )],
            &[&alice],
        )
        .expect("transfer failed");

        assert_eq!(
            source_before - balance(&env, &source),
            amount,
            "debit at {amount}"
        );
        assert_eq!(
            balance(&env, &destination),
            amount - fee,
            "credit at {amount}"
        );
        assert_eq!(withheld(&env, &destination), fee, "fee at {amount}");
        assert_eq!(supply(&env, &m), supply_before);
        env.assert_unchanged(&untouched);
        expected_fees += fee;
    }

    // A later instruction failing reverts an earlier one in the same
    // transaction.
    let over = balance(&env, &source) + 1;
    env.rejects_at(
        &[
            transfer_ix(&source, &m, &sink, &alice.pubkey(), 100_000),
            transfer_ix(&source, &m, &sink, &alice.pubkey(), over),
        ],
        &[&alice],
        1,
        token(TokenError::InsufficientFunds),
        &[source, sink],
    );

    // One unit either side of the balance.
    let carol = Keypair::new();
    let small = open_and_kyc(&mut env, &m, &carol.pubkey(), &mint.issuer);
    accounts.push(small);
    mint_to(&mut env, &m, &small, &mint.issuer, 1_000);
    env.rejects(
        &[transfer_ix(&small, &m, &sink, &carol.pubkey(), 1_001)],
        &[&carol],
        token(TokenError::InsufficientFunds),
        &[small, sink],
    );
    env.send(
        &[transfer_ix(&small, &m, &sink, &carol.pubkey(), 1_000)],
        &[&carol],
    )
    .expect("transfer of the whole balance failed");
    assert_eq!(balance(&env, &small), 0);
    assert_eq!((balance(&env, &sink), withheld(&env, &sink)), (995, 5));
    expected_fees += 5;

    // A new schedule applies from its activation epoch and not one epoch
    // earlier; the program reads it from the Clock, never from a cache.
    let set = t22new::extension::transfer_fee::instruction::set_transfer_fee(
        &token_program(),
        &m,
        &issuer,
        &[],
        250,
        90_000,
    )
    .unwrap();
    env.send(&[set], &[&mint.issuer])
        .expect("set_transfer_fee failed");
    let activation: u64 = {
        let data = env.data(&m);
        mint_state(&data)
            .get_extension::<TransferFeeConfig>()
            .unwrap()
            .newer_transfer_fee
            .epoch
            .into()
    };
    assert!(activation > env.epoch());
    for (epoch, fee) in [
        (activation - 1, 5_000), // old schedule, capped
        (activation, 25_000),    // 1 000 000 × 2.5%, under the new 90 000 cap
    ] {
        env.set_epoch(epoch);
        let destination = open_and_kyc(&mut env, &m, &Keypair::new().pubkey(), &mint.issuer);
        accounts.push(destination);
        env.send(
            &[transfer_ix(
                &source,
                &m,
                &destination,
                &alice.pubkey(),
                1_000_000,
            )],
            &[&alice],
        )
        .expect("transfer failed");
        assert_eq!(withheld(&env, &destination), fee, "fee in epoch {epoch}");
        expected_fees += fee;
    }
    assert_public_supply_conserved(&env, &m, &accounts);

    // Harvesting is permissionless but needs something to sweep. It moves the
    // withheld fees into the mint and leaves every spendable balance alone.
    env.rejects(
        &[harvest_ix(&m, &[])],
        &[],
        program(t22::MintError::NoFeeSources),
        &[m],
    );
    let balances: Vec<u64> = accounts.iter().map(|a| balance(&env, a)).collect();
    env.send(&[harvest_ix(&m, &accounts)], &[])
        .expect("harvest failed");
    assert_eq!(mint_withheld(&env, &m), expected_fees);
    for (account, before) in accounts.iter().zip(&balances) {
        assert_eq!(withheld(&env, account), 0);
        assert_eq!(balance(&env, account), *before);
    }

    // Collecting is not permissionless.
    let treasury = open_and_kyc(&mut env, &m, &issuer, &mint.issuer);
    accounts.push(treasury);
    env.rejects(
        &[collect_ix(&m, &treasury, &mallory.pubkey())],
        &[&mallory],
        token(TokenError::OwnerMismatch),
        &[m, treasury],
    );
    env.rejects(
        &[unsigned(collect_ix(&m, &treasury, &issuer), &issuer)],
        &[],
        anchor(AnchorError::AccountNotSigner),
        &[m, treasury],
    );
    env.send(&[collect_ix(&m, &treasury, &issuer)], &[&mint.issuer])
        .expect("collect failed");
    assert_eq!(balance(&env, &treasury), expected_fees);
    assert_eq!(mint_withheld(&env, &m), 0);
    assert_public_supply_conserved(&env, &m, &accounts);
}

/// seize: the permanent delegate moves funds without the owner, and only the
/// delegate can.
#[test]
fn only_the_permanent_delegate_seizes_and_never_past_a_freeze() {
    let mut env = Env::new();
    let v2 = create_confidential_mint(&mut env, [5u8; 32], None);
    let v1 = create_remittance_mint(&mut env);
    let (m, delegate) = (v2.pubkey(), v2.issuer.pubkey());

    let alice = Keypair::new();
    let sanctioned = open_and_kyc(&mut env, &m, &alice.pubkey(), &v2.issuer);
    let treasury = open_and_kyc(&mut env, &m, &delegate, &v2.issuer);
    let bystander = open_and_kyc(&mut env, &m, &Keypair::new().pubkey(), &v2.issuer);
    mint_to(&mut env, &m, &sanctioned, &v2.issuer, 1_000_000);
    mint_to(&mut env, &m, &bystander, &v2.issuer, 777);
    let watched = [sanctioned, treasury, bystander, m];

    let mallory = Keypair::new();
    env.rejects(
        &[seize_ix(&sanctioned, &m, &treasury, &mallory.pubkey(), 1)],
        &[&mallory],
        program(t22::MintError::NoSeizureAuthority),
        &watched,
    );
    env.rejects(
        &[unsigned(
            seize_ix(&sanctioned, &m, &treasury, &delegate, 1),
            &delegate,
        )],
        &[],
        anchor(AnchorError::AccountNotSigner),
        &watched,
    );

    // A mint with no delegate cannot be seized from, not even by its issuer.
    let v1_account = open_and_kyc(&mut env, &v1.pubkey(), &alice.pubkey(), &v1.issuer);
    let v1_sink = open_and_kyc(&mut env, &v1.pubkey(), &v1.issuer.pubkey(), &v1.issuer);
    mint_to(&mut env, &v1.pubkey(), &v1_account, &v1.issuer, 1_000);
    env.rejects(
        &[seize_ix(
            &v1_account,
            &v1.pubkey(),
            &v1_sink,
            &v1.issuer.pubkey(),
            1,
        )],
        &[&v1.issuer],
        program(t22::MintError::NoSeizureAuthority),
        &[v1_account, v1_sink, v1.pubkey()],
    );

    // Alice never signs. The fee still applies: 250 000 × 0.5% = 1 250.
    let untouched = env.snapshot(&[bystander]);
    let supply_before = supply(&env, &m);
    env.send(
        &[seize_ix(&sanctioned, &m, &treasury, &delegate, 250_000)],
        &[&v2.issuer],
    )
    .expect("seizure failed");
    assert_eq!(balance(&env, &sanctioned), 750_000);
    assert_eq!(
        (balance(&env, &treasury), withheld(&env, &treasury)),
        (248_750, 1_250)
    );
    assert_eq!(supply(&env, &m), supply_before);
    env.assert_unchanged(&untouched);

    // A frozen account blocks the delegate too, so enforcement seizes first.
    freeze(&mut env, &sanctioned, &m, &v2.issuer);
    env.rejects(
        &[seize_ix(&sanctioned, &m, &treasury, &delegate, 1)],
        &[&v2.issuer],
        token(TokenError::AccountFrozen),
        &watched,
    );
    env.send(&[thaw_ix(&sanctioned, &m, &delegate)], &[&v2.issuer])
        .expect("thaw failed");

    // One unit either side of what is there.
    env.rejects(
        &[seize_ix(&sanctioned, &m, &treasury, &delegate, 750_001)],
        &[&v2.issuer],
        token(TokenError::InsufficientFunds),
        &watched,
    );
    env.send(
        &[seize_ix(&sanctioned, &m, &treasury, &delegate, 750_000)],
        &[&v2.issuer],
    )
    .expect("seizing the whole balance failed");
    assert_eq!(balance(&env, &sanctioned), 0);
    // 750 000 × 0.5% = 3 750, on top of the earlier 1 250.
    assert_eq!(
        (balance(&env, &treasury), withheld(&env, &treasury)),
        (248_750 + 746_250, 1_250 + 3_750)
    );
    assert_public_supply_conserved(&env, &m, &[sanctioned, treasury, bystander]);
}
