mod common;

use {
    anchor_lang::error::ErrorCode as AnchorError,
    common::*,
    proofgen::{
        errors::TokenProofGenerationError, transfer_with_fee::transfer_with_fee_split_proof_data,
        withdraw::withdraw_proof_data,
    },
    solana_compute_budget_interface::ComputeBudgetInstruction,
    solana_instruction::{AccountMeta, Instruction},
    solana_keypair::Keypair,
    solana_pubkey::Pubkey,
    solana_signer::Signer,
    t22::accounts as t22_accounts,
    t22new::{
        error::TokenError,
        extension::{
            confidential_transfer::ConfidentialTransferAccount,
            confidential_transfer_fee::{
                ConfidentialTransferFeeAmount, ConfidentialTransferFeeConfig,
            },
            transfer_fee::{TransferFeeAmount, TransferFeeConfig},
            BaseStateWithExtensions, ExtensionType,
        },
    },
    zk::{
        encryption::{
            auth_encryption::AeKey,
            elgamal::{ElGamalKeypair, ElGamalPubkey},
            pod::elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
        },
        zk_elgamal_proof_program::{
            self,
            instruction::{ContextStateInfo, ProofInstruction},
            proof_data::{ProofType, PubkeyValidityProofData, ZkProofData},
            state::ProofContextState,
        },
    },
};

fn verifier_for(proof_type: ProofType) -> ProofInstruction {
    match proof_type {
        ProofType::PubkeyValidity => ProofInstruction::VerifyPubkeyValidity,
        ProofType::CiphertextCommitmentEquality => {
            ProofInstruction::VerifyCiphertextCommitmentEquality
        }
        ProofType::PercentageWithCap => ProofInstruction::VerifyPercentageWithCap,
        ProofType::BatchedRangeProofU64 => ProofInstruction::VerifyBatchedRangeProofU64,
        ProofType::BatchedRangeProofU256 => ProofInstruction::VerifyBatchedRangeProofU256,
        ProofType::BatchedGroupedCiphertext2HandlesValidity => {
            ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity
        }
        ProofType::BatchedGroupedCiphertext3HandlesValidity => {
            ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity
        }
        other => panic!("no verifier wired up for {other:?}"),
    }
}

/// The default 200k budget does not cover a range proof verification.
fn compute_units_for(proof_type: ProofType) -> u32 {
    match proof_type {
        ProofType::BatchedRangeProofU256 => 800_000,
        ProofType::BatchedRangeProofU64 => 300_000,
        _ => 200_000,
    }
}

/// Two transactions: a 256-bit range proof nearly fills one on its own.
fn verify_into_context<T, U>(env: &mut Env, proof: &T, authority: &Pubkey) -> Pubkey
where
    T: bytemuck::Pod + ZkProofData<U>,
    U: bytemuck::Pod,
{
    let context = Keypair::new();
    let space = std::mem::size_of::<ProofContextState<U>>();
    let create = solana_system_interface::instruction::create_account(
        &env.payer.pubkey(),
        &context.pubkey(),
        env.svm.minimum_balance_for_rent_exemption(space),
        space as u64,
        &zk_elgamal_proof_program::id(),
    );
    env.send(&[create], &[&context])
        .expect("proof context allocation failed");

    let verify = verifier_for(T::PROOF_TYPE).encode_verify_proof(
        Some(ContextStateInfo {
            context_state_account: &context.pubkey(),
            context_state_authority: authority,
        }),
        proof,
    );
    env.send(
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(compute_units_for(T::PROOF_TYPE)),
            verify,
        ],
        &[],
    )
    .expect("proof verification failed");
    context.pubkey()
}

struct Holder {
    owner: Keypair,
    account: Pubkey,
    elgamal: ElGamalKeypair,
    aes: AeKey,
}

fn keys(owner: &Keypair, account: &Pubkey) -> (ElGamalKeypair, AeKey) {
    (
        ElGamalKeypair::new_from_signer(owner, &account.to_bytes()).unwrap(),
        AeKey::new_from_signer(owner, &account.to_bytes()).unwrap(),
    )
}

fn confidential_mint(env: &mut Env) -> (Mint, ElGamalKeypair) {
    let withheld = ElGamalKeypair::new_rand();
    let bytes = bytemuck::bytes_of(&PodElGamalPubkey::from(*withheld.pubkey()))
        .try_into()
        .unwrap();
    (create_confidential_mint(env, bytes, None), withheld)
}

fn confidential(env: &Env, account: &Pubkey) -> ConfidentialTransferAccount {
    let data = env.data(account);
    *token_account(&data)
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap()
}

fn decrypt(key: &ElGamalKeypair, ciphertext: PodElGamalCiphertext) -> u64 {
    key.secret()
        .decrypt_u32(&ciphertext.try_into().unwrap())
        .expect("ciphertext does not decrypt under this key")
}

/// Read from the ElGamal ciphertexts — ground truth, not the owner's own copy.
/// Returns (available, pending, pending credit counter).
fn truth(env: &Env, holder: &Holder) -> (u64, u64, u64) {
    let ct = confidential(env, &holder.account);
    (
        decrypt(&holder.elgamal, ct.available_balance),
        decrypt(&holder.elgamal, ct.pending_balance_lo)
            + (decrypt(&holder.elgamal, ct.pending_balance_hi) << 16),
        ct.pending_balance_credit_counter.into(),
    )
}

/// Every issued token is in exactly one place: a public balance, a public or
/// encrypted withheld fee, or a confidential available or pending balance.
/// Also, no owner's self-reported balance has drifted from its ciphertext.
fn assert_conserved(env: &Env, mint: &Pubkey, holders: &[&Holder], withheld: &ElGamalKeypair) {
    let data = env.data(mint);
    let parsed = mint_state(&data);
    let mut total = u64::from(
        parsed
            .get_extension::<TransferFeeConfig>()
            .unwrap()
            .withheld_amount,
    ) + decrypt(
        withheld,
        parsed
            .get_extension::<ConfidentialTransferFeeConfig>()
            .unwrap()
            .withheld_amount,
    );

    for holder in holders {
        let data = env.data(&holder.account);
        let account = token_account(&data);
        let ct = account
            .get_extension::<ConfidentialTransferAccount>()
            .unwrap();
        let (available, pending, _) = truth(env, holder);
        assert_eq!(
            holder
                .aes
                .decrypt(&ct.decryptable_available_balance.try_into().unwrap()),
            Some(available),
            "the decryptable copy drifted from the ciphertext"
        );
        total += account.base.amount
            + u64::from(
                account
                    .get_extension::<TransferFeeAmount>()
                    .unwrap()
                    .withheld_amount,
            )
            + available
            + pending
            + decrypt(
                withheld,
                account
                    .get_extension::<ConfidentialTransferFeeAmount>()
                    .unwrap()
                    .withheld_amount,
            );
    }
    assert_eq!(
        total, parsed.base.supply,
        "supply is not fully accounted for"
    );
}

fn reallocate(env: &mut Env, account: &Pubkey, owner: &Keypair) {
    let grow = t22new::instruction::reallocate(
        &token_program(),
        account,
        &env.payer.pubkey(),
        &owner.pubkey(),
        &[],
        &[
            ExtensionType::ConfidentialTransferAccount,
            ExtensionType::ConfidentialTransferFeeAmount,
        ],
    )
    .unwrap();
    env.send(&[grow], &[owner]).expect("reallocate failed");
}

fn configure_ix(
    account: &Pubkey,
    mint: &Pubkey,
    proof: &Pubkey,
    owner: &Pubkey,
    aes: &AeKey,
) -> Instruction {
    ix(
        t22_accounts::ConfigureConfidentialAccount {
            token_account: *account,
            mint: *mint,
            proof_context: *proof,
            owner: *owner,
            token_program: token_program(),
        },
        t22::instruction::ConfigureConfidentialAccount {
            decryptable_zero_balance: aes.encrypt(0).to_bytes(),
            maximum_pending_balance_credit_counter: 65_536,
        },
    )
}

fn approve_ix(account: &Pubkey, mint: &Pubkey, authority: &Pubkey) -> Instruction {
    ix(
        t22_accounts::ApproveConfidentialAccount {
            token_account: *account,
            mint: *mint,
            authority: *authority,
            token_program: token_program(),
        },
        t22::instruction::ApproveConfidentialAccount {},
    )
}

fn deposit_ix(account: &Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) -> Instruction {
    ix(
        t22_accounts::DepositConfidential {
            token_account: *account,
            mint: *mint,
            owner: *owner,
            token_program: token_program(),
        },
        t22::instruction::DepositConfidential { amount },
    )
}

fn apply_ix(holder: &Holder, counter: u64, new_available: u64) -> Instruction {
    ix(
        t22_accounts::ApplyPendingBalance {
            token_account: holder.account,
            owner: holder.owner.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::ApplyPendingBalance {
            expected_pending_balance_credit_counter: counter,
            new_decryptable_available_balance: holder.aes.encrypt(new_available).to_bytes(),
        },
    )
}

fn withdraw_ix(
    holder: &Holder,
    mint: &Pubkey,
    proofs: (Pubkey, Pubkey),
    amount: u64,
    remaining: u64,
) -> Instruction {
    ix(
        t22_accounts::WithdrawConfidential {
            token_account: holder.account,
            mint: *mint,
            equality_proof: proofs.0,
            range_proof: proofs.1,
            owner: holder.owner.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::WithdrawConfidential {
            amount,
            new_decryptable_available_balance: holder.aes.encrypt(remaining).to_bytes(),
        },
    )
}

/// Proves a withdrawal of `amount` against the account's current ciphertext.
fn prove_withdraw(env: &mut Env, holder: &Holder, amount: u64) -> (Pubkey, Pubkey) {
    let (available, _, _) = truth(env, holder);
    let proofs = withdraw_proof_data(
        &confidential(env, &holder.account)
            .available_balance
            .try_into()
            .unwrap(),
        available,
        amount,
        &holder.elgamal,
    )
    .unwrap();
    let owner = holder.owner.pubkey();
    (
        verify_into_context(env, &proofs.equality_proof_data, &owner),
        verify_into_context(env, &proofs.range_proof_data, &owner),
    )
}

/// Steps 1-5: open, grow, KYC, configure, approve.
fn onboard(env: &mut Env, mint: &Mint) -> Holder {
    let owner = Keypair::new();
    let account = create_ata(env, &mint.pubkey(), &owner.pubkey());
    reallocate(env, &account, &owner);
    env.send(
        &[thaw_ix(&account, &mint.pubkey(), &mint.issuer.pubkey())],
        &[&mint.issuer],
    )
    .expect("thaw failed");
    let (elgamal, aes) = keys(&owner, &account);
    let proof = verify_into_context(
        env,
        &PubkeyValidityProofData::new(&elgamal).unwrap(),
        &owner.pubkey(),
    );
    env.send(
        &[configure_ix(
            &account,
            &mint.pubkey(),
            &proof,
            &owner.pubkey(),
            &aes,
        )],
        &[&owner],
    )
    .expect("configure failed");
    env.send(
        &[approve_ix(&account, &mint.pubkey(), &mint.issuer.pubkey())],
        &[&mint.issuer],
    )
    .expect("approve failed");
    Holder {
        owner,
        account,
        elgamal,
        aes,
    }
}

/// configure_confidential_account, approve_confidential_account and
/// deposit_confidential: every trust assumption on getting an account ready.
#[test]
fn onboarding_is_owner_only_manually_approved_and_kyc_gated() {
    let mut env = Env::new();
    let (mint, _) = confidential_mint(&mut env);
    let (m, authority) = (mint.pubkey(), mint.issuer.pubkey());

    // The payer alone opens the account; growing it takes the owner.
    let owner = Keypair::new();
    let account = create_ata(&mut env, &m, &owner.pubkey());
    reallocate(&mut env, &account, &owner);
    let (elgamal, aes) = keys(&owner, &account);

    // The payer who created it cannot attach its own keys to it.
    let payer = env.payer.insecure_clone();
    let (payer_elgamal, payer_aes) = keys(&payer, &account);
    let proof = verify_into_context(
        &mut env,
        &PubkeyValidityProofData::new(&payer_elgamal).unwrap(),
        &payer.pubkey(),
    );
    env.rejects(
        &[configure_ix(
            &account,
            &m,
            &proof,
            &payer.pubkey(),
            &payer_aes,
        )],
        &[],
        token(TokenError::OwnerMismatch),
        &[account],
    );

    let proof = verify_into_context(
        &mut env,
        &PubkeyValidityProofData::new(&elgamal).unwrap(),
        &owner.pubkey(),
    );
    env.rejects(
        &[unsigned(
            configure_ix(&account, &m, &proof, &owner.pubkey(), &aes),
            &owner.pubkey(),
        )],
        &[],
        anchor(AnchorError::AccountNotSigner),
        &[account],
    );

    // The owner configures it while it is still frozen: nothing here moves
    // value, so KYC does not have to come first.
    env.send(
        &[configure_ix(&account, &m, &proof, &owner.pubkey(), &aes)],
        &[&owner],
    )
    .expect("configure failed");
    let ct = confidential(&env, &account);
    assert_eq!(ct.elgamal_pubkey, PodElGamalPubkey::from(*elgamal.pubkey()));
    assert!(!bool::from(ct.approved));
    assert!(bool::from(ct.allow_confidential_credits));
    assert_eq!(u64::from(ct.maximum_pending_balance_credit_counter), 65_536);
    assert_eq!(u64::from(ct.pending_balance_credit_counter), 0);
    assert_eq!(
        aes.decrypt(&ct.decryptable_available_balance.try_into().unwrap()),
        Some(0)
    );
    assert_eq!(state(&env, &account), t22new::state::AccountState::Frozen);

    // Configuring twice is the wrong state, not a reset.
    let again = verify_into_context(
        &mut env,
        &PubkeyValidityProofData::new(&elgamal).unwrap(),
        &owner.pubkey(),
    );
    env.rejects(
        &[configure_ix(&account, &m, &again, &owner.pubkey(), &aes)],
        &[&owner],
        token(TokenError::ExtensionAlreadyInitialized),
        &[account],
    );

    env.send(&[thaw_ix(&account, &m, &authority)], &[&mint.issuer])
        .expect("thaw failed");
    mint_to(&mut env, &m, &account, &mint.issuer, 10_000);

    // approve_policy = manual: inert until the confidential authority signs.
    env.rejects(
        &[deposit_ix(&account, &m, &owner.pubkey(), 1_000)],
        &[&owner],
        token(TokenError::ConfidentialTransferAccountNotApproved),
        &[account, m],
    );
    env.rejects(
        &[approve_ix(&account, &m, &owner.pubkey())],
        &[&owner],
        // Token-2022 folds "wrong authority" into this even when it signed.
        solana_instruction_error::InstructionError::MissingRequiredSignature,
        &[account],
    );
    env.rejects(
        &[unsigned(approve_ix(&account, &m, &authority), &authority)],
        &[],
        anchor(AnchorError::AccountNotSigner),
        &[account],
    );
    env.send(&[approve_ix(&account, &m, &authority)], &[&mint.issuer])
        .expect("approve failed");
    assert!(bool::from(confidential(&env, &account).approved));

    // Depositing: only the owner, never while frozen, never past the balance.
    let mallory = Keypair::new();
    env.rejects(
        &[deposit_ix(&account, &m, &mallory.pubkey(), 1_000)],
        &[&mallory],
        token(TokenError::OwnerMismatch),
        &[account, m],
    );
    env.rejects(
        &[unsigned(
            deposit_ix(&account, &m, &owner.pubkey(), 1_000),
            &owner.pubkey(),
        )],
        &[],
        anchor(AnchorError::AccountNotSigner),
        &[account, m],
    );
    freeze(&mut env, &account, &m, &mint.issuer);
    env.rejects(
        &[deposit_ix(&account, &m, &owner.pubkey(), 1_000)],
        &[&owner],
        token(TokenError::AccountFrozen),
        &[account, m],
    );
    env.send(&[thaw_ix(&account, &m, &authority)], &[&mint.issuer])
        .expect("thaw failed");
    env.rejects(
        &[deposit_ix(&account, &m, &owner.pubkey(), 10_001)],
        &[&owner],
        // Deposit checks the balance with checked_sub, so an over-draw reads
        // as Overflow where a public transfer says InsufficientFunds.
        token(TokenError::Overflow),
        &[account, m],
    );

    env.send(
        &[deposit_ix(&account, &m, &owner.pubkey(), 10_000)],
        &[&owner],
    )
    .expect("deposit of the whole balance failed");
    let holder = Holder {
        owner,
        account,
        elgamal,
        aes,
    };
    assert_eq!(balance(&env, &account), 0);
    assert_eq!(truth(&env, &holder), (0, 10_000, 1));
}

/// apply_pending_balance, transfer_confidential and withdraw_confidential: two
/// users through the whole lifecycle, with supply accounted for after every
/// step.
#[test]
fn two_users_through_the_whole_confidential_lifecycle() {
    let mut env = Env::new();
    let (mint, withheld) = confidential_mint(&mut env);
    let m = mint.pubkey();
    let alice = onboard(&mut env, &mint);
    let bob = onboard(&mut env, &mint);
    mint_to(&mut env, &m, &alice.account, &mint.issuer, 1_000_000);
    mint_to(&mut env, &m, &bob.account, &mint.issuer, 300_000);
    let both = [&alice, &bob];
    assert_conserved(&env, &m, &both, &withheld);

    // Interleaved deposits land in each user's own pending balance.
    env.send(
        &[deposit_ix(
            &alice.account,
            &m,
            &alice.owner.pubkey(),
            1_000_000,
        )],
        &[&alice.owner],
    )
    .expect("deposit failed");
    env.send(
        &[deposit_ix(&bob.account, &m, &bob.owner.pubkey(), 300_000)],
        &[&bob.owner],
    )
    .expect("deposit failed");
    assert_eq!(truth(&env, &alice), (0, 1_000_000, 1));
    assert_eq!(truth(&env, &bob), (0, 300_000, 1));
    assert_conserved(&env, &m, &both, &withheld);

    env.send(&[apply_ix(&alice, 1, 1_000_000)], &[&alice.owner])
        .expect("apply failed");
    assert_eq!(truth(&env, &alice), (1_000_000, 0, 0));
    assert_conserved(&env, &m, &both, &withheld);

    // Alice -> Bob: 100 000, of which 0.5% = 500 is withheld, encrypted.
    let source = confidential(&env, &alice.account);
    let destination: ElGamalPubkey = confidential(&env, &bob.account)
        .elgamal_pubkey
        .try_into()
        .unwrap();
    let proofs = transfer_with_fee_split_proof_data(
        &source.available_balance.try_into().unwrap(),
        &source.decryptable_available_balance.try_into().unwrap(),
        100_000,
        &alice.elgamal,
        &alice.aes,
        &destination,
        None,
        withheld.pubkey(),
        FEE_BPS,
        MAX_FEE,
    )
    .unwrap();
    let owner = alice.owner.pubkey();
    let validity = &proofs.transfer_amount_ciphertext_validity_proof_data_with_ciphertext;
    let contexts = [
        verify_into_context(&mut env, &proofs.equality_proof_data, &owner),
        verify_into_context(&mut env, &validity.proof_data, &owner),
        verify_into_context(&mut env, &proofs.percentage_with_cap_proof_data, &owner),
        verify_into_context(&mut env, &proofs.fee_ciphertext_validity_proof_data, &owner),
        verify_into_context(&mut env, &proofs.range_proof_data, &owner),
    ];
    let transfer = |signer: &Pubkey, contexts: &[Pubkey]| {
        let mut call = ix(
            t22_accounts::TransferConfidential {
                source: alice.account,
                mint: m,
                destination: bob.account,
                owner: *signer,
                token_program: token_program(),
            },
            t22::instruction::TransferConfidential {
                new_source_decryptable_available_balance: alice.aes.encrypt(900_000).to_bytes(),
                auditor_ciphertext_lo: bytemuck::bytes_of(&validity.ciphertext_lo)
                    .try_into()
                    .unwrap(),
                auditor_ciphertext_hi: bytemuck::bytes_of(&validity.ciphertext_hi)
                    .try_into()
                    .unwrap(),
            },
        );
        call.accounts.extend(
            contexts
                .iter()
                .map(|c| AccountMeta::new_readonly(*c, false)),
        );
        vec![
            ComputeBudgetInstruction::set_compute_unit_limit(400_000),
            call,
        ]
    };

    let watched = [alice.account, bob.account, m];
    env.rejects(
        &transfer(&owner, &contexts[..4]),
        &[&alice.owner],
        program(t22::MintError::MissingProofContexts),
        &watched,
    );
    let mut reordered = contexts;
    reordered.swap(0, 4);
    env.rejects(
        &transfer(&owner, &reordered),
        &[&alice.owner],
        // The context in each slot is read at that proof's size, so a swapped
        // one fails its shape check before its type is even compared.
        solana_instruction_error::InstructionError::InvalidArgument,
        &watched,
    );
    env.rejects(
        &transfer(&bob.owner.pubkey(), &contexts),
        &[&bob.owner],
        token(TokenError::OwnerMismatch),
        &watched,
    );
    env.send(&transfer(&owner, &contexts), &[&alice.owner])
        .expect("confidential transfer failed");
    assert_eq!(truth(&env, &alice), (900_000, 0, 0));
    assert_eq!(truth(&env, &bob), (0, 300_000 + 99_500, 2));
    assert_eq!(
        (balance(&env, &alice.account), balance(&env, &bob.account)),
        (0, 0)
    );
    let data = env.data(&bob.account);
    let fee = token_account(&data)
        .get_extension::<ConfidentialTransferFeeAmount>()
        .unwrap()
        .withheld_amount;
    assert_eq!(decrypt(&withheld, fee), 500);
    assert_conserved(&env, &m, &both, &withheld);

    // Bob cannot withdraw with credits still pending, even with a valid proof.
    let stale = prove_withdraw(&mut env, &bob, 0);
    env.rejects(
        &[withdraw_ix(&bob, &m, stale, 0, 0)],
        &[&bob.owner],
        program(t22::MintError::PendingBalanceNotApplied),
        &watched,
    );
    env.send(&[apply_ix(&bob, 2, 399_500)], &[&bob.owner])
        .expect("apply failed");
    assert_eq!(truth(&env, &bob), (399_500, 0, 0));
    let ct = confidential(&env, &bob.account);
    assert_eq!(
        u64::from(ct.expected_pending_balance_credit_counter),
        u64::from(ct.actual_pending_balance_credit_counter)
    );
    assert_conserved(&env, &m, &both, &withheld);

    // A withdrawal whose amount disagrees with its proof by one unit is
    // refused; the honest one goes through.
    let proven = prove_withdraw(&mut env, &alice, 200_000);
    env.rejects(
        &[withdraw_ix(&alice, &m, proven, 200_001, 699_999)],
        &[&alice.owner],
        token(TokenError::ConfidentialTransferBalanceMismatch),
        &watched,
    );
    env.send(
        &[withdraw_ix(&alice, &m, proven, 200_000, 700_000)],
        &[&alice.owner],
    )
    .expect("withdraw failed");
    assert_eq!(truth(&env, &alice), (700_000, 0, 0));
    assert_eq!(balance(&env, &alice.account), 200_000);
    assert_conserved(&env, &m, &both, &withheld);

    // Draining exactly what is there works; one unit more cannot be proven.
    let rest = prove_withdraw(&mut env, &alice, 700_000);
    env.send(
        &[withdraw_ix(&alice, &m, rest, 700_000, 0)],
        &[&alice.owner],
    )
    .expect("withdraw of the whole balance failed");
    assert_eq!(truth(&env, &alice), (0, 0, 0));
    assert!(matches!(
        withdraw_proof_data(
            &confidential(&env, &alice.account)
                .available_balance
                .try_into()
                .unwrap(),
            0,
            1,
            &alice.elgamal,
        ),
        Err(TokenProofGenerationError::NotEnoughFunds)
    ));

    let rest = prove_withdraw(&mut env, &bob, 399_500);
    env.send(&[withdraw_ix(&bob, &m, rest, 399_500, 0)], &[&bob.owner])
        .expect("withdraw failed");
    assert_conserved(&env, &m, &both, &withheld);
    assert_eq!(
        (balance(&env, &alice.account), balance(&env, &bob.account)),
        (900_000, 399_500)
    );
    assert_eq!(supply(&env, &m), 900_000 + 399_500 + 500);
}

/// The gap: the seizure authority reaches the public balance and nothing
/// behind the encryption. Freezing contains the funds; it cannot take them.
#[test]
fn seizure_cannot_reach_a_confidential_balance() {
    let mut env = Env::new();
    let (mint, _) = confidential_mint(&mut env);
    let (m, delegate) = (mint.pubkey(), mint.issuer.pubkey());
    let alice = onboard(&mut env, &mint);
    let treasury = open_and_kyc(&mut env, &m, &delegate, &mint.issuer);
    mint_to(&mut env, &m, &alice.account, &mint.issuer, 1_000_000);

    // While public, seizure works: 100 000 taken, 0.5% = 500 withheld.
    env.send(
        &[seize_ix(&alice.account, &m, &treasury, &delegate, 100_000)],
        &[&mint.issuer],
    )
    .expect("seizing a public balance failed");
    assert_eq!(balance(&env, &alice.account), 900_000);
    assert_eq!(
        (balance(&env, &treasury), withheld(&env, &treasury)),
        (99_500, 500)
    );

    env.send(
        &[deposit_ix(
            &alice.account,
            &m,
            &alice.owner.pubkey(),
            900_000,
        )],
        &[&alice.owner],
    )
    .expect("deposit failed");
    env.send(&[apply_ix(&alice, 1, 900_000)], &[&alice.owner])
        .expect("apply failed");
    assert_eq!(truth(&env, &alice), (900_000, 0, 0));

    // The tokens are still in the account, but not even one unit is reachable.
    env.rejects(
        &[seize_ix(&alice.account, &m, &treasury, &delegate, 1)],
        &[&mint.issuer],
        token(TokenError::InsufficientFunds),
        &[alice.account, treasury, m],
    );

    // Nor can the delegate build its way in: every proof needs Alice's
    // secret, and keys derived from the delegate's own wallet read nothing.
    let (delegate_elgamal, delegate_aes) = keys(&mint.issuer, &alice.account);
    let ct = confidential(&env, &alice.account);
    assert_eq!(
        delegate_aes.decrypt(&ct.decryptable_available_balance.try_into().unwrap()),
        None
    );
    assert_ne!(
        delegate_elgamal
            .secret()
            .decrypt_u32(&ct.available_balance.try_into().unwrap()),
        Some(900_000)
    );

    // What the issuer can do unilaterally is contain it: frozen, even Alice's
    // own valid withdrawal is refused, and the balance stays put.
    let proven = prove_withdraw(&mut env, &alice, 900_000);
    freeze(&mut env, &alice.account, &m, &mint.issuer);
    env.rejects(
        &[withdraw_ix(&alice, &m, proven, 900_000, 0)],
        &[&alice.owner],
        token(TokenError::AccountFrozen),
        &[alice.account, m],
    );
    assert_eq!(truth(&env, &alice), (900_000, 0, 0));
}
