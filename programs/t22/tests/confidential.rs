mod common;

use {
    common::*,
    solana_compute_budget_interface::ComputeBudgetInstruction,
    solana_keypair::Keypair,
    solana_pubkey::Pubkey,
    solana_signer::Signer,
    t22::accounts as t22_accounts,
    t22new::extension::{
        confidential_transfer::ConfidentialTransferAccount, BaseStateWithExtensions, ExtensionType,
        StateWithExtensions,
    },
    t22new::state::Account as TokenAccountState,
    zk::{
        encryption::{
            auth_encryption::AeKey,
            elgamal::{ElGamalCiphertext, ElGamalKeypair},
            pod::elgamal::PodElGamalPubkey,
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
fn verify_into_context<T, U>(env: &mut Env, proof: &T, authority: &Pubkey) -> Keypair
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

    context
}

struct Holder {
    owner: Keypair,
    account: Pubkey,
    elgamal: ElGamalKeypair,
    aes: AeKey,
}

fn confidential_state(env: &Env, account: &Pubkey) -> ConfidentialTransferAccount {
    let data = env.data(account);
    *StateWithExtensions::<TokenAccountState>::unpack(&data)
        .unwrap()
        .get_extension::<ConfidentialTransferAccount>()
        .unwrap()
}

fn balances(env: &Env, holder: &Holder) -> (u64, u64, u64) {
    let ct = confidential_state(env, &holder.account);

    let available = holder
        .aes
        .decrypt(&ct.decryptable_available_balance.try_into().unwrap())
        .expect("wrong AES key for this account");

    let lo: ElGamalCiphertext = ct.pending_balance_lo.try_into().unwrap();
    let hi: ElGamalCiphertext = ct.pending_balance_hi.try_into().unwrap();
    let pending = holder.elgamal.secret().decrypt_u32(&lo).unwrap()
        + (holder.elgamal.secret().decrypt_u32(&hi).unwrap() << 16);

    (available, pending, ct.pending_balance_credit_counter.into())
}

fn onboard(env: &mut Env, mint: &Mint) -> Holder {
    let owner = Keypair::new();
    env.svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();

    let account = create_ata(env, &mint.pubkey(), &owner.pubkey());

    // ConfigureAccount does not grow the account, so make room first.
    let reallocate = t22new::instruction::reallocate(
        &token_program(),
        &account,
        &env.payer.pubkey(),
        &owner.pubkey(),
        &[],
        &[
            ExtensionType::ConfidentialTransferAccount,
            ExtensionType::ConfidentialTransferFeeAmount,
        ],
    )
    .unwrap();
    env.send(&[reallocate], &[&owner])
        .expect("reallocate failed");

    env.call(
        t22_accounts::ThawAfterKyc {
            token_account: account,
            mint: mint.pubkey(),
            freeze_authority: mint.issuer.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::ThawAfterKyc {},
        &[&mint.issuer],
    )
    .expect("thaw failed");

    let elgamal = ElGamalKeypair::new_from_signer(&owner, &account.to_bytes()).unwrap();
    let aes = AeKey::new_from_signer(&owner, &account.to_bytes()).unwrap();

    let proof = PubkeyValidityProofData::new(&elgamal).unwrap();
    let context = verify_into_context(env, &proof, &owner.pubkey());

    env.call(
        t22_accounts::ConfigureConfidentialAccount {
            token_account: account,
            mint: mint.pubkey(),
            proof_context: context.pubkey(),
            owner: owner.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::ConfigureConfidentialAccount {
            decryptable_zero_balance: aes.encrypt(0).to_bytes(),
            maximum_pending_balance_credit_counter: 65_536,
        },
        &[&owner],
    )
    .expect("configure failed");

    env.call(
        t22_accounts::ApproveConfidentialAccount {
            token_account: account,
            mint: mint.pubkey(),
            authority: mint.issuer.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::ApproveConfidentialAccount {},
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

fn deposit_and_apply(env: &mut Env, mint: &Mint, holder: &Holder, amount: u64) {
    env.call(
        t22_accounts::DepositConfidential {
            token_account: holder.account,
            mint: mint.pubkey(),
            owner: holder.owner.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::DepositConfidential { amount },
        &[&holder.owner],
    )
    .expect("deposit failed");

    let (available, pending, counter) = balances(env, holder);
    env.call(
        t22_accounts::ApplyPendingBalance {
            token_account: holder.account,
            owner: holder.owner.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::ApplyPendingBalance {
            expected_pending_balance_credit_counter: counter,
            new_decryptable_available_balance: holder.aes.encrypt(available + pending).to_bytes(),
        },
        &[&holder.owner],
    )
    .expect("apply failed");
}

fn confidential_mint(env: &mut Env) -> (Mint, ElGamalKeypair) {
    let withheld = ElGamalKeypair::new_rand();
    let withheld_bytes = bytemuck::bytes_of(&PodElGamalPubkey::from(*withheld.pubkey()))
        .try_into()
        .unwrap();
    let mint = create_confidential_mint(env, withheld_bytes, None);
    (mint, withheld)
}

#[test]
fn configure_is_owner_only() {
    let mut env = Env::new();
    let (mint, _) = confidential_mint(&mut env);
    let owner = Keypair::new();
    env.svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();

    let account = create_ata(&mut env, &mint.pubkey(), &owner.pubkey());
    let reallocate = t22new::instruction::reallocate(
        &token_program(),
        &account,
        &env.payer.pubkey(),
        &owner.pubkey(),
        &[],
        &[
            ExtensionType::ConfidentialTransferAccount,
            ExtensionType::ConfidentialTransferFeeAmount,
        ],
    )
    .unwrap();
    env.send(&[reallocate], &[&owner]).unwrap();

    let payer_elgamal = ElGamalKeypair::new_from_signer(&env.payer, &account.to_bytes()).unwrap();
    let payer_aes = AeKey::new_from_signer(&env.payer, &account.to_bytes()).unwrap();
    let proof = PubkeyValidityProofData::new(&payer_elgamal).unwrap();
    let payer_key = env.payer.pubkey();
    let context = verify_into_context(&mut env, &proof, &payer_key);

    let payer = env.payer.insecure_clone();
    assert!(
        env.call(
            t22_accounts::ConfigureConfidentialAccount {
                token_account: account,
                mint: mint.pubkey(),
                proof_context: context.pubkey(),
                owner: payer.pubkey(),
                token_program: token_program(),
            },
            t22::instruction::ConfigureConfidentialAccount {
                decryptable_zero_balance: payer_aes.encrypt(0).to_bytes(),
                maximum_pending_balance_credit_counter: 65_536,
            },
            &[],
        )
        .is_err(),
        "the processor validates the authority against the account's owner field"
    );
}

#[test]
fn an_unapproved_account_cannot_take_a_deposit() {
    let mut env = Env::new();
    let (mint, _) = confidential_mint(&mut env);

    let owner = Keypair::new();
    env.svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();
    let account = create_ata(&mut env, &mint.pubkey(), &owner.pubkey());
    let reallocate = t22new::instruction::reallocate(
        &token_program(),
        &account,
        &env.payer.pubkey(),
        &owner.pubkey(),
        &[],
        &[
            ExtensionType::ConfidentialTransferAccount,
            ExtensionType::ConfidentialTransferFeeAmount,
        ],
    )
    .unwrap();
    env.send(&[reallocate], &[&owner]).unwrap();
    env.call(
        t22_accounts::ThawAfterKyc {
            token_account: account,
            mint: mint.pubkey(),
            freeze_authority: mint.issuer.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::ThawAfterKyc {},
        &[&mint.issuer],
    )
    .unwrap();

    let elgamal = ElGamalKeypair::new_from_signer(&owner, &account.to_bytes()).unwrap();
    let aes = AeKey::new_from_signer(&owner, &account.to_bytes()).unwrap();
    let proof = PubkeyValidityProofData::new(&elgamal).unwrap();
    let context = verify_into_context(&mut env, &proof, &owner.pubkey());
    env.call(
        t22_accounts::ConfigureConfidentialAccount {
            token_account: account,
            mint: mint.pubkey(),
            proof_context: context.pubkey(),
            owner: owner.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::ConfigureConfidentialAccount {
            decryptable_zero_balance: aes.encrypt(0).to_bytes(),
            maximum_pending_balance_credit_counter: 65_536,
        },
        &[&owner],
    )
    .unwrap();

    assert!(!bool::from(confidential_state(&env, &account).approved));
    mint_to(&mut env, &mint.pubkey(), &account, &mint.issuer, 10_000);

    let deposit = t22::instruction::DepositConfidential { amount: 1_000 };
    let accounts = t22_accounts::DepositConfidential {
        token_account: account,
        mint: mint.pubkey(),
        owner: owner.pubkey(),
        token_program: token_program(),
    };
    assert!(
        env.call(accounts, deposit, &[&owner]).is_err(),
        "an unapproved account must not accept confidential credits"
    );

    env.call(
        t22_accounts::ApproveConfidentialAccount {
            token_account: account,
            mint: mint.pubkey(),
            authority: mint.issuer.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::ApproveConfidentialAccount {},
        &[&mint.issuer],
    )
    .unwrap();
    env.call(
        t22_accounts::DepositConfidential {
            token_account: account,
            mint: mint.pubkey(),
            owner: owner.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::DepositConfidential { amount: 1_000 },
        &[&owner],
    )
    .expect("an approved account should accept a deposit");
}

#[test]
fn deposit_lands_in_pending_and_apply_makes_it_spendable() {
    let mut env = Env::new();
    let (mint, _) = confidential_mint(&mut env);
    let alice = onboard(&mut env, &mint);
    mint_to(
        &mut env,
        &mint.pubkey(),
        &alice.account,
        &mint.issuer,
        1_000_000,
    );

    env.call(
        t22_accounts::DepositConfidential {
            token_account: alice.account,
            mint: mint.pubkey(),
            owner: alice.owner.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::DepositConfidential { amount: 600_000 },
        &[&alice.owner],
    )
    .expect("deposit failed");

    assert_eq!(balance(&env, &alice.account), 400_000);
    let (available, pending, counter) = balances(&env, &alice);
    assert_eq!((available, pending, counter), (0, 600_000, 1));

    env.call(
        t22_accounts::ApplyPendingBalance {
            token_account: alice.account,
            owner: alice.owner.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::ApplyPendingBalance {
            expected_pending_balance_credit_counter: counter,
            new_decryptable_available_balance: alice.aes.encrypt(600_000).to_bytes(),
        },
        &[&alice.owner],
    )
    .expect("apply failed");

    let (available, pending, _) = balances(&env, &alice);
    assert_eq!((available, pending), (600_000, 0));

    let ct = confidential_state(&env, &alice.account);
    assert_eq!(
        u64::from(ct.expected_pending_balance_credit_counter),
        u64::from(ct.actual_pending_balance_credit_counter)
    );
}

#[test]
fn withdraw_returns_value_to_the_public_balance() {
    use proofgen::withdraw::withdraw_proof_data;

    let mut env = Env::new();
    let (mint, _) = confidential_mint(&mut env);
    let alice = onboard(&mut env, &mint);
    mint_to(
        &mut env,
        &mint.pubkey(),
        &alice.account,
        &mint.issuer,
        1_000_000,
    );
    deposit_and_apply(&mut env, &mint, &alice, 600_000);

    let ct = confidential_state(&env, &alice.account);
    let proofs = withdraw_proof_data(
        &ct.available_balance.try_into().unwrap(),
        600_000,
        200_000,
        &alice.elgamal,
    )
    .unwrap();

    let equality =
        verify_into_context(&mut env, &proofs.equality_proof_data, &alice.owner.pubkey());
    let range = verify_into_context(&mut env, &proofs.range_proof_data, &alice.owner.pubkey());

    env.call(
        t22_accounts::WithdrawConfidential {
            token_account: alice.account,
            mint: mint.pubkey(),
            equality_proof: equality.pubkey(),
            range_proof: range.pubkey(),
            owner: alice.owner.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::WithdrawConfidential {
            amount: 200_000,
            new_decryptable_available_balance: alice.aes.encrypt(400_000).to_bytes(),
        },
        &[&alice.owner],
    )
    .expect("withdraw failed");

    assert_eq!(balance(&env, &alice.account), 400_000 + 200_000);
    assert_eq!(balances(&env, &alice).0, 400_000);
}

#[test]
fn a_confidential_transfer_moves_value_without_publishing_the_amount() {
    use proofgen::transfer_with_fee::transfer_with_fee_split_proof_data;

    let mut env = Env::new();
    let (mint, withheld) = confidential_mint(&mut env);
    let alice = onboard(&mut env, &mint);
    let bob = onboard(&mut env, &mint);

    mint_to(
        &mut env,
        &mint.pubkey(),
        &alice.account,
        &mint.issuer,
        1_000_000,
    );
    deposit_and_apply(&mut env, &mint, &alice, 1_000_000);
    assert_eq!(balance(&env, &alice.account), 0);

    let amount = 100_000u64;
    let fee = 500u64; // 0.5%, under the cap

    let source = confidential_state(&env, &alice.account);
    let destination = confidential_state(&env, &bob.account);
    let proofs = transfer_with_fee_split_proof_data(
        &source.available_balance.try_into().unwrap(),
        &source.decryptable_available_balance.try_into().unwrap(),
        amount,
        &alice.elgamal,
        &alice.aes,
        &destination.elgamal_pubkey.try_into().unwrap(),
        None,
        &withheld.pubkey().clone(),
        FEE_BPS,
        MAX_FEE,
    )
    .unwrap();

    let owner = alice.owner.pubkey();
    let equality = verify_into_context(&mut env, &proofs.equality_proof_data, &owner);
    let amount_validity = verify_into_context(
        &mut env,
        &proofs
            .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
            .proof_data,
        &owner,
    );
    let fee_sigma = verify_into_context(&mut env, &proofs.percentage_with_cap_proof_data, &owner);
    let fee_validity =
        verify_into_context(&mut env, &proofs.fee_ciphertext_validity_proof_data, &owner);
    let range = verify_into_context(&mut env, &proofs.range_proof_data, &owner);

    // The five contexts ride as remaining_accounts, in instruction order.
    let mut metas = {
        use anchor_lang::ToAccountMetas;
        t22_accounts::TransferConfidential {
            source: alice.account,
            mint: mint.pubkey(),
            destination: bob.account,
            owner,
            token_program: token_program(),
        }
        .to_account_metas(None)
    };
    for context in [
        &equality,
        &amount_validity,
        &fee_sigma,
        &fee_validity,
        &range,
    ] {
        metas.push(solana_instruction::AccountMeta::new_readonly(
            context.pubkey(),
            false,
        ));
    }

    let ciphertexts = &proofs.transfer_amount_ciphertext_validity_proof_data_with_ciphertext;
    let data = {
        use anchor_lang::InstructionData;
        t22::instruction::TransferConfidential {
            new_source_decryptable_available_balance: alice
                .aes
                .encrypt(1_000_000 - amount)
                .to_bytes(),
            auditor_ciphertext_lo: bytemuck::bytes_of(&ciphertexts.ciphertext_lo)
                .try_into()
                .unwrap(),
            auditor_ciphertext_hi: bytemuck::bytes_of(&ciphertexts.ciphertext_hi)
                .try_into()
                .unwrap(),
        }
        .data()
    };

    env.send(
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(400_000),
            solana_instruction::Instruction {
                program_id: t22::ID,
                accounts: metas,
                data,
            },
        ],
        &[&alice.owner],
    )
    .expect("confidential transfer failed");

    assert_eq!(balances(&env, &alice).0, 900_000);

    assert_eq!(balance(&env, &alice.account), 0);
    assert_eq!(balance(&env, &bob.account), 0);

    let (bob_available, bob_pending, counter) = balances(&env, &bob);
    assert_eq!((bob_available, bob_pending), (0, amount - fee));

    env.call(
        t22_accounts::ApplyPendingBalance {
            token_account: bob.account,
            owner: bob.owner.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::ApplyPendingBalance {
            expected_pending_balance_credit_counter: counter,
            new_decryptable_available_balance: bob.aes.encrypt(amount - fee).to_bytes(),
        },
        &[&bob.owner],
    )
    .expect("apply failed");
    assert_eq!(balances(&env, &bob).0, amount - fee);
}

#[test]
fn the_permanent_delegate_cannot_reach_a_confidential_balance() {
    let mut env = Env::new();
    let (mint, _) = confidential_mint(&mut env);
    let alice = onboard(&mut env, &mint);
    let treasury = open_and_kyc(
        &mut env,
        &mint.pubkey(),
        &mint.issuer.pubkey(),
        &mint.issuer,
    );
    mint_to(
        &mut env,
        &mint.pubkey(),
        &alice.account,
        &mint.issuer,
        1_000_000,
    );

    env.call(
        t22_accounts::Seize {
            source: alice.account,
            mint: mint.pubkey(),
            destination: treasury,
            permanent_delegate: mint.issuer.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::Seize { amount: 100_000 },
        &[&mint.issuer],
    )
    .expect("seizing a public balance should work");
    assert_eq!(balance(&env, &alice.account), 900_000);

    deposit_and_apply(&mut env, &mint, &alice, 900_000);
    assert_eq!(balance(&env, &alice.account), 0);
    assert_eq!(balances(&env, &alice).0, 900_000);

    assert!(
        env.call(
            t22_accounts::Seize {
                source: alice.account,
                mint: mint.pubkey(),
                destination: treasury,
                permanent_delegate: mint.issuer.pubkey(),
                token_program: token_program(),
            },
            t22::instruction::Seize { amount: 100_000 },
            &[&mint.issuer],
        )
        .is_err(),
        "the permanent delegate should not reach a confidential balance"
    );

    let issuer_aes = AeKey::new_from_signer(&mint.issuer, &alice.account.to_bytes()).unwrap();
    let ct = confidential_state(&env, &alice.account);
    assert!(
        issuer_aes
            .decrypt(&ct.decryptable_available_balance.try_into().unwrap())
            .is_none(),
        "the delegate must not be able to read the balance it would prove over"
    );

    let freeze = t22new::instruction::freeze_account(
        &token_program(),
        &alice.account,
        &mint.pubkey(),
        &mint.issuer.pubkey(),
        &[],
    )
    .unwrap();
    env.send(&[freeze], &[&mint.issuer]).expect("freeze failed");

    assert!(env
        .call(
            t22_accounts::DepositConfidential {
                token_account: alice.account,
                mint: mint.pubkey(),
                owner: alice.owner.pubkey(),
                token_program: token_program(),
            },
            t22::instruction::DepositConfidential { amount: 1 },
            &[&alice.owner],
        )
        .is_err());
}
