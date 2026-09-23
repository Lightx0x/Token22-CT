//! Zero-knowledge proof plumbing for the confidential extension.
//!
//! Token-2022 never verifies a proof itself. It reads an already-verified
//! *proof context* produced by the ZK ElGamal proof program, located either:
//!
//! * inline — the verify instruction sits in the same transaction and the token
//!   instruction points at it by relative offset; or
//! * by reference — the proof was verified earlier into a **context state
//!   account**, and the token instruction just names that account.
//!
//! Inline is simpler and is used here for `ConfigureAccount`, whose proof is
//! under 100 bytes. Everything else uses context state accounts: a single
//! `BatchedRangeProofU256Data` is on its own larger than a transaction, so a
//! five-proof `TransferWithFee` has no inline form at all.
//!
//! Context state accounts are rent-bearing and single-use. Each helper below
//! pairs with [`close`], which returns the rent; forgetting that is a slow
//! lamport leak, one account per transfer.

use {
    crate::plan::Step,
    solana_compute_budget_interface::ComputeBudgetInstruction,
    solana_instruction::Instruction,
    solana_pubkey::Pubkey,
    solana_rent::Rent,
    solana_system_interface::instruction as system_instruction,
    solana_zk_sdk::zk_elgamal_proof_program::{
        self,
        instruction::{ContextStateInfo, ProofInstruction},
        proof_data::{ProofType, ZkProofData},
        state::ProofContextState,
    },
};

/// Compute units to request for verifying a given proof.
///
/// The default 200k budget does not cover the range proofs — verifying a
/// `BatchedRangeProofU256` exceeds it on its own, and without an explicit
/// request the transaction dies with `ComputationalBudgetExceeded`. These are
/// headroom figures, not measured minima: tighten them if you pay a priority
/// fee, since the requested limit is what that fee scales with.
fn compute_units_for(proof_type: ProofType) -> u32 {
    match proof_type {
        ProofType::BatchedRangeProofU256 => 800_000,
        ProofType::BatchedRangeProofU128 => 500_000,
        ProofType::BatchedRangeProofU64 => 300_000,
        // The sigma proofs are cheap by comparison and fit the default, but an
        // explicit request keeps every verify step self-sufficient.
        _ => 200_000,
    }
}

/// The `ProofInstruction` that verifies a given proof type.
///
/// Derived from the proof data's own `PROOF_TYPE` so a call site cannot pair a
/// proof with the wrong verifier — a mistake the runtime would only report as
/// an opaque instruction error.
fn verifier_for(proof_type: ProofType) -> ProofInstruction {
    match proof_type {
        ProofType::ZeroCiphertext => ProofInstruction::VerifyZeroCiphertext,
        ProofType::CiphertextCiphertextEquality => {
            ProofInstruction::VerifyCiphertextCiphertextEquality
        }
        ProofType::CiphertextCommitmentEquality => {
            ProofInstruction::VerifyCiphertextCommitmentEquality
        }
        ProofType::PubkeyValidity => ProofInstruction::VerifyPubkeyValidity,
        ProofType::PercentageWithCap => ProofInstruction::VerifyPercentageWithCap,
        ProofType::BatchedRangeProofU64 => ProofInstruction::VerifyBatchedRangeProofU64,
        ProofType::BatchedRangeProofU128 => ProofInstruction::VerifyBatchedRangeProofU128,
        ProofType::BatchedRangeProofU256 => ProofInstruction::VerifyBatchedRangeProofU256,
        ProofType::GroupedCiphertext2HandlesValidity => {
            ProofInstruction::VerifyGroupedCiphertext2HandlesValidity
        }
        ProofType::BatchedGroupedCiphertext2HandlesValidity => {
            ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity
        }
        ProofType::GroupedCiphertext3HandlesValidity => {
            ProofInstruction::VerifyGroupedCiphertext3HandlesValidity
        }
        ProofType::BatchedGroupedCiphertext3HandlesValidity => {
            ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity
        }
        // Not reachable: no proof data carries `Uninitialized`, which exists
        // only to mark an unwritten context account.
        ProofType::Uninitialized => unreachable!("proof data always names a real proof type"),
    }
}

/// Allocate a context state account, then verify one proof into it.
///
/// Two steps, deliberately. The proof data travels inside the verify
/// instruction, and a `BatchedRangeProofU256Data` is on its own close to the
/// 1232-byte packet limit — pairing it with anything else, even a small
/// `CreateAccount`, risks a transaction that cannot be sent. Allocating
/// separately keeps every verify instruction alone in its transaction, at the
/// cost of one cheap extra transaction per proof.
///
/// The labels are `allocate <label>` and `verify <label>`.
pub fn verify_into_context_state<T, U>(
    label: &'static str,
    allocate_label: &'static str,
    payer: &Pubkey,
    context_state_account: &Pubkey,
    context_state_authority: &Pubkey,
    proof_data: &T,
    rent: &Rent,
) -> [Step; 2]
where
    T: bytemuck::Pod + ZkProofData<U>,
    U: bytemuck::Pod,
{
    // authority (32) + proof type tag (1) + the context itself.
    let space = std::mem::size_of::<ProofContextState<U>>();

    let create = system_instruction::create_account(
        payer,
        context_state_account,
        rent.minimum_balance(space),
        space as u64,
        &zk_elgamal_proof_program::id(),
    );

    // Picking the verifier from the proof's own `PROOF_TYPE` means a call site
    // cannot pair a proof with the wrong one.
    let verify = verifier_for(T::PROOF_TYPE).encode_verify_proof(
        Some(ContextStateInfo {
            context_state_account,
            context_state_authority,
        }),
        proof_data,
    );

    [
        // The freshly generated context account signs its own allocation.
        Step::new(allocate_label, vec![create], vec![*context_state_account]),
        Step::payer_only(
            label,
            vec![
                ComputeBudgetInstruction::set_compute_unit_limit(compute_units_for(T::PROOF_TYPE)),
                verify,
            ],
        ),
    ]
}

/// Reclaim the rent from a context state account once the token instruction
/// that consumed it has landed. Signed by the context state authority.
pub fn close(
    context_state_account: &Pubkey,
    context_state_authority: &Pubkey,
    rent_destination: &Pubkey,
) -> Instruction {
    zk_elgamal_proof_program::instruction::close_context_state(
        ContextStateInfo {
            context_state_account,
            context_state_authority,
        },
        rent_destination,
    )
}
