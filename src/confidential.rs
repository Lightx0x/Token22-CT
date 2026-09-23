//! **Task 6: the confidential lifecycle, end to end.**
//!
//! A confidential account keeps two balances:
//!
//! * **pending** — where incoming credits (deposits and inbound transfers)
//!   land. The owner cannot spend it and, because senders write to it, cannot
//!   predict its ciphertext.
//! * **available** — spendable. Only the owner moves value into it, with
//!   `ApplyPendingBalance`.
//!
//! That split exists so a sender cannot invalidate a proof the owner is
//! building. It is also why `ApplyPendingBalance` is not an optimisation but a
//! mandatory step between "funds arrived" and "funds can be spent or
//! withdrawn".
//!
//! The full path, in order:
//!
//! | step | instruction | signer |
//! |---|---|---|
//! | 1 | `CreateAssociatedTokenAccount` | payer (**anyone**) |
//! | 2 | `ThawAccount` (KYC) | freeze authority |
//! | 3 | `Reallocate` | owner |
//! | 4 | `ConfigureAccount` | **owner only** |
//! | 5 | `ApproveAccount` | confidential-transfer mint authority |
//! | 6 | `Deposit` | owner |
//! | 7 | `ApplyPendingBalance` | owner |
//! | 8 | `Transfer` / `TransferWithFee` | owner |
//! | 9 | `ApplyPendingBalance`, then `WithdrawConfidentialTokens` | owner |
//!
//! Steps 1 and 4 are the pair worth being precise about. Creating an ATA is
//! permissionless — a relayer can open an account *for* a user, and Token-2022
//! is fine with it because the address is derived from the owner. Attaching
//! confidential state is not: `ConfigureAccount` registers the ElGamal public
//! key that will guard the balance, so the processor calls `validate_owner`
//! against the token account's own owner field. A payer who is not the owner
//! cannot do step 4, and the ElGamal key must be derived from the owner's
//! wallet, which the relayer does not hold.

use {
    crate::{
        error::{Error, Result},
        plan::Step,
        proof, state,
    },
    bytemuck::Zeroable,
    solana_pubkey::Pubkey,
    solana_rent::Rent,
    solana_signer::Signer,
    solana_zk_sdk::{
        encryption::{
            auth_encryption::{AeCiphertext, AeKey},
            elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
            pod::elgamal::PodElGamalPubkey,
        },
        zk_elgamal_proof_program::proof_data::PubkeyValidityProofData,
    },
    spl_token_2022_interface::{
        extension::{
            confidential_transfer::{
                instruction as confidential_instruction, EncryptedBalance,
                DEFAULT_MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER, PENDING_BALANCE_LO_BIT_LENGTH,
            },
            ExtensionType,
        },
        instruction as token_instruction,
    },
    spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation,
    spl_token_confidential_transfer_proof_generation::{
        transfer::transfer_split_proof_data, transfer_with_fee::transfer_with_fee_split_proof_data,
        withdraw::withdraw_proof_data,
    },
    std::num::NonZeroI8,
};

/// The two secrets that guard a confidential balance.
///
/// Neither ever reaches the chain: the ElGamal *public* key is stored in the
/// account, the AES key is not stored anywhere at all.
pub struct ConfidentialKeys {
    /// Homomorphic encryption of the balance. Its secret half is what proofs
    /// are built from — which is exactly why a permanent delegate that lacks it
    /// cannot move confidential funds.
    pub elgamal: ElGamalKeypair,
    /// Symmetric key for `decryptable_available_balance`, a convenience copy of
    /// the available balance that the owner can read without a discrete-log
    /// search.
    pub ae: AeKey,
}

impl ConfidentialKeys {
    /// Derive both keys deterministically from the owner's wallet.
    ///
    /// The wallet signs the token account address and the signature is hashed
    /// into key material, so the keys are reproducible on any device holding
    /// the wallet, never stored, and scoped to one account. Hardware wallets
    /// work because only a signature is required, never the raw secret.
    pub fn derive(owner: &dyn Signer, token_account: &Pubkey) -> Result<Self> {
        let seed = token_account.to_bytes();
        Ok(Self {
            elgamal: ElGamalKeypair::new_from_signer(owner, &seed)
                .map_err(|e| Error::KeyDerivation(e.to_string()))?,
            ae: AeKey::new_from_signer(owner, &seed)
                .map_err(|e| Error::KeyDerivation(e.to_string()))?,
        })
    }
}

/// Where a holder's tokens live for a given mint.
pub fn associated_token_address(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    spl_associated_token_account_interface::address::get_associated_token_address_with_program_id(
        owner,
        mint,
        &spl_token_2022_interface::id(),
    )
}

/// Plaintext view of a confidential account, for the owner only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfidentialBalances {
    /// Spendable now.
    pub available: u64,
    /// Received but not yet applied.
    pub pending: u64,
    /// How many credits have landed in pending. Quoted to
    /// `ApplyPendingBalance` so a credit arriving mid-flight is detectable.
    pub pending_credit_counter: u64,
    /// The counter the last `ApplyPendingBalance` said it expected.
    pub last_expected_credit_counter: u64,
    /// The counter that last `ApplyPendingBalance` actually applied. If this
    /// differs from [`Self::last_expected_credit_counter`], the stored
    /// decryptable balance is stale — see [`apply_pending_balance`].
    pub last_applied_credit_counter: u64,
}

/// Decrypt both balances.
///
/// `available` comes from the AES ciphertext (a direct decryption); `pending`
/// is stored as two ElGamal ciphertexts — a 16-bit low half and a 32-bit high
/// half — each recovered by discrete-log search over a small range. That split
/// is what keeps the search cheap.
pub fn decrypt_balances(
    account_data: &[u8],
    keys: &ConfidentialKeys,
) -> Result<ConfidentialBalances> {
    let ct = state::confidential_transfer_account(account_data)?;

    let decryptable: AeCiphertext = ct
        .decryptable_available_balance
        .try_into()
        .map_err(|_| Error::BalanceDecryption)?;
    let available = keys
        .ae
        .decrypt(&decryptable)
        .ok_or(Error::BalanceDecryption)?;

    let pending_lo: ElGamalCiphertext = ct
        .pending_balance_lo
        .try_into()
        .map_err(|_| Error::BalanceDecryption)?;
    let pending_hi: ElGamalCiphertext = ct
        .pending_balance_hi
        .try_into()
        .map_err(|_| Error::BalanceDecryption)?;

    let lo = keys
        .elgamal
        .secret()
        .decrypt_u32(&pending_lo)
        .ok_or(Error::BalanceDecryption)?;
    let hi = keys
        .elgamal
        .secret()
        .decrypt_u32(&pending_hi)
        .ok_or(Error::BalanceDecryption)?;

    // The two halves recombine as `lo + (hi << 16)`.
    let pending = hi
        .checked_shl(PENDING_BALANCE_LO_BIT_LENGTH)
        .and_then(|high| lo.checked_add(high))
        .ok_or(Error::BalanceDecryption)?;

    Ok(ConfidentialBalances {
        available,
        pending,
        pending_credit_counter: ct.pending_balance_credit_counter.into(),
        last_expected_credit_counter: ct.expected_pending_balance_credit_counter.into(),
        last_applied_credit_counter: ct.actual_pending_balance_credit_counter.into(),
    })
}

/// **Steps 1–3.** Open a token account and make room for confidential state.
///
/// Returned as two steps because they have different signers, and that
/// difference is the point:
///
/// * the ATA creation is signed by the payer alone — a relayer can front the
///   rent for a user who holds no SOL;
/// * `Reallocate` is signed by the owner, because it grows an account the owner
///   controls (the payer funds the extra rent).
///
/// `Reallocate` is required at all because ConfigureAccount does not grow the
/// account — the ATA program sizes a new account only for the extensions a mint
/// *requires* (here `TransferFeeAmount`), and `ConfidentialTransferAccount` is
/// opt-in.
///
/// Both steps work on a still-frozen account, as do `ConfigureAccount` and
/// `ApproveAccount` — none of them moves value. Everything from `Deposit`
/// onward (including `ApplyPendingBalance`) rejects a frozen account, so the
/// KYC thaw must land before step 6 but may land any time before it.
pub fn open_account(
    payer: &Pubkey,
    owner: &Pubkey,
    mint: &Pubkey,
    mint_data: &[u8],
) -> Result<(Pubkey, Vec<Step>)> {
    let token_program = spl_token_2022_interface::id();
    let token_account = associated_token_address(owner, mint);

    // On a fee-bearing mint, ConfigureAccount also initialises
    // ConfidentialTransferFeeAmount (to hold encrypted withheld fees), so the
    // space for it has to exist up front too.
    let mut new_extensions = vec![ExtensionType::ConfidentialTransferAccount];
    if state::has_transfer_fee(mint_data)? {
        new_extensions.push(ExtensionType::ConfidentialTransferFeeAmount);
    }

    let create =
        spl_associated_token_account_interface::instruction::create_associated_token_account(
            payer,
            owner,
            mint,
            &token_program,
        );

    let reallocate = token_instruction::reallocate(
        &token_program,
        &token_account,
        payer,
        owner,
        &[],
        &new_extensions,
    )?;

    Ok((
        token_account,
        vec![
            Step::payer_only("create associated token account", vec![create]),
            Step::new(
                "reallocate for confidential state",
                vec![reallocate],
                vec![*owner],
            ),
        ],
    ))
}

/// **Step 4. `ConfigureAccount` — owner only.**
///
/// Registers the account's ElGamal public key and its zeroed decryptable
/// balance. The accompanying `PubkeyValidity` proof shows the caller actually
/// holds the matching secret, which stops anyone registering a key they cannot
/// decrypt with (and thereby bricking the account).
///
/// The proof is ~96 bytes, so it travels inline at relative offset 1 rather
/// than through a context state account.
pub fn configure_account(
    token_account: &Pubkey,
    mint: &Pubkey,
    owner: &Pubkey,
    keys: &ConfidentialKeys,
    maximum_pending_balance_credit_counter: Option<u64>,
) -> Result<Step> {
    // Proves knowledge of the ElGamal secret for the registered public key.
    let proof_data = PubkeyValidityProofData::new(&keys.elgamal)
        .map_err(|_| Error::KeyDerivation("invalid ElGamal keypair".into()))?;

    // A valid encryption of zero, readable only by the owner's AES key.
    let decryptable_zero_balance = keys.ae.encrypt(0).into();

    let instructions = confidential_instruction::configure_account(
        &spl_token_2022_interface::id(),
        token_account,
        mint,
        &decryptable_zero_balance,
        // Cap on unapplied credits. Once reached, incoming transfers are
        // rejected until the owner applies — back-pressure that stops a spammer
        // forcing an unbounded discrete-log search on the owner.
        maximum_pending_balance_credit_counter
            .unwrap_or(DEFAULT_MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER),
        owner,
        &[],
        ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &proof_data),
    )?;

    // Owner signs — not the payer who created the account in step 1.
    Ok(Step::new("configure account", instructions, vec![*owner]))
}

/// **Step 5. `ApproveAccount`.**
///
/// Needed because the mint was created with `approve_policy = manual`
/// (`auto_approve_new_accounts: false`): `ConfigureAccount` leaves `approved`
/// false, and every confidential operation fails until the mint's
/// confidential-transfer authority signs this. It is the issuer's second gate,
/// independent of the KYC thaw in step 2.
pub fn approve_account(
    token_account: &Pubkey,
    mint: &Pubkey,
    confidential_transfer_authority: &Pubkey,
) -> Result<Step> {
    let instruction = confidential_instruction::approve_account(
        &spl_token_2022_interface::id(),
        token_account,
        mint,
        confidential_transfer_authority,
        &[],
    )?;

    Ok(Step::new(
        "approve confidential account",
        vec![instruction],
        vec![*confidential_transfer_authority],
    ))
}

/// **Step 6. `DepositConfidentialTokens`.**
///
/// Moves value from the account's public balance into its own *pending*
/// confidential balance. No proof is needed: the amount is public on the way in
/// — hiding it is what the later transfer does. The account must be thawed, as
/// deposits reject frozen accounts.
pub fn deposit(
    token_account: &Pubkey,
    mint: &Pubkey,
    mint_data: &[u8],
    owner: &Pubkey,
    amount: u64,
) -> Result<Step> {
    let instruction = confidential_instruction::deposit(
        &spl_token_2022_interface::id(),
        token_account,
        mint,
        amount,
        state::decimals(mint_data)?,
        owner,
        &[],
    )?;

    Ok(Step::new(
        "deposit to confidential balance",
        vec![instruction],
        vec![*owner],
    ))
}

/// **Step 7 / 9a. `ApplyPendingBalance`.**
///
/// Folds pending into available. The chain does the ciphertext addition
/// homomorphically; the owner supplies the matching *plaintext* sum re-encrypted
/// under their AES key, since only the owner can read either side.
///
/// The credit counter is the race detector, and it does not abort: the chain
/// always applies whatever is pending, then stores the counter the caller
/// expected alongside the counter that actually applied. If a credit lands
/// between reading the account and this landing, the two differ and the
/// `decryptable_available_balance` written here is short by that credit — the
/// ElGamal `available_balance` is still correct. The fix is to re-read, compare
/// the two counters, and if they disagree apply again with the corrected sum
/// (pending is zero by then, so the second apply only rewrites the decryptable
/// copy).
pub fn apply_pending_balance(
    token_account: &Pubkey,
    account_data: &[u8],
    owner: &Pubkey,
    keys: &ConfidentialKeys,
) -> Result<Step> {
    let balances = decrypt_balances(account_data, keys)?;

    let new_available = balances
        .available
        .checked_add(balances.pending)
        .ok_or(Error::BalanceDecryption)?;

    let instruction = confidential_instruction::apply_pending_balance(
        &spl_token_2022_interface::id(),
        token_account,
        balances.pending_credit_counter,
        &keys.ae.encrypt(new_available).into(),
        owner,
        &[],
    )?;

    Ok(Step::new(
        "apply pending balance",
        vec![instruction],
        vec![*owner],
    ))
}

/// Fresh keypairs the caller generated, one per proof, to hold verified proof
/// contexts.
///
/// `fee_sigma` and `fee_validity` are required exactly when the mint charges a
/// transfer fee, and must be absent otherwise.
pub struct TransferProofAccounts {
    pub equality: Pubkey,
    pub transfer_amount_validity: Pubkey,
    pub range: Pubkey,
    pub fee_sigma: Option<Pubkey>,
    pub fee_validity: Option<Pubkey>,
}

/// **Step 8. The confidential transfer.**
///
/// Which instruction this builds is decided by the mint, not by the caller:
/// Token-2022's processor branches on whether the mint has `TransferFeeConfig`,
/// and only the matching variant is accepted.
///
/// * no fee → `Transfer`, three proofs (equality, ciphertext validity, 128-bit
///   range);
/// * fee → `TransferWithFee`, five proofs (the three above plus a
///   percentage-with-cap proof that the encrypted fee really is the mint's
///   rate applied to the encrypted amount, and a validity proof for the fee
///   ciphertext, with the range proof widened to 256 bits).
///
/// The fee proof is the interesting one: it lets the chain enforce the fee
/// schedule without anyone learning the amount.
///
/// Each proof is verified into its own account in its own transaction, then the
/// transfer references all of them, then the accounts are closed to recover
/// rent. The returned steps are in submission order.
#[allow(clippy::too_many_arguments)]
pub fn transfer(
    payer: &Pubkey,
    source: &Pubkey,
    source_data: &[u8],
    destination: &Pubkey,
    destination_data: &[u8],
    mint: &Pubkey,
    mint_data: &[u8],
    owner: &Pubkey,
    keys: &ConfidentialKeys,
    amount: u64,
    current_epoch: u64,
    context_accounts: &TransferProofAccounts,
    rent: &Rent,
) -> Result<Vec<Step>> {
    let token_program = spl_token_2022_interface::id();

    let source_ct = state::confidential_transfer_account(source_data)?;
    let destination_ct = state::confidential_transfer_account(destination_data)?;
    let confidential_mint = state::confidential_transfer_mint(mint_data)?;

    // Source's current available balance, in both forms the prover needs.
    let current_available: ElGamalCiphertext = source_ct
        .available_balance
        .try_into()
        .map_err(|_| Error::BalanceDecryption)?;
    let current_decryptable: AeCiphertext = source_ct
        .decryptable_available_balance
        .try_into()
        .map_err(|_| Error::BalanceDecryption)?;
    let available = keys
        .ae
        .decrypt(&current_decryptable)
        .ok_or(Error::BalanceDecryption)?;
    if available < amount {
        return Err(Error::InsufficientConfidentialBalance {
            available,
            requested: amount,
        });
    }

    let destination_pubkey: ElGamalPubkey = destination_ct
        .elgamal_pubkey
        .try_into()
        .map_err(|_| Error::BalanceDecryption)?;
    let auditor_pubkey = optional_elgamal_pubkey(&confidential_mint.auditor_elgamal_pubkey)?;

    // The source is debited the full amount in both variants; on a fee mint the
    // fee is withheld on the destination side, not added on top.
    let new_source_decryptable = keys.ae.encrypt(available - amount).into();

    let mut steps = Vec::new();
    let mut to_close = vec![
        context_accounts.equality,
        context_accounts.transfer_amount_validity,
        context_accounts.range,
    ];

    let transfer_instructions = if state::has_transfer_fee(mint_data)? {
        let (fee_sigma, fee_validity) =
            match (context_accounts.fee_sigma, context_accounts.fee_validity) {
                (Some(a), Some(b)) => (a, b),
                _ => {
                    return Err(Error::MissingExtension(
                        "fee proof context accounts (mint charges a transfer fee)",
                    ))
                }
            };
        to_close.extend_from_slice(&[fee_sigma, fee_validity]);

        let fee_config = state::transfer_fee_config(mint_data)?;
        // The fee schedule for *this* epoch, same source of truth as the public
        // transfer path; the proof is built against it and the chain re-checks
        // it, so a stale rate fails verification.
        let epoch_fee = fee_config.get_epoch_fee(current_epoch);

        let withheld_authority_pubkey: ElGamalPubkey =
            state::confidential_transfer_fee_config(mint_data)?
                .withdraw_withheld_authority_elgamal_pubkey
                .try_into()
                .map_err(|_| Error::BalanceDecryption)?;

        let proofs = transfer_with_fee_split_proof_data(
            &current_available,
            &current_decryptable,
            amount,
            &keys.elgamal,
            &keys.ae,
            &destination_pubkey,
            auditor_pubkey.as_ref(),
            &withheld_authority_pubkey,
            epoch_fee.transfer_fee_basis_points.into(),
            epoch_fee.maximum_fee.into(),
        )?;

        steps.extend(proof::verify_into_context_state(
            "verify equality proof",
            "allocate equality proof context",
            payer,
            &context_accounts.equality,
            owner,
            &proofs.equality_proof_data,
            rent,
        ));
        steps.extend(proof::verify_into_context_state(
            "verify transfer amount validity proof",
            "allocate transfer amount validity context",
            payer,
            &context_accounts.transfer_amount_validity,
            owner,
            &proofs
                .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
                .proof_data,
            rent,
        ));
        steps.extend(proof::verify_into_context_state(
            "verify fee percentage-with-cap proof",
            "allocate fee percentage-with-cap context",
            payer,
            &fee_sigma,
            owner,
            &proofs.percentage_with_cap_proof_data,
            rent,
        ));
        steps.extend(proof::verify_into_context_state(
            "verify fee ciphertext validity proof",
            "allocate fee ciphertext validity context",
            payer,
            &fee_validity,
            owner,
            &proofs.fee_ciphertext_validity_proof_data,
            rent,
        ));
        steps.extend(proof::verify_into_context_state(
            "verify range proof",
            "allocate range proof context",
            payer,
            &context_accounts.range,
            owner,
            &proofs.range_proof_data,
            rent,
        ));

        confidential_instruction::transfer_with_fee(
            &token_program,
            source,
            mint,
            destination,
            &new_source_decryptable,
            // Handed to the chain so it can check they match the proof — this
            // is what guarantees the auditor really can decrypt the amount.
            &proofs
                .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
                .ciphertext_lo,
            &proofs
                .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
                .ciphertext_hi,
            owner,
            &[],
            ProofLocation::ContextStateAccount(&context_accounts.equality),
            ProofLocation::ContextStateAccount(&context_accounts.transfer_amount_validity),
            ProofLocation::ContextStateAccount(&fee_sigma),
            ProofLocation::ContextStateAccount(&fee_validity),
            ProofLocation::ContextStateAccount(&context_accounts.range),
        )?
    } else {
        if context_accounts.fee_sigma.is_some() || context_accounts.fee_validity.is_some() {
            return Err(Error::MissingExtension(
                "TransferFeeConfig (fee proof accounts supplied for a fee-less mint)",
            ));
        }

        let proofs = transfer_split_proof_data(
            &current_available,
            &current_decryptable,
            amount,
            &keys.elgamal,
            &keys.ae,
            &destination_pubkey,
            auditor_pubkey.as_ref(),
        )?;

        steps.extend(proof::verify_into_context_state(
            "verify equality proof",
            "allocate equality proof context",
            payer,
            &context_accounts.equality,
            owner,
            &proofs.equality_proof_data,
            rent,
        ));
        steps.extend(proof::verify_into_context_state(
            "verify transfer amount validity proof",
            "allocate transfer amount validity context",
            payer,
            &context_accounts.transfer_amount_validity,
            owner,
            &proofs
                .ciphertext_validity_proof_data_with_ciphertext
                .proof_data,
            rent,
        ));
        steps.extend(proof::verify_into_context_state(
            "verify range proof",
            "allocate range proof context",
            payer,
            &context_accounts.range,
            owner,
            &proofs.range_proof_data,
            rent,
        ));

        confidential_instruction::transfer(
            &token_program,
            source,
            mint,
            destination,
            &new_source_decryptable,
            &proofs
                .ciphertext_validity_proof_data_with_ciphertext
                .ciphertext_lo,
            &proofs
                .ciphertext_validity_proof_data_with_ciphertext
                .ciphertext_hi,
            owner,
            &[],
            ProofLocation::ContextStateAccount(&context_accounts.equality),
            ProofLocation::ContextStateAccount(&context_accounts.transfer_amount_validity),
            ProofLocation::ContextStateAccount(&context_accounts.range),
        )?
    };

    steps.push(Step::new(
        "confidential transfer",
        transfer_instructions,
        vec![*owner],
    ));

    // Reclaim the proof rent. The owner is the context state authority, so the
    // owner signs; lamports go back to the payer that funded them.
    steps.push(Step::new(
        "close proof context accounts",
        to_close
            .iter()
            .map(|account| proof::close(account, owner, payer))
            .collect(),
        vec![*owner],
    ));

    Ok(steps)
}

/// Context accounts for a withdrawal: an equality proof and a 64-bit range
/// proof over the remaining balance.
pub struct WithdrawProofAccounts {
    pub equality: Pubkey,
    pub range: Pubkey,
}

/// **Step 9b. `WithdrawConfidentialTokens`.**
///
/// Moves value back out to the public balance, revealing the amount.
///
/// Withdrawal spends the *available* balance, so anything still pending is
/// invisible to it — and worse, a proof built while a credit is pending is
/// built against a ciphertext the chain has already moved past. This function
/// refuses to build in that state; call [`apply_pending_balance`] first, let it
/// land, re-read the account, then call this.
#[allow(clippy::too_many_arguments)]
pub fn withdraw(
    payer: &Pubkey,
    token_account: &Pubkey,
    account_data: &[u8],
    mint: &Pubkey,
    mint_data: &[u8],
    owner: &Pubkey,
    keys: &ConfidentialKeys,
    amount: u64,
    context_accounts: &WithdrawProofAccounts,
    rent: &Rent,
) -> Result<Vec<Step>> {
    let ct = state::confidential_transfer_account(account_data)?;

    // ApplyPendingBalance zeroes both pending ciphertexts; anything non-zero
    // here means it has not run since the last credit landed.
    let pending_applied = ct.pending_balance_lo == EncryptedBalance::zeroed()
        && ct.pending_balance_hi == EncryptedBalance::zeroed();
    if !pending_applied {
        return Err(Error::PendingBalanceNotApplied);
    }

    let current_available: ElGamalCiphertext = ct
        .available_balance
        .try_into()
        .map_err(|_| Error::BalanceDecryption)?;
    let decryptable: AeCiphertext = ct
        .decryptable_available_balance
        .try_into()
        .map_err(|_| Error::BalanceDecryption)?;
    let available = keys
        .ae
        .decrypt(&decryptable)
        .ok_or(Error::BalanceDecryption)?;
    if available < amount {
        return Err(Error::InsufficientConfidentialBalance {
            available,
            requested: amount,
        });
    }

    // Proves the remaining balance is correct and non-negative without
    // revealing it — only `amount` becomes public.
    let proofs = withdraw_proof_data(&current_available, available, amount, &keys.elgamal)?;

    let equality_steps = proof::verify_into_context_state(
        "verify withdraw equality proof",
        "allocate withdraw equality context",
        payer,
        &context_accounts.equality,
        owner,
        &proofs.equality_proof_data,
        rent,
    );
    let range_steps = proof::verify_into_context_state(
        "verify withdraw range proof",
        "allocate withdraw range context",
        payer,
        &context_accounts.range,
        owner,
        &proofs.range_proof_data,
        rent,
    );

    let withdraw_instruction = confidential_instruction::inner_withdraw(
        &spl_token_2022_interface::id(),
        token_account,
        mint,
        amount,
        state::decimals(mint_data)?,
        &keys.ae.encrypt(available - amount).into(),
        owner,
        &[],
        ProofLocation::ContextStateAccount(&context_accounts.equality),
        ProofLocation::ContextStateAccount(&context_accounts.range),
    )?;

    let mut steps = Vec::with_capacity(6);
    steps.extend(equality_steps);
    steps.extend(range_steps);
    steps.push(Step::new(
        "withdraw from confidential balance",
        vec![withdraw_instruction],
        vec![*owner],
    ));
    steps.push(Step::new(
        "close proof context accounts",
        vec![
            proof::close(&context_accounts.equality, owner, payer),
            proof::close(&context_accounts.range, owner, payer),
        ],
        vec![*owner],
    ));
    Ok(steps)
}

/// `OptionalNonZeroElGamalPubkey` -> `Option<ElGamalPubkey>`.
fn optional_elgamal_pubkey(
    optional: &spl_pod::optional_keys::OptionalNonZeroElGamalPubkey,
) -> Result<Option<ElGamalPubkey>> {
    let pod: Option<PodElGamalPubkey> = Option::from(*optional);
    match pod {
        None => Ok(None),
        Some(pod) => Ok(Some(pod.try_into().map_err(|_| Error::BalanceDecryption)?)),
    }
}
