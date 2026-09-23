//! Shared harness.
//!
//! The tests run against a real Token-2022 ELF, so an assertion that passes
//! here is an assertion about the program's actual behaviour, not about a mock.
#![allow(dead_code)]
// litesvm's own result type carries the full transaction metadata in its error
// variant, which is exactly what makes a failure readable here.
#![allow(clippy::result_large_err)]

use {
    litesvm::{types::TransactionResult, LiteSVM},
    solana_clock::Clock,
    solana_instruction::Instruction,
    solana_keypair::Keypair,
    solana_message::{Message, VersionedMessage},
    solana_pubkey::Pubkey,
    solana_rent::Rent,
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
    solana_zk_sdk::encryption::{elgamal::ElGamalKeypair, pod::elgamal::PodElGamalPubkey},
    spl_token_2022_interface::instruction as token_instruction,
    token22_ct::{
        confidential, kyc,
        mint::{self, ConfidentialConfig, RemittanceMint},
        plan::Step,
    },
};

pub const DECIMALS: u8 = 6;
/// 0.5%, capped — a plausible remittance fee.
pub const FEE_BPS: u16 = 50;
pub const MAX_FEE: u64 = 5_000;

pub const NAME: &str = "Remit USD";
pub const SYMBOL: &str = "rUSD";
pub const URI: &str = "https://example.org/rusd.json";

const SOL: u64 = 1_000_000_000;

pub struct Env {
    pub svm: LiteSVM,
    pub payer: Keypair,
}

impl Env {
    pub fn new() -> Self {
        let mut svm = LiteSVM::new();

        // litesvm bundles Token-2022 v10 built *without* the `zk-ops` feature,
        // where every confidential value-moving instruction is compiled out and
        // answers `InvalidInstructionData` unconditionally:
        //
        //     ConfidentialTransferInstruction::Deposit => {
        //         #[cfg(feature = "zk-ops")] { ... }
        //         #[cfg(not(feature = "zk-ops"))]
        //         Err(ProgramError::InvalidInstructionData)
        //     }
        //
        // Configure and Approve are not gated, so onboarding would pass and
        // every deposit, transfer and withdrawal would fail for a reason that
        // has nothing to do with this crate. Override it with a v11 build that
        // has `zk-ops` on.
        svm.add_program(
            spl_token_2022_interface::id(),
            include_bytes!("../fixtures/spl_token_2022.so"),
        )
        .expect("failed to load the Token-2022 fixture");

        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 1_000 * SOL).unwrap();
        Self { svm, payer }
    }

    pub fn rent(&self) -> Rent {
        self.svm.get_sysvar::<Rent>()
    }

    pub fn epoch(&self) -> u64 {
        self.svm.get_sysvar::<Clock>().epoch
    }

    /// A funded keypair, for roles that must pay their own way.
    pub fn funded_key(&mut self) -> Keypair {
        let key = Keypair::new();
        self.svm.airdrop(&key.pubkey(), 100 * SOL).unwrap();
        key
    }

    pub fn data(&self, address: &Pubkey) -> Vec<u8> {
        self.svm
            .get_account(address)
            .unwrap_or_else(|| panic!("account {address} does not exist"))
            .data
    }

    pub fn exists(&self, address: &Pubkey) -> bool {
        self.svm
            .get_account(address)
            .is_some_and(|a| !a.data.is_empty())
    }

    /// Send instructions signed by the payer plus exactly `extra`.
    pub fn send(&mut self, instructions: &[Instruction], extra: &[&Keypair]) -> TransactionResult {
        let mut signers: Vec<&Keypair> = vec![&self.payer];
        for key in extra {
            if key.pubkey() != self.payer.pubkey() {
                signers.push(key);
            }
        }
        let message = Message::new_with_blockhash(
            instructions,
            Some(&self.payer.pubkey()),
            &self.svm.latest_blockhash(),
        );
        let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(message), &signers)
            .expect("a declared signer was not supplied");
        self.svm.send_transaction(tx)
    }

    /// Run a [`Step`], signing with the payer plus **exactly** the signers the
    /// step declares — no more.
    ///
    /// This is deliberately strict: if a builder under-declares its signers the
    /// transaction fails signature verification, and if it over-declares one we
    /// cannot supply, `run` panics. Either way the step's signer list is under
    /// test, not just its instructions.
    pub fn run(&mut self, step: &Step, available: &[&Keypair]) -> TransactionResult {
        let signers: Vec<&Keypair> = step
            .signers
            .iter()
            .map(|wanted| {
                available
                    .iter()
                    .copied()
                    .find(|key| key.pubkey() == *wanted)
                    .unwrap_or_else(|| {
                        panic!(
                            "step {:?} declares signer {wanted}, which was not supplied",
                            step.label
                        )
                    })
            })
            .collect();
        self.send(&step.instructions, &signers)
    }

    pub fn run_all(&mut self, steps: &[Step], available: &[&Keypair]) {
        for step in steps {
            self.run(step, available)
                .unwrap_or_else(|e| panic!("step {:?} failed: {e:?}", step.label));
            // Each step is its own transaction; without a fresh blockhash the
            // next one would be rejected as a duplicate.
            self.svm.expire_blockhash();
        }
    }
}

/// The v1 remittance mint: one issuer key holds every authority.
pub struct MintV1 {
    pub mint: Keypair,
    pub issuer: Keypair,
}

impl MintV1 {
    pub fn config(&self, payer: &Pubkey) -> RemittanceMint<'static> {
        remittance_config(&self.mint.pubkey(), payer, &self.issuer.pubkey())
    }
}

pub fn remittance_config(
    mint: &Pubkey,
    payer: &Pubkey,
    issuer: &Pubkey,
) -> RemittanceMint<'static> {
    RemittanceMint {
        mint: *mint,
        payer: *payer,
        decimals: DECIMALS,
        mint_authority: *issuer,
        freeze_authority: *issuer,
        transfer_fee_config_authority: Some(*issuer),
        withdraw_withheld_authority: Some(*issuer),
        transfer_fee_basis_points: FEE_BPS,
        maximum_fee: MAX_FEE,
        close_authority: *issuer,
        metadata_authority: Some(*issuer),
        name: NAME,
        symbol: SYMBOL,
        uri: URI,
    }
}

pub fn create_mint_v1(env: &mut Env) -> MintV1 {
    let handle = MintV1 {
        mint: Keypair::new(),
        issuer: Keypair::new(),
    };
    let creation =
        mint::create_remittance_mint_v1(&handle.config(&env.payer.pubkey()), &env.rent()).unwrap();
    env.run(&creation.step, &[&handle.mint, &handle.issuer])
        .expect("mint v1 creation failed");
    env.svm.expire_blockhash();
    handle
}

/// The re-issued mint: adds a seizure authority and confidential transfers.
pub struct MintV2 {
    pub mint: Keypair,
    pub issuer: Keypair,
    /// Separate from the issuer, so tests can show seizure is its own
    /// authority rather than a side effect of holding the mint authority.
    pub delegate: Keypair,
    /// Holds the secret that decrypts withheld confidential fees.
    pub withheld_elgamal: ElGamalKeypair,
    /// Compliance read-access over every transfer amount.
    pub auditor_elgamal: ElGamalKeypair,
}

impl MintV2 {
    pub fn confidential_config(&self) -> ConfidentialConfig {
        ConfidentialConfig {
            authority: Some(self.issuer.pubkey()),
            auditor_elgamal_pubkey: Some(PodElGamalPubkey::from(*self.auditor_elgamal.pubkey())),
            withdraw_withheld_authority_elgamal_pubkey: PodElGamalPubkey::from(
                *self.withheld_elgamal.pubkey(),
            ),
            confidential_fee_authority: Some(self.issuer.pubkey()),
            permanent_delegate: self.delegate.pubkey(),
        }
    }

    pub fn config(&self, payer: &Pubkey) -> RemittanceMint<'static> {
        remittance_config(&self.mint.pubkey(), payer, &self.issuer.pubkey())
    }
}

pub fn new_mint_v2_handle() -> MintV2 {
    MintV2 {
        mint: Keypair::new(),
        issuer: Keypair::new(),
        delegate: Keypair::new(),
        withheld_elgamal: ElGamalKeypair::new_rand(),
        auditor_elgamal: ElGamalKeypair::new_rand(),
    }
}

pub fn create_mint_v2(env: &mut Env) -> MintV2 {
    let handle = new_mint_v2_handle();
    let creation = mint::create_remittance_mint_v2(
        &handle.config(&env.payer.pubkey()),
        &handle.confidential_config(),
        &env.rent(),
    )
    .unwrap();
    env.run(&creation.step, &[&handle.mint, &handle.issuer])
        .expect("mint v2 creation failed");
    env.svm.expire_blockhash();
    handle
}

/// Open an associated token account and clear it through KYC.
///
/// Split deliberately: the payer creates it, the freeze authority thaws it.
pub fn open_and_kyc(env: &mut Env, mint: &Pubkey, owner: &Pubkey, issuer: &Keypair) -> Pubkey {
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

    let thaw = kyc::thaw_after_kyc(mint, &account, &issuer.pubkey()).unwrap();
    env.send(&[thaw], &[issuer]).expect("thaw failed");
    env.svm.expire_blockhash();
    account
}

pub fn mint_to(env: &mut Env, mint: &Pubkey, account: &Pubkey, issuer: &Keypair, amount: u64) {
    let instruction = token_instruction::mint_to_checked(
        &spl_token_2022_interface::id(),
        mint,
        account,
        &issuer.pubkey(),
        &[],
        amount,
        DECIMALS,
    )
    .unwrap();
    env.send(&[instruction], &[issuer]).expect("mint_to failed");
    env.svm.expire_blockhash();
}

/// Public (non-confidential) balance of a token account.
pub fn balance(env: &Env, account: &Pubkey) -> u64 {
    token22_ct::state::token_account(&env.data(account))
        .unwrap()
        .base
        .amount
}
