#![allow(dead_code)]
// litesvm's error variant carries the full transaction metadata.
#![allow(clippy::result_large_err)]

use {
    anchor_lang::{
        error::{ErrorCode as AnchorError, ERROR_CODE_OFFSET},
        InstructionData, ToAccountMetas,
    },
    litesvm::{types::TransactionResult, LiteSVM},
    solana_account::Account,
    solana_instruction::Instruction,
    solana_instruction_error::InstructionError,
    solana_keypair::Keypair,
    solana_message::{Message, VersionedMessage},
    solana_pubkey::Pubkey,
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
    solana_transaction_error::TransactionError,
    t22::accounts as t22_accounts,
    t22new::{
        error::TokenError,
        extension::{
            transfer_fee::{TransferFeeAmount, TransferFeeConfig},
            BaseStateWithExtensions, StateWithExtensions,
        },
        state::{Account as TokenAccountState, AccountState, Mint as MintState},
    },
};

pub const DECIMALS: u8 = 6;
pub const FEE_BPS: u16 = 50;
pub const MAX_FEE: u64 = 5_000;

pub const NAME: &str = "Remit USD";
pub const SYMBOL: &str = "rUSD";
pub const URI: &str = "https://example.org/rusd.json";

pub const SOL: u64 = 1_000_000_000;

pub fn token_program() -> Pubkey {
    t22new::id()
}

pub fn token(e: TokenError) -> InstructionError {
    InstructionError::Custom(e as u32)
}

pub fn program(e: t22::MintError) -> InstructionError {
    InstructionError::Custom(ERROR_CODE_OFFSET + e as u32)
}

pub fn anchor(e: AnchorError) -> InstructionError {
    InstructionError::Custom(e as u32)
}

/// Accounts captured before a call that must not change them.
pub struct Snapshot(Vec<(Pubkey, Option<Account>)>);

pub struct Env {
    pub svm: LiteSVM,
    pub payer: Keypair,
}

impl Env {
    pub fn new() -> Self {
        let mut svm = LiteSVM::new();
        // litesvm's bundled Token-2022 is built without `zk-ops`, so every
        // confidential value-moving instruction returns InvalidInstructionData.
        svm.add_program(
            token_program(),
            include_bytes!("../fixtures/spl_token_2022.so"),
        )
        .expect("failed to load the Token-2022 fixture");
        svm.add_program(
            t22::ID,
            include_bytes!(concat!(env!("CARGO_TARGET_TMPDIR"), "/../deploy/t22.so")),
        )
        .expect("run `cargo build-sbf` first");

        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 1_000 * SOL).unwrap();
        Self { svm, payer }
    }

    pub fn epoch(&self) -> u64 {
        self.svm.get_sysvar::<solana_clock::Clock>().epoch
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        let mut clock = self.svm.get_sysvar::<solana_clock::Clock>();
        clock.epoch = epoch;
        self.svm.set_sysvar(&clock);
    }

    pub fn data(&self, address: &Pubkey) -> Vec<u8> {
        self.svm
            .get_account(address)
            .unwrap_or_else(|| panic!("account {address} does not exist"))
            .data
    }

    pub fn lamports(&self, address: &Pubkey) -> u64 {
        self.svm.get_account(address).map_or(0, |a| a.lamports)
    }

    pub fn exists(&self, address: &Pubkey) -> bool {
        self.svm
            .get_account(address)
            .is_some_and(|a| a.lamports > 0)
    }

    pub fn snapshot(&self, keys: &[Pubkey]) -> Snapshot {
        Snapshot(keys.iter().map(|k| (*k, self.svm.get_account(k))).collect())
    }

    pub fn assert_unchanged(&self, before: &Snapshot) {
        for (key, account) in &before.0 {
            assert_eq!(&self.svm.get_account(key), account, "account {key} changed");
        }
    }

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
            .expect("the signer set does not match the instructions");
        let result = self.svm.send_transaction(tx);
        self.svm.expire_blockhash();
        result
    }

    /// The last instruction must fail with exactly `expected`, and every
    /// `watched` account must be byte-for-byte what it was before.
    pub fn rejects(
        &mut self,
        instructions: &[Instruction],
        extra: &[&Keypair],
        expected: InstructionError,
        watched: &[Pubkey],
    ) {
        let index = (instructions.len() - 1) as u8;
        self.rejects_at(instructions, extra, index, expected, watched);
    }

    pub fn rejects_at(
        &mut self,
        instructions: &[Instruction],
        extra: &[&Keypair],
        index: u8,
        expected: InstructionError,
        watched: &[Pubkey],
    ) {
        let before = self.snapshot(watched);
        match self.send(instructions, extra) {
            Ok(_) => panic!("expected {expected:?} at instruction {index}, but it succeeded"),
            Err(e) => assert_eq!(
                e.err,
                TransactionError::InstructionError(index, expected),
                "logs: {:#?}",
                e.meta.logs
            ),
        }
        self.assert_unchanged(&before);
    }
}

pub fn ix<A: ToAccountMetas, D: InstructionData>(accounts: A, data: D) -> Instruction {
    Instruction {
        program_id: t22::ID,
        accounts: accounts.to_account_metas(None),
        data: data.data(),
    }
}

/// The same instruction with `key` marked as not signing, to test a missing
/// signature without the runtime rejecting the transaction first.
pub fn unsigned(mut instruction: Instruction, key: &Pubkey) -> Instruction {
    for meta in &mut instruction.accounts {
        if meta.pubkey == *key {
            meta.is_signer = false;
        }
    }
    instruction
}

pub struct Mint {
    pub key: Keypair,
    pub issuer: Keypair,
}

impl Mint {
    pub fn pubkey(&self) -> Pubkey {
        self.key.pubkey()
    }
}

pub fn new_mint(env: &mut Env) -> Mint {
    let mint = Mint {
        key: Keypair::new(),
        issuer: Keypair::new(),
    };
    env.svm.airdrop(&mint.issuer.pubkey(), 100 * SOL).unwrap();
    mint
}

pub fn create_mint_accounts(mint: &Mint) -> t22_accounts::CreateMint {
    t22_accounts::CreateMint {
        payer: mint.issuer.pubkey(),
        mint: mint.pubkey(),
        token_program: token_program(),
        system_program: solana_system_interface::program::ID,
    }
}

pub fn remittance_mint_data() -> t22::instruction::CreateRemittanceMint {
    t22::instruction::CreateRemittanceMint {
        decimals: DECIMALS,
        basis_points: FEE_BPS,
        maximum_fee: MAX_FEE,
        name: NAME.to_string(),
        symbol: SYMBOL.to_string(),
        uri: URI.to_string(),
    }
}

pub fn create_remittance_mint(env: &mut Env) -> Mint {
    let mint = new_mint(env);
    env.send(
        &[ix(create_mint_accounts(&mint), remittance_mint_data())],
        &[&mint.key, &mint.issuer],
    )
    .expect("remittance mint creation failed");
    mint
}

pub fn create_confidential_mint(
    env: &mut Env,
    withdraw_withheld_elgamal: [u8; 32],
    auditor_elgamal: Option<[u8; 32]>,
) -> Mint {
    let mint = new_mint(env);
    env.send(
        &[ix(
            create_mint_accounts(&mint),
            t22::instruction::CreateConfidentialMint {
                decimals: DECIMALS,
                basis_points: FEE_BPS,
                maximum_fee: MAX_FEE,
                withdraw_withheld_elgamal,
                auditor_elgamal,
                name: NAME.to_string(),
                symbol: SYMBOL.to_string(),
                uri: URI.to_string(),
            },
        )],
        &[&mint.key, &mint.issuer],
    )
    .expect("confidential mint creation failed");
    mint
}

pub fn associated_token_address(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    spl_associated_token_account_interface::address::get_associated_token_address_with_program_id(
        owner,
        mint,
        &token_program(),
    )
}

pub fn create_ata(env: &mut Env, mint: &Pubkey, owner: &Pubkey) -> Pubkey {
    let account = associated_token_address(owner, mint);
    let create =
        spl_associated_token_account_interface::instruction::create_associated_token_account(
            &env.payer.pubkey(),
            owner,
            mint,
            &token_program(),
        );
    env.send(&[create], &[]).expect("ATA creation failed");
    account
}

pub fn thaw_ix(account: &Pubkey, mint: &Pubkey, freeze_authority: &Pubkey) -> Instruction {
    ix(
        t22_accounts::ThawAfterKyc {
            token_account: *account,
            mint: *mint,
            freeze_authority: *freeze_authority,
            token_program: token_program(),
        },
        t22::instruction::ThawAfterKyc {},
    )
}

pub fn freeze(env: &mut Env, account: &Pubkey, mint: &Pubkey, issuer: &Keypair) {
    let freeze =
        t22new::instruction::freeze_account(&token_program(), account, mint, &issuer.pubkey(), &[])
            .unwrap();
    env.send(&[freeze], &[issuer]).expect("freeze failed");
}

pub fn open_and_kyc(env: &mut Env, mint: &Pubkey, owner: &Pubkey, issuer: &Keypair) -> Pubkey {
    let account = create_ata(env, mint, owner);
    env.send(&[thaw_ix(&account, mint, &issuer.pubkey())], &[issuer])
        .expect("thaw failed");
    account
}

pub fn mint_to_ix(mint: &Pubkey, account: &Pubkey, issuer: &Pubkey, amount: u64) -> Instruction {
    t22new::instruction::mint_to_checked(
        &token_program(),
        mint,
        account,
        issuer,
        &[],
        amount,
        DECIMALS,
    )
    .unwrap()
}

pub fn mint_to(env: &mut Env, mint: &Pubkey, account: &Pubkey, issuer: &Keypair, amount: u64) {
    env.send(
        &[mint_to_ix(mint, account, &issuer.pubkey(), amount)],
        &[issuer],
    )
    .expect("mint_to failed");
}

pub fn transfer_ix(
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
) -> Instruction {
    ix(
        t22_accounts::TransferWithFee {
            source: *source,
            mint: *mint,
            destination: *destination,
            authority: *authority,
            token_program: token_program(),
        },
        t22::instruction::TransferWithFee { amount },
    )
}

pub fn seize_ix(
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    delegate: &Pubkey,
    amount: u64,
) -> Instruction {
    ix(
        t22_accounts::Seize {
            source: *source,
            mint: *mint,
            destination: *destination,
            permanent_delegate: *delegate,
            token_program: token_program(),
        },
        t22::instruction::Seize { amount },
    )
}

pub fn token_account(data: &[u8]) -> StateWithExtensions<'_, TokenAccountState> {
    StateWithExtensions::<TokenAccountState>::unpack(data).unwrap()
}

pub fn mint_state(data: &[u8]) -> StateWithExtensions<'_, MintState> {
    StateWithExtensions::<MintState>::unpack(data).unwrap()
}

pub fn balance(env: &Env, account: &Pubkey) -> u64 {
    token_account(&env.data(account)).base.amount
}

pub fn state(env: &Env, account: &Pubkey) -> AccountState {
    token_account(&env.data(account)).base.state
}

pub fn withheld(env: &Env, account: &Pubkey) -> u64 {
    let data = env.data(account);
    u64::from(
        token_account(&data)
            .get_extension::<TransferFeeAmount>()
            .unwrap()
            .withheld_amount,
    )
}

pub fn supply(env: &Env, mint: &Pubkey) -> u64 {
    mint_state(&env.data(mint)).base.supply
}

pub fn mint_withheld(env: &Env, mint: &Pubkey) -> u64 {
    let data = env.data(mint);
    u64::from(
        mint_state(&data)
            .get_extension::<TransferFeeConfig>()
            .unwrap()
            .withheld_amount,
    )
}

/// Every token the mint has issued is somewhere: a spendable balance, a fee
/// parked on an account, or a fee harvested back into the mint.
pub fn assert_public_supply_conserved(env: &Env, mint: &Pubkey, accounts: &[Pubkey]) {
    let held: u64 = accounts
        .iter()
        .map(|a| balance(env, a) + withheld(env, a))
        .sum();
    assert_eq!(
        held + mint_withheld(env, mint),
        supply(env, mint),
        "supply is not fully accounted for"
    );
}
