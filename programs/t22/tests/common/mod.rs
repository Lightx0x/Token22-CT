#![allow(dead_code)]
// litesvm's error variant carries the full transaction metadata.
#![allow(clippy::result_large_err)]

use {
    anchor_lang::{InstructionData, ToAccountMetas},
    litesvm::{types::TransactionResult, LiteSVM},
    solana_instruction::Instruction,
    solana_keypair::Keypair,
    solana_message::{Message, VersionedMessage},
    solana_pubkey::Pubkey,
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
    t22::accounts as t22_accounts,
    t22new::state::{Account as TokenAccountState, Mint as MintState},
};

pub const DECIMALS: u8 = 6;
pub const FEE_BPS: u16 = 50;
pub const MAX_FEE: u64 = 5_000;

pub const NAME: &str = "Remit USD";
pub const SYMBOL: &str = "rUSD";
pub const URI: &str = "https://example.org/rusd.json";

const SOL: u64 = 1_000_000_000;

pub fn token_program() -> Pubkey {
    t22new::id()
}

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
            .expect("a required signer was not supplied");
        let result = self.svm.send_transaction(tx);
        self.svm.expire_blockhash();
        result
    }

    pub fn call<A: ToAccountMetas, D: InstructionData>(
        &mut self,
        accounts: A,
        data: D,
        extra: &[&Keypair],
    ) -> TransactionResult {
        self.send(
            &[Instruction {
                program_id: t22::ID,
                accounts: accounts.to_account_metas(None),
                data: data.data(),
            }],
            extra,
        )
    }
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

pub fn create_remittance_mint(env: &mut Env) -> Mint {
    let mint = Mint {
        key: Keypair::new(),
        issuer: Keypair::new(),
    };
    env.svm.airdrop(&mint.issuer.pubkey(), 100 * SOL).unwrap();

    let result = env.send(
        &[Instruction {
            program_id: t22::ID,
            accounts: t22_accounts::CreateMint {
                payer: mint.issuer.pubkey(),
                mint: mint.pubkey(),
                token_program: token_program(),
                system_program: solana_system_interface::program::ID,
            }
            .to_account_metas(None),
            data: t22::instruction::CreateRemittanceMint {
                decimals: DECIMALS,
                basis_points: FEE_BPS,
                maximum_fee: MAX_FEE,
                name: NAME.to_string(),
                symbol: SYMBOL.to_string(),
                uri: URI.to_string(),
            }
            .data(),
        }],
        &[&mint.key, &mint.issuer],
    );
    result.expect("remittance mint creation failed");
    mint
}

pub fn create_confidential_mint(
    env: &mut Env,
    withdraw_withheld_elgamal: [u8; 32],
    auditor_elgamal: Option<[u8; 32]>,
) -> Mint {
    let mint = Mint {
        key: Keypair::new(),
        issuer: Keypair::new(),
    };
    env.svm.airdrop(&mint.issuer.pubkey(), 100 * SOL).unwrap();

    let result = env.send(
        &[Instruction {
            program_id: t22::ID,
            accounts: t22_accounts::CreateMint {
                payer: mint.issuer.pubkey(),
                mint: mint.pubkey(),
                token_program: token_program(),
                system_program: solana_system_interface::program::ID,
            }
            .to_account_metas(None),
            data: t22::instruction::CreateConfidentialMint {
                decimals: DECIMALS,
                basis_points: FEE_BPS,
                maximum_fee: MAX_FEE,
                withdraw_withheld_elgamal,
                auditor_elgamal,
                name: NAME.to_string(),
                symbol: SYMBOL.to_string(),
                uri: URI.to_string(),
            }
            .data(),
        }],
        &[&mint.key, &mint.issuer],
    );
    result.expect("confidential mint creation failed");
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

pub fn open_and_kyc(env: &mut Env, mint: &Pubkey, owner: &Pubkey, issuer: &Keypair) -> Pubkey {
    let account = create_ata(env, mint, owner);
    env.call(
        t22_accounts::ThawAfterKyc {
            token_account: account,
            mint: *mint,
            freeze_authority: issuer.pubkey(),
            token_program: token_program(),
        },
        t22::instruction::ThawAfterKyc {},
        &[issuer],
    )
    .expect("thaw failed");
    account
}

pub fn mint_to(env: &mut Env, mint: &Pubkey, account: &Pubkey, issuer: &Keypair, amount: u64) {
    let instruction = t22new::instruction::mint_to_checked(
        &token_program(),
        mint,
        account,
        &issuer.pubkey(),
        &[],
        amount,
        DECIMALS,
    )
    .unwrap();
    env.send(&[instruction], &[issuer]).expect("mint_to failed");
}

pub fn balance(env: &Env, account: &Pubkey) -> u64 {
    use t22new::extension::StateWithExtensions;
    StateWithExtensions::<TokenAccountState>::unpack(&env.data(account))
        .unwrap()
        .base
        .amount
}

pub fn mint_state(data: &[u8]) -> t22new::extension::StateWithExtensions<'_, MintState> {
    t22new::extension::StateWithExtensions::<MintState>::unpack(data).unwrap()
}
