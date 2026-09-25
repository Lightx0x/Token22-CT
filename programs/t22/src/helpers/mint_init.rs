use {
    anchor_lang::prelude::*,
    anchor_spl::{
        token_2022::{
            initialize_mint2,
            spl_token_2022::{extension::ExtensionType, state::AccountState},
            InitializeMint2,
        },
        token_2022_extensions::{
            default_account_state_initialize, metadata_pointer_initialize,
            mint_close_authority_initialize, token_metadata_initialize, transfer_fee_initialize,
            DefaultAccountStateInitialize, MetadataPointerInitialize, MintCloseAuthorityInitialize,
            TokenMetadataInitialize, TransferFeeInitialize,
        },
    },
    spl_token_metadata_interface::state::TokenMetadata,
    spl_type_length_value::variable_len_pack::VariableLenPack,
};

pub struct MintParts<'info> {
    pub payer: AccountInfo<'info>,
    pub mint: AccountInfo<'info>,
    pub authority: AccountInfo<'info>,
    pub token_program: AccountInfo<'info>,
    pub system_program: AccountInfo<'info>,
}

/// Allocates at the full extended length, then runs the extension
/// initializers. Metadata is variable length, so it is excluded from `space`
/// and its rent is funded up front for the realloc in [`write_metadata`].
pub fn init_mint<'info>(
    a: &MintParts<'info>,
    space: usize,
    name: &str,
    symbol: &str,
    uri: &str,
    extensions: impl FnOnce(&MintParts<'info>) -> Result<()>,
) -> Result<()> {
    // Token-2022 stores a variable-length extension behind its own u16 type and
    // u16 length. `TokenMetadata::tlv_size_of` sizes for the generic TLV header
    // instead, which is 8 bytes larger and over-funds the mint.
    let metadata_space = TokenMetadata {
        name: name.to_string(),
        symbol: symbol.to_string(),
        uri: uri.to_string(),
        ..Default::default()
    }
    .get_packed_len()?
        + std::mem::size_of::<ExtensionType>()
        + std::mem::size_of::<u16>();
    let lamports = Rent::get()?.minimum_balance(space + metadata_space);

    anchor_lang::system_program::create_account(
        CpiContext::new(
            a.system_program.key(),
            anchor_lang::system_program::CreateAccount {
                from: a.payer.clone(),
                to: a.mint.clone(),
            },
        ),
        lamports,
        space as u64,
        a.token_program.key,
    )?;

    extensions(a)
}

pub fn init_remittance_extensions(
    a: &MintParts<'_>,
    basis_points: u16,
    maximum_fee: u64,
) -> Result<()> {
    transfer_fee_initialize(
        CpiContext::new(
            a.token_program.key(),
            TransferFeeInitialize {
                token_program_id: a.token_program.clone(),
                mint: a.mint.clone(),
            },
        ),
        Some(&a.authority.key()),
        Some(&a.authority.key()),
        basis_points,
        maximum_fee,
    )?;

    // Pointed at the mint itself, so the metadata needs no second account.
    metadata_pointer_initialize(
        CpiContext::new(
            a.token_program.key(),
            MetadataPointerInitialize {
                token_program_id: a.token_program.clone(),
                mint: a.mint.clone(),
            },
        ),
        Some(a.authority.key()),
        Some(a.mint.key()),
    )?;

    // The KYC gate: new accounts open frozen.
    default_account_state_initialize(
        CpiContext::new(
            a.token_program.key(),
            DefaultAccountStateInitialize {
                token_program_id: a.token_program.clone(),
                mint: a.mint.clone(),
            },
        ),
        &AccountState::Frozen,
    )?;

    mint_close_authority_initialize(
        CpiContext::new(
            a.token_program.key(),
            MintCloseAuthorityInitialize {
                token_program_id: a.token_program.clone(),
                mint: a.mint.clone(),
            },
        ),
        Some(&a.authority.key()),
    )
}

/// Seals the extension set. The freeze authority is not optional:
/// `DefaultAccountState` is administered by it.
pub fn seal_mint(a: &MintParts<'_>, decimals: u8) -> Result<()> {
    initialize_mint2(
        CpiContext::new(
            a.token_program.key(),
            InitializeMint2 {
                mint: a.mint.clone(),
            },
        ),
        decimals,
        &a.authority.key(),
        Some(&a.authority.key()),
    )
}

/// Not an extension initializer: it runs after `InitializeMint2` and needs a
/// mint-authority signature.
pub fn write_metadata(a: &MintParts<'_>, name: String, symbol: String, uri: String) -> Result<()> {
    token_metadata_initialize(
        CpiContext::new(
            a.token_program.key(),
            TokenMetadataInitialize {
                program_id: a.token_program.clone(),
                metadata: a.mint.clone(),
                update_authority: a.authority.clone(),
                mint_authority: a.authority.clone(),
                mint: a.mint.clone(),
            },
        ),
        name,
        symbol,
        uri,
    )
}
