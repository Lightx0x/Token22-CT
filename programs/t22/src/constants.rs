use anchor_spl::token_2022::spl_token_2022::extension::ExtensionType;

/// Instruction args are Borsh-encoded; the pod ciphertext types are not Borsh,
/// so they cross the boundary as raw bytes.
pub const AE_CIPHERTEXT_LEN: usize = 36;
pub const ELGAMAL_CIPHERTEXT_LEN: usize = 64;

pub const REMITTANCE_EXTENSIONS: &[ExtensionType] = &[
    ExtensionType::TransferFeeConfig,
    ExtensionType::MetadataPointer,
    ExtensionType::DefaultAccountState,
    ExtensionType::MintCloseAuthority,
];

/// `ConfidentialTransferFeeConfig` is forced: Token-2022 rejects
/// `TransferFeeConfig + ConfidentialTransferMint` without it.
pub const CONFIDENTIAL_EXTENSIONS: &[ExtensionType] = &[
    ExtensionType::TransferFeeConfig,
    ExtensionType::MetadataPointer,
    ExtensionType::DefaultAccountState,
    ExtensionType::MintCloseAuthority,
    ExtensionType::PermanentDelegate,
    ExtensionType::ConfidentialTransferMint,
    ExtensionType::ConfidentialTransferFeeConfig,
];
