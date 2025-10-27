use anchor_lang::prelude::*;
use anchor_lang::solana_program::pubkey::Pubkey;
use anchor_lang::solana_program::sysvar::instructions::{
    load_current_index_checked, load_instruction_at_checked, ID as INSTRUCTIONS_ID,
};

declare_id!("9regB6ad87mGXsskBEhkP9eXNPR1CGMmkFaGynLr3t8S");

// Hardcoded authorized signer (your base58 key)
const AUTHORIZED_SIGNER: Pubkey = pubkey!("84SBbUsyV3BJLdytTswHuAgcwdUrZcACCy38EA1DanmS");

#[program]
pub mod experimental_preflight_sigcheck {
    use super::*;

    pub fn verify_signature(ctx: Context<VerifySignature>, message_hash: [u8; 32]) -> Result<()> {
        // Safely get prior instruction
        let current_index = load_current_index_checked(&ctx.accounts.instruction_sysvar)?;
        let prev_index = current_index
            .checked_sub(1)
            .ok_or(ErrorCode::NoEd25519Instruction)?;
        let ed25519_ix =
            load_instruction_at_checked(prev_index as usize, &ctx.accounts.instruction_sysvar)?;
        msg!("Prev ix program_id: {}", ed25519_ix.program_id);

        // Must be native Ed25519
        let expected = Pubkey::from_str_const("Ed25519SigVerify111111111111111111111111111");
        require_keys_eq!(
            ed25519_ix.program_id,
            expected,
            ErrorCode::InvalidEd25519Program
        );

        // Parse Ed25519 instruction
        let data = &ed25519_ix.data;
        require!(data.len() >= 112, ErrorCode::InvalidEd25519Data);
        require!(data[0] == 1, ErrorCode::InvalidSignatureCount);

        let sig_offset = u16::from_le_bytes([data[2], data[3]]) as usize;
        let sig_ix_index = u16::from_le_bytes([data[4], data[5]]);
        let pubkey_offset = u16::from_le_bytes([data[6], data[7]]) as usize;
        let pubkey_ix_index = u16::from_le_bytes([data[8], data[9]]);
        let msg_offset = u16::from_le_bytes([data[10], data[11]]) as usize;
        let msg_size = u16::from_le_bytes([data[12], data[13]]) as usize;
        let msg_ix_index = u16::from_le_bytes([data[14], data[15]]);

        msg!("sig_ix_index={}", sig_ix_index);
        msg!("pubkey_ix_index={}", pubkey_ix_index);
        msg!("msg_ix_index={}", msg_ix_index);
        msg!("sig_offset={}", sig_offset);
        msg!("pubkey_offset={}", pubkey_offset);
        msg!("msg_offset={}", msg_offset);
        msg!("msg_size={}", msg_size);

        // Enforce same-instruction sourcing (prevents cross-instruction substitution)
        require!(sig_ix_index == 0xFFFF, ErrorCode::InvalidOffset);
        require!(pubkey_ix_index == 0xFFFF, ErrorCode::InvalidOffset);
        require!(msg_ix_index == 0xFFFF, ErrorCode::InvalidOffset);

        // Enforce canonical single-sig layout used by web3 helper
        require!(sig_offset == 48, ErrorCode::InvalidOffset);
        require!(pubkey_offset == 16, ErrorCode::InvalidOffset);
        require!(msg_offset == 112, ErrorCode::InvalidOffset);
        require!(msg_size == 32, ErrorCode::InvalidMessageSize);

        // Bounds checks
        require!(data.len() >= sig_offset + 64, ErrorCode::InvalidEd25519Data);
        require!(
            data.len() >= pubkey_offset + 32,
            ErrorCode::InvalidEd25519Data
        );
        require!(data.len() >= msg_offset + 32, ErrorCode::InvalidEd25519Data);

        // Authorized signer check
        let pubkey_bytes = &data[pubkey_offset..pubkey_offset + 32];
        require!(
            pubkey_bytes == AUTHORIZED_SIGNER.as_ref(),
            ErrorCode::UnauthorizedSigner
        );

        // Bind exact 32-byte message
        let verified_hash_slice = &data[msg_offset..msg_offset + 32];
        require!(
            verified_hash_slice == &message_hash,
            ErrorCode::MessageHashMismatch
        );

        Ok(())
    }
}

#[derive(Accounts)]
pub struct VerifySignature<'info> {
    /// CHECK: Address asserted to be the instructions sysvar
    #[account(address = INSTRUCTIONS_ID)]
    pub instruction_sysvar: AccountInfo<'info>,
    // Optional: satisfy linters/CI that require a signer, not used for auth
    // pub payer: Signer<'info>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("No Ed25519 instruction found")]
    NoEd25519Instruction,
    #[msg("Invalid Ed25519 program ID")]
    InvalidEd25519Program,
    #[msg("Invalid Ed25519 instruction data")]
    InvalidEd25519Data,
    #[msg("Invalid signature count")]
    InvalidSignatureCount,
    #[msg("Invalid offset - security check failed")]
    InvalidOffset,
    #[msg("Invalid message size")]
    InvalidMessageSize,
    #[msg("Unauthorized signer - not the expected public key")]
    UnauthorizedSigner,
    #[msg("Message hash mismatch")]
    MessageHashMismatch,
}
