use anchor_lang::prelude::*;

declare_id!("9regB6ad87mGXsskBEhkP9eXNPR1CGMmkFaGynLr3t8S");

#[program]
pub mod experimental_preflight_sigcheck {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
