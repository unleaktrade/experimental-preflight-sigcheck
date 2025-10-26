import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { ExperimentalPreflightSigcheck } from "../target/types/experimental_preflight_sigcheck";

describe("experimental-preflight-sigcheck", () => {
  // Configure the client to use the local cluster.
  anchor.setProvider(anchor.AnchorProvider.env());

  const program = anchor.workspace.experimentalPreflightSigcheck as Program<ExperimentalPreflightSigcheck>;

  it("Is initialized!", async () => {
    // Add your test here.
    const tx = await program.methods.initialize().rpc();
    console.log("Your transaction signature", tx);
  });
});
