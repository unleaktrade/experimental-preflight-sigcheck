import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { ExperimentalPreflightSigcheck } from "../target/types/experimental_preflight_sigcheck";
import {
  Ed25519Program,
  PublicKey,
  Transaction,
} from "@solana/web3.js";
import { assert } from "chai";

describe("signature-verifier", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.ExperimentalPreflightSigcheck as Program<ExperimentalPreflightSigcheck>;

  it("verifies hardcoded signature for 'mynameisjulien'", async () => {
    // Public key of the signer (base58)
    const signerPubkey = new PublicKey("84SBbUsyV3BJLdytTswHuAgcwdUrZcACCy38EA1DanmS");

    // SHA-256 hash of "mynameisjulien" (32 bytes)
    const messageHash = Buffer.from([163, 46, 34, 239, 22, 106, 138, 90, 17, 46, 155, 195, 172, 175, 129, 105, 59, 139, 103, 180, 202, 157, 67, 153, 176, 17, 124, 92, 176, 221, 235, 117
    ]);

    // Ed25519 signature (64 bytes)
    const signature = Buffer.from([130, 134, 248, 108, 160, 106, 182, 110, 15, 38, 65, 163, 39, 234, 13, 235, 101, 239, 208, 146, 34, 33, 199, 143, 2, 193, 223, 174, 72, 53, 215, 187, 42, 25, 81, 200, 124, 234, 73, 57, 246, 91, 13, 109, 123, 128, 8, 5, 86, 186, 161, 190, 64, 80, 34, 38, 133, 246, 54, 226, 30, 50, 15, 6
    ]);

    if (messageHash.length !== 32) throw new Error("hash must be 32 bytes");
    if (signature.length !== 64) throw new Error("sig must be 64 bytes");
    if (!signerPubkey.equals(new PublicKey("84SBbUsyV3BJLdytTswHuAgcwdUrZcACCy38EA1DanmS")))
      throw new Error("pubkey mismatch vs hardcoded AUTHORIZED_SIGNER");


    // Create Ed25519 verification instruction using the helper
    const ed25519Ix = Ed25519Program.createInstructionWithPublicKey({
      publicKey: signerPubkey.toBytes(),
      message: messageHash,
      signature: signature,
    });

    // Peek at the data to confirm offsets (little‑endian u16 fields)
    const data = ed25519Ix.data;
    const sigOffset = data.readUInt16LE(2);
    const pubkeyOffset = data.readUInt16LE(6);
    const msgOffset = data.readUInt16LE(10);
    const msgSize = data.readUInt16LE(12);
    console.log('OFFSETS:', { sigOffset, pubkeyOffset, msgOffset, msgSize });

    // Create your program's verification instruction
    // Note: Only pass message_hash since pubkey is hardcoded in the program
    const verifyIx = await program.methods
      .verifySignature(Array.from(messageHash))
      .accounts({
        instruction_sysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
      })
      .instruction();

    const tx = new anchor.web3.Transaction();
    // Add ONLY these two instructions, in this exact order:
    tx.add(ed25519Ix);
    tx.add(verifyIx);

    // Send and confirm
    const txSig = await provider.sendAndConfirm(tx, [], { skipPreflight: false });
    console.log("✅ Signature verified successfully!");
    console.log("Transaction signature:", txSig);
    console.log("Explorer:", `https://explorer.solana.com/tx/${txSig}?cluster=devnet`);
  });

  it("rejects invalid signature", async () => {
    const signerPubkey = new PublicKey("84SBbUsyV3BJLdytTswHuAgcwdUrZcACCy38EA1DanmS");

    // Correct hash
    const messageHash = Buffer.from([163, 46, 34, 239, 22, 106, 138, 90, 17, 46, 155, 195, 172, 175, 129, 105, 59, 139, 103, 180, 202, 157, 67, 153, 176, 17, 124, 92, 176, 221, 235, 117]);

    // WRONG signature (tampered)
    const wrongSignature = Buffer.from([131, 134, 248, 108, 160, 106, 182, 110, 15, 38, 65, 163, 39, 234, 13, 235, 101, 239, 208, 146, 34, 33, 199, 143, 2, 193, 223, 174, 72, 53, 215, 187, 42, 25, 81, 200, 124, 234, 73, 57, 246, 91, 13, 109, 123, 128, 8, 5, 86, 186, 161, 190, 64, 80, 34, 38, 133, 246, 54, 226, 30, 50, 15, 6
    ]);

    const ed25519Ix = Ed25519Program.createInstructionWithPublicKey({
      publicKey: signerPubkey.toBytes(),
      message: messageHash,
      signature: wrongSignature,
    });

    const verifyIx = await program.methods
      .verifySignature(Array.from(messageHash))
      .accounts({
        instruction_sysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
      })
      .instruction();

    const tx = new anchor.web3.Transaction();
    // Add ONLY these two instructions, in this exact order:
    tx.add(ed25519Ix);
    tx.add(verifyIx);

    let failed = false;
    try {
      await provider.sendAndConfirm(tx, [], { skipPreflight: false });
    } catch (err) {
      console.log("✅ Correctly rejected invalid signature");
      failed = true;
    }
    assert(failed, "Should have failed with invalid signature!");
  });
});
