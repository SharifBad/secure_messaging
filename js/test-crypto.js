import {
  generateKeyPair,
  exportPublicKey,
  importPublicKey,
  deriveSharedKey,
  encryptMessage,
  decryptMessage,
} from "./crypto.js";

async function runTest() {
  console.log("Generating Alice and Bob keypairs...");
  const alice = await generateKeyPair();
  const bob = await generateKeyPair();

  // Simulate exchanging public keys over the network
  const alicePubB64 = await exportPublicKey(alice.publicKey);
  const bobPubB64 = await exportPublicKey(bob.publicKey);
  console.log("Alice's public key (base64):", alicePubB64);
  console.log("Bob's public key (base64):  ", bobPubB64);

  // Each side derives the shared key independently
  const aliceShared = await deriveSharedKey(
    alice.privateKey,
    await importPublicKey(bobPubB64),
  );
  const bobShared = await deriveSharedKey(
    bob.privateKey,
    await importPublicKey(alicePubB64),
  );

  // Alice encrypts, Bob decrypts
  const message = "Hello Bob — this is secret 🔐";
  const encrypted = await encryptMessage(aliceShared, message);
  console.log("Encrypted payload:", encrypted);

  const decrypted = await decryptMessage(bobShared, encrypted);
  console.log("Bob decrypted:", decrypted);

  if (decrypted === message) console.log("✅ PASS — E2EE round-trip works");
  else console.log("❌ FAIL — decryption did not match");
}

runTest().catch(console.error);
