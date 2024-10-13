import CryptoJS from "crypto-js";
import EC from "elliptic";
import { accessEccPrivate, accessEccPublic } from "./kms";

// Encrypt content using AES
export function encryptContent(content: Uint8Array, key: string): string {
  const magicString = "MAGICSTRING"; // This string will be used to validate the decryption
  const magicStringBytes = new TextEncoder().encode(magicString);
  const combinedContent = new Uint8Array(
    magicStringBytes.length + content.length
  );
  combinedContent.set(magicStringBytes);
  combinedContent.set(content, magicStringBytes.length);

  // Convert combined content to WordArray (needed for AES encryption)
  const wordArray = CryptoJS.lib.WordArray.create(combinedContent);

  // Encrypt the wordArray using AES
  const encrypted = CryptoJS.AES.encrypt(wordArray, key);
  return encrypted.toString(); // Return encrypted content as string
}

// Decrypt content using AES
export function decryptContent(
  encryptedContent: string,
  key: string
): Uint8Array {
  // Decrypt the encrypted content using AES
  const decrypted = CryptoJS.AES.decrypt(encryptedContent, key);

  // Convert decrypted data into a WordArray
  const wordArray = decrypted.toString(CryptoJS.enc.Base64);
  const bytes = CryptoJS.enc.Base64.parse(wordArray).words;

  // Convert WordArray back into Uint8Array
  const decryptedBytes = new Uint8Array(bytes.length * 4).map(
    (_, i) => (bytes[i >>> 2] >>> ((3 - (i % 4)) * 8)) & 0xff
  );

  // Define the magic string and its byte representation
  const magicString = "MAGICSTRING";
  const magicStringBytes = new TextEncoder().encode(magicString);

  // Extract the magic string from the decrypted content
  const extractedMagicString = decryptedBytes.subarray(
    0,
    magicStringBytes.length
  );

  // Validate the magic string
  if (
    !magicStringBytes.every((val, index) => val === extractedMagicString[index])
  ) {
    throw new Error("Decryption failed: Magic string mismatch.");
  }

  // Return the actual content without the magic string
  return decryptedBytes.subarray(magicStringBytes.length);
}

// Generate AES key (256-bit)
export function generateKey(): string {
  return CryptoJS.lib.WordArray.random(32).toString(CryptoJS.enc.Hex);
}

const ec = new EC.ec("secp256k1");

// Encrypt AES key using ECC and include an HMAC for validation
export const encryptAESKeyWithECC = async (aesKey: string) => {
  const publicKeyHex = await accessEccPublic();

  // Generate a random private key for ephemeral key pair
  const ephemeralKeyPair = ec.genKeyPair();

  // Derive shared secret using the recipient's public key
  const recipientPublicKey = ec.keyFromPublic(publicKeyHex, "hex");
  const sharedSecret = ephemeralKeyPair.derive(recipientPublicKey.getPublic());

  // Hash the shared secret using SHA-256
  const sharedSecretHash = CryptoJS.SHA256(sharedSecret.toString(16));

  // Generate HMAC using the shared secret and the AES key
  const hmac = CryptoJS.HmacSHA256(aesKey, sharedSecretHash.toString());

  // Combine AES key and HMAC
  const aesKeyWithHMAC = aesKey + hmac.toString(CryptoJS.enc.Hex);

  // Encrypt the AES key (with HMAC) using the shared secret hash
  const aesKeyWordArray = CryptoJS.enc.Hex.parse(aesKeyWithHMAC);
  const encryptedAESKey = CryptoJS.AES.encrypt(
    aesKeyWordArray,
    sharedSecretHash.toString()
  );

  // Return the encrypted AES key and the ephemeral public key
  return {
    encryptedAESKey: encryptedAESKey.toString(), // Base64 encoded
    ephemeralPublicKey: ephemeralKeyPair.getPublic("hex"), // Ephemeral public key in hex
  };
};

// Decrypt AES key using ECC and validate the HMAC
export const decryptAESKeyWithECC = async (
  encryptedAESKey: string,
  ephemeralPublicKeyHex: string
) => {
  const privateKeyHex = await accessEccPrivate();

  // Derive shared secret using recipient's private key and the sender's ephemeral public key
  const recipientPrivateKey = ec.keyFromPrivate(privateKeyHex, "hex");
  const ephemeralPublicKey = ec.keyFromPublic(ephemeralPublicKeyHex, "hex");
  const sharedSecret = recipientPrivateKey.derive(
    ephemeralPublicKey.getPublic()
  );

  // Hash the shared secret using SHA-256
  const sharedSecretHash = CryptoJS.SHA256(sharedSecret.toString(16));

  // Decrypt the AES key using the shared secret hash
  const decryptedAESKeyWordArray = CryptoJS.AES.decrypt(
    encryptedAESKey,
    sharedSecretHash.toString()
  );

  // Convert decrypted WordArray back into hex string (the AES key + HMAC)
  const aesKeyWithHMAC = decryptedAESKeyWordArray.toString(CryptoJS.enc.Hex);

  // Extract the AES key and HMAC
  const aesKey = aesKeyWithHMAC.slice(0, 64); // First 64 characters are the AES key
  const receivedHMAC = aesKeyWithHMAC.slice(64); // Remaining characters are the HMAC

  // Recalculate the HMAC
  const expectedHMAC = CryptoJS.HmacSHA256(
    aesKey,
    sharedSecretHash.toString()
  ).toString(CryptoJS.enc.Hex);

  // Validate the HMAC
  if (receivedHMAC !== expectedHMAC) {
    throw new Error("Decryption failed: Incorrect ECC key or tampered data.");
  }

  return aesKey; // Return the validated AES key
};
