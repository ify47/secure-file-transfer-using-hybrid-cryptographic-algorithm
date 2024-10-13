import CryptoJS from "crypto-js";
import crypto from "crypto";
import {
  decryptWithKMS,
  getDecryptedAesKey,
  getEncryptedAesKey,
  getPublicKey,
} from "./kms";

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

// Encrypt data with the RSA public key
export async function encryptWithPublicKey(data: string) {
  try {
    const buffer = Buffer.from(data);
    const publicKey = (await getPublicKey()) as string;
    const encrypted = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, // Use OAEP Padding
        oaepHash: "sha256", // Use SHA-256 for OAEP hash
      },
      buffer
    );
    return encrypted.toString("base64");
  } catch (error) {
    console.error("RSA Encryption Error:", error);
    throw new Error("Failed to encrypt data with RSA key.");
  }
}

// Decrypt data with the RSA private key
export async function decryptWithPrivateKey(encryptedData: string) {
  try {
    const decrypted = await decryptWithKMS(encryptedData);
    return decrypted;
  } catch (error) {
    console.error("RSA Decryption Error:", error);
    throw new Error("Failed to decrypt data with RSA key.");
  }
}

export async function generateShortKey(rsaEncryptedKey: string) {
  const encrypted = await getEncryptedAesKey(rsaEncryptedKey);
  return encrypted;
}

export async function decodeShortKey(encryptedKey: string) {
  const decrypted = await getDecryptedAesKey(encryptedKey);

  return decrypted;
}
