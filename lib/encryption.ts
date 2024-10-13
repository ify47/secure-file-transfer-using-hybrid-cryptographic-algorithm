import CryptoJS from 'crypto-js';

export function encryptContent(content: Uint8Array, key: string): string {
    const magicString = "MAGICSTRING";  // This string will be used to validate the decryption
    const magicStringBytes = new TextEncoder().encode(magicString);
    const combinedContent = new Uint8Array(magicStringBytes.length + content.length);
    combinedContent.set(magicStringBytes);
    combinedContent.set(content, magicStringBytes.length);

    const wordArray = CryptoJS.lib.WordArray.create(combinedContent);
    const encrypted = CryptoJS.Blowfish.encrypt(wordArray, key);
    return encrypted.toString();
}

// ...


export function decryptContent(encryptedContent: string, key: string): Uint8Array {
    const decrypted = CryptoJS.Blowfish.decrypt(encryptedContent, key);
    const words = decrypted.toString(CryptoJS.enc.Base64);
    const bytes = CryptoJS.enc.Base64.parse(words).words;
    return new Uint8Array(bytes.length * 4).map((_, i) => (bytes[i >>> 2] >>> ((3 - (i % 4)) * 8)) & 0xff);
}

export function generateKey(): string {
    return Math.random().toString(36).substring(2, 10);
}

