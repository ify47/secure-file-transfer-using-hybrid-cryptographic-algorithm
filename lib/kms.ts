"use server";
import { KeyManagementServiceClient } from "@google-cloud/kms";
import { SecretManagerServiceClient } from "@google-cloud/secret-manager";

const credentials = JSON.parse(
  Buffer.from(
    process.env.KEYFILENAME ? process.env.KEYFILENAME : "",
    "base64"
  ).toString()
);

const kmsClient = new KeyManagementServiceClient({
  credentials: {
    client_email: credentials.client_email,
    private_key: credentials.private_key,
  },
});

const secretManagerClient = new SecretManagerServiceClient({
  credentials: {
    client_email: credentials.client_email,
    private_key: credentials.private_key,
  },
});

export async function getPublicKey() {
  const keyName =
    "projects/school-projecyt/locations/us/keyRings/rsaPublic/cryptoKeys/Rsa/cryptoKeyVersions/1";

  const [publicKey] = await kmsClient.getPublicKey({
    name: keyName,
  });

  console.log(`public: ${publicKey.pem}`);
  return publicKey.pem;
}

export async function decryptWithKMS(encryptedData: string) {
  const keyName =
    "projects/school-projecyt/locations/us/keyRings/rsaPublic/cryptoKeys/Rsa/cryptoKeyVersions/1";
  const ciphertextBuffer = Buffer.from(encryptedData, "base64");

  const [result] = await kmsClient.asymmetricDecrypt({
    name: keyName,
    ciphertext: ciphertextBuffer,
  });

  const plaintext = result.plaintext?.toString();
  console.log(`Decrypted data: ${plaintext}`);
  return plaintext;
}

// Function to perform AES-256-GCM encryption using an AES key from KMS
export async function getEncryptedAesKey(rsaEncryptedKey: string) {
  const keyName =
    "projects/school-projecyt/locations/us/keyRings/rsaPublic/cryptoKeys/aeskey1";

  // Perform encryption
  const [result] = await kmsClient.encrypt({
    name: keyName,
    plaintext: Buffer.from(rsaEncryptedKey),
  });

  // Directly return the base64 string of the ciphertext
  return Buffer.from(result.ciphertext as Buffer).toString("base64");
}
export async function getDecryptedAesKey(rsaEncryptedKey: string) {
  const keyName =
    "projects/school-projecyt/locations/us/keyRings/rsaPublic/cryptoKeys/aeskey1";

  // Convert the base64 encoded ciphertext back to buffer
  const ciphertextBuffer = Buffer.from(rsaEncryptedKey, "base64");

  // Perform decryption
  const [result] = await kmsClient.decrypt({
    name: keyName,
    ciphertext: ciphertextBuffer,
  });

  // Return the decrypted result as a utf-8 string
  const decryptedAes = Buffer.from(result.plaintext as string).toString("utf8");
  return decryptedAes;
}

export async function accessEccPublic() {
  const [version] = await secretManagerClient.accessSecretVersion({
    name: "projects/school-projecyt/secrets/ecck/versions/1",
  });

  const payload = Buffer.from(version.payload?.data as Buffer).toString("utf8");
  return payload;
}
export async function accessEccPrivate() {
  const [version] = await secretManagerClient.accessSecretVersion({
    name: "projects/school-projecyt/secrets/ecck/versions/2",
  });

  const payload = Buffer.from(version.payload?.data as Buffer).toString("utf8");
  console.log(payload);

  return payload;
}
