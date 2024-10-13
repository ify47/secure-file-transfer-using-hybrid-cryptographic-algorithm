"use server";
import { Storage } from "@google-cloud/storage";
import {
  decodeShortKey,
  decryptContent,
  decryptWithPrivateKey,
  encryptContent,
  encryptWithPublicKey,
  generateKey,
  generateShortKey,
} from "./encryptionAes";
import { PassThrough } from "stream";
import { UploadFileResult } from "./fileOperations-AesEcc";
import { error } from "console";

const credentials = JSON.parse(
  Buffer.from(
    process.env.KEYFILENAME ? process.env.KEYFILENAME : "",
    "base64"
  ).toString()
);

const bucketName = process.env.BUCKET_NAME;
const FILE_SIZE_LIMIT = 25 * 1024 * 1024; // 25 MB

export const UploadFile = async (
  form: FormData,
  userEmail: string,
  senderName: string
) => {
  try {
    const clientFile = form.get("file") as File;
    if (!clientFile) return { error: "No file provided" };
    if (clientFile.size < 1) return { error: "File is empty" };

    // Check if file exceeds the size limit of 25MB
    if (clientFile.size > FILE_SIZE_LIMIT) {
      return {
        success: false,
        error: "File exceeds the maximum allowed size of 25MB",
      };
    }

    const storage = new Storage({
      projectId: credentials.projectId,
      credentials: {
        client_email: credentials.client_email,
        private_key: credentials.private_key,
      },
    });
    const bucket = storage.bucket(bucketName as string);

    // Generate an AES encryption key for the file content
    const aesKey = generateKey();

    // Encrypt the content on the server-side
    const buffer = await clientFile.arrayBuffer();
    const uint8Array = new Uint8Array(buffer);
    const encryptedContent = encryptContent(uint8Array, aesKey); // Encrypt content

    // Create a unique encrypted file name for storage
    const encryptedFileName = `${clientFile.name}.enc`;

    // Get the Google Cloud Storage file object
    const bucketFile = bucket.file(encryptedFileName);

    // Create signed URL for direct upload to GCS
    const [signedUrl] = await bucketFile.getSignedUrl({
      version: "v4",
      action: "write",
      expires: Date.now() + 15 * 60 * 1000, // 15 minutes
      contentType: "application/octet-stream", // Adjust if necessary
    });

    // Return the signed URL and the encrypted content to the client
    return {
      success: true,
      key: aesKey,
      signedUrl: signedUrl,
      encryptedContent: encryptedContent,
    };
  } catch (error) {
    if (error instanceof Error) {
      console.error(error.message);
      return { success: false, error: error.message };
    } else {
      console.error("An unknown error occurred");
      return { success: false, error: "Unknown error" };
    }
  }
};

export const FetchFiles = async (userEmail: string) => {
  try {
    const storage = new Storage({
      projectId: credentials.projectId,
      credentials: {
        client_email: credentials.client_email,
        private_key: credentials.private_key,
      },
    });
    const bucket = storage.bucket(bucketName as string);
    const [files] = await bucket.getFiles();

    // Fetch the original names from the metadata and filter by the user's email
    const fileList = await Promise.all(
      files.map(async (file) => {
        const [metadata] = await file.getMetadata();

        // Check if the file belongs to the user by comparing the userEmail stored in metadata
        if (metadata.metadata?.userEmail === userEmail) {
          return {
            originalName:
              (metadata.metadata?.originalName as string) ||
              file.name.replace(".enc", ""),
            encryptedName: file.name,
            senderName: (metadata.metadata?.senderName as string) || "Unknown", // Get the sender's name
            fileType: (metadata.metadata?.fileType as string) || "Unknown", // Get file MIME type
            fileSize: (metadata.metadata?.fileSize as number) || 0, // Get file size in bytes
            uploadTime: (metadata.metadata?.uploadTime as string) || "Unknown", // Get upload time
          };
        }
        return null;
      })
    );

    // Filter out any null results (files not meant for the user)
    const userFiles = fileList.filter((file) => file !== null);

    return { success: true, files: userFiles };
  } catch (error) {
    if (error instanceof Error) {
      return { success: false, error: error.message };
    } else {
      console.error("An unknown error occurred");
      return { success: false, error: "Unknown error" };
    }
  }
};

export const DownloadFile = async (
  encryptedFileName: string,
  firstPartKey: string
) => {
  try {
    const storage = new Storage({
      projectId: credentials.projectId,
      credentials: {
        client_email: credentials.client_email,
        private_key: credentials.private_key,
      },
    });
    const bucket = storage.bucket(bucketName as string);
    const file = bucket.file(encryptedFileName);
    const exists = await file.exists();

    if (!exists[0]) {
      return { error: "File does not exist" };
    }

    const [encryptedContent] = await file.download();

    // Retrieve the encrypted remaining part of the RSA-encrypted AES key from metadata
    const [metadata] = await file.getMetadata();
    const encrypted = metadata.metadata?.encrypted as string;

    if (!encrypted) {
      return { error: "Missing encryption metadata" };
    }

    // Decrypt the remaining part using AES-256-CBC
    const remainingPartKey = await decodeShortKey(encrypted);

    // Combine the two parts to reconstruct the full RSA-encrypted AES key
    const fullEncryptedKey = firstPartKey + remainingPartKey;

    // Decrypt the RSA-encrypted AES key using the RSA private key
    let aesKey;
    try {
      aesKey = await decryptWithPrivateKey(fullEncryptedKey);
    } catch (error) {
      return { error: "Invalid decryption key" };
    }

    // Decrypt the file content using the AES key
    let decryptedContent;
    try {
      decryptedContent = decryptContent(
        encryptedContent.toString("utf8"),
        aesKey as string
      );
    } catch (error) {
      return { error: "Failed to decrypt file" };
    }

    // Retrieve the original file name from metadata
    const originalFileName =
      metadata.metadata?.originalName || encryptedFileName.replace(".enc", "");

    // Convert the Uint8Array to Base64 string
    const base64Content = Buffer.from(decryptedContent).toString("base64");

    return { content: base64Content, originalFileName };
  } catch (error) {
    if (error instanceof Error) {
      return {
        error:
          "Unable to retrieve or decrypt file. Please check the key and try again.",
      };
    } else {
      return { success: false, error: "Unknown error" };
    }
  }
};
