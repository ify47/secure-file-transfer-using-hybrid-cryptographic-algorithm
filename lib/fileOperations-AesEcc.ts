"use server";
import { Storage } from "@google-cloud/storage";
import {
  decryptAESKeyWithECC,
  decryptContent,
  encryptAESKeyWithECC,
  encryptContent,
  generateKey,
} from "./encryptionAesECC";
import { PassThrough } from "stream";
import { error } from "console";

export interface UploadFileResult {
  success: boolean;
  key?: string;
  error?: string;
}

const credentials = JSON.parse(
  Buffer.from(
    process.env.KEYFILENAME ? process.env.KEYFILENAME : "",
    "base64"
  ).toString()
);

const projectId = process.env.PROJECT_ID;
const keyFilename = process.env.KEYFILENAME;
const bucketName = process.env.BUCKET_NAME_ECC;

const FILE_SIZE_LIMIT = 25 * 1024 * 1024; // 25MB

export const UploadFile = async (
  form: FormData,
  userEmail: string,
  senderName: string
): Promise<UploadFileResult> => {
  try {
    const file = form.get("file") as File;
    if (!file) throw new Error("No file provided");
    if (file.size < 1) throw new Error("File is empty");

    // Check if file exceeds the size limit of 25MB
    if (file.size > FILE_SIZE_LIMIT) {
      return {
        success: false,
        error: "File exceeds the maximum allowed size of 25MB",
      };
    }

    // Convert the file into a buffer
    const buffer = await file.arrayBuffer();
    const uint8Array = new Uint8Array(buffer);

    // Generate an AES encryption key for the file content
    const aesKey = generateKey();
    const encryptedContent = encryptContent(uint8Array, aesKey);
    console.log("AES key for encryption:", aesKey);

    // Encrypt the AES key using ECC
    const { encryptedAESKey, ephemeralPublicKey } = await encryptAESKeyWithECC(
      aesKey
    );

    const storage = new Storage({
      projectId: credentials.projectId,
      credentials: {
        client_email: credentials.client_email,
        private_key: credentials.private_key,
      },
    });
    const bucket = storage.bucket(bucketName as string);

    // Create a PassThrough stream for streaming encrypted content
    const stream = new PassThrough();

    // Define the initial file name
    let baseFileName = `${file.name}.enc`;
    let fileNumber = 0;
    let encryptedFileName = baseFileName;

    // Loop to check if a file with the same name exists
    let fileExists = await bucket.file(encryptedFileName).exists();
    while (fileExists[0]) {
      fileNumber += 1;
      encryptedFileName = `${file.name}(${fileNumber}).enc`;
      fileExists = await bucket.file(encryptedFileName).exists();
    }

    // Pipe the stream to Google Cloud Storage
    const writeStream = bucket.file(encryptedFileName).createWriteStream({
      resumable: false, // Non-resumable for simplicity
      metadata: {
        contentType: file.type, // Set the file MIME type
        metadata: {
          originalName: file.name,
          userEmail: userEmail,
          senderName: senderName,
          fileType: file.type, // File type
          fileSize: file.size, // File size in bytes
          uploadTime: new Date().toISOString(),
          ephemeral: ephemeralPublicKey, // The ephemeral public key for ECC decryption
        },
      },
    });

    // Send encrypted content to the stream
    stream.write(Buffer.from(encryptedContent, "utf8"));
    stream.end();

    // Pipe the pass-through stream to GCS writeStream
    stream.pipe(writeStream);

    // Return the first 16 digits of the ECC-encrypted AES key to the user
    return new Promise((resolve, reject) => {
      writeStream.on("finish", () => {
        resolve({ success: true, key: encryptedAESKey });
      });
      writeStream.on("error", (error) => {
        reject({ success: false, error: error.message });
      });
    });
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
      console.error(error.message);
      return { success: false, error: error.message };
    } else {
      console.error("An unknown error occurred");
      return { success: false, error: "Unknown error" };
    }
  }
};

export const DownloadFile = async (
  encryptedFileName: string,
  eccKey: string
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
      throw new Error("File does not exist");
    }

    const [encryptedContent] = await file.download();

    // Retrieve the encrypted remaining part of the RSA-encrypted AES key from metadata
    const [metadata] = await file.getMetadata();
    const ephemeralPublicKey = metadata.metadata?.ephemeral as string;

    // Decrypt the RSA-encrypted AES key using the RSA private key
    let aesKey;
    try {
      aesKey = await decryptAESKeyWithECC(eccKey, ephemeralPublicKey);
    } catch (error) {
      throw new Error("Invalid decryption key");
    }

    console.log("aesdec", aesKey);

    // Decrypt the file content using the AES key
    let decryptedContent;
    try {
      decryptedContent = decryptContent(
        encryptedContent.toString("utf8"),
        aesKey
      );
    } catch (error) {
      throw new Error("Failed to decrypt file");
    }

    // Retrieve the original file name from metadata
    const originalFileName =
      metadata.metadata?.originalName || encryptedFileName.replace(".enc", "");

    // Convert the Uint8Array to Base64 string
    const base64Content = Buffer.from(decryptedContent).toString("base64");

    return { content: base64Content, originalFileName };
  } catch (error) {
    if (error instanceof Error) {
      console.error("Error during file download:", error.message);
      throw new Error(
        "Unable to retrieve or decrypt file. Please check the key and try again."
      );
    } else {
      console.error("An unknown error occurred");
      return { success: false, error: "Unknown error" };
    }
  }
};
