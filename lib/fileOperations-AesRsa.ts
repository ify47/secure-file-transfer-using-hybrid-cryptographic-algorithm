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

const credentials = JSON.parse(
  Buffer.from(
    process.env.KEYFILENAME ? process.env.KEYFILENAME : "",
    "base64"
  ).toString()
);

const projectId = process.env.PROJECT_ID;
const keyFilename = credentials;
const bucketName = process.env.BUCKET_NAME;

const FILE_SIZE_LIMIT = 25 * 1024 * 1024; // 25 MB

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

    // Split the RSA-encrypted key into two parts
    const rsaEncryptedKey = await encryptWithPublicKey(aesKey);
    const firstPartKey = rsaEncryptedKey.slice(0, 16); // First 16 characters for user
    const remainingKey = rsaEncryptedKey.slice(16); // Remaining part to be encrypted

    // Encrypt the remaining part using AES-256-CBC
    const encrypted = await generateShortKey(remainingKey);
    console.log("enc", encrypted);

    // Create a PassThrough stream for streaming the encrypted content
    const stream = new PassThrough();

    // Define the initial file name without numbering
    let baseFileName = `${file.name}.enc`;
    let fileNumber = 0;
    let encryptedFileName = baseFileName;

    // Loop to find an available file name
    let fileExists = await bucket.file(encryptedFileName).exists();
    while (fileExists[0]) {
      fileNumber += 1;
      encryptedFileName = `${file.name}(${fileNumber}).enc`;
      fileExists = await bucket.file(encryptedFileName).exists();
    }

    // Create a write stream to the Google Cloud Storage bucket
    const writeStream = bucket.file(encryptedFileName).createWriteStream({
      resumable: false, // Non-resumable for simplicity
      metadata: {
        contentType: file.type, // MIME type
        metadata: {
          originalName: file.name,
          userEmail: userEmail,
          senderName: senderName,
          fileType: file.type,
          fileSize: file.size,
          uploadTime: new Date().toISOString(),
          encrypted: encrypted,
        },
      },
    });

    // Convert the file buffer to encrypted content and pipe it to the write stream
    const buffer = await file.arrayBuffer();
    const uint8Array = new Uint8Array(buffer);
    const encryptedContent = encryptContent(uint8Array, aesKey); // Encrypt content

    // Pipe the PassThrough stream into Google Cloud Storage's write stream
    stream.write(Buffer.from(encryptedContent, "utf8"));
    stream.end();
    stream.pipe(writeStream);

    // Return the first 16 digits of the RSA-encrypted AES key to the user
    return new Promise((resolve, reject) => {
      writeStream.on("finish", () => {
        resolve({ success: true, key: firstPartKey });
      });

      writeStream.on("error", (error: any) => {
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
      throw new Error("File does not exist");
    }

    const [encryptedContent] = await file.download();

    // Retrieve the encrypted remaining part of the RSA-encrypted AES key from metadata
    const [metadata] = await file.getMetadata();
    const encrypted = metadata.metadata?.encrypted as string;

    if (!encrypted) {
      throw new Error("Missing encryption metadata");
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
      throw new Error("Invalid decryption key");
    }

    // Decrypt the file content using the AES key
    let decryptedContent;
    try {
      decryptedContent = decryptContent(
        encryptedContent.toString("utf8"),
        aesKey as string
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
