'use server';

import { Storage } from "@google-cloud/storage";
import { decryptContent, encryptContent, generateKey } from './encryption';
import path from 'path';
import { performance } from "perf_hooks";

const projectId = process.env.PROJECT_ID;
const keyFilename = process.env.KEYFILENAME;
const bucketName = process.env.BUCKET_NAME;

export const UploadFile = async (form: FormData, userEmail: string, senderName: string) => {
    try {
        const file = form.get('file') as File;
        if (!file) throw new Error('No file provided');
        if (file.size < 1) throw new Error('File is empty');

        const buffer = await file.arrayBuffer();
        const uint8Array = new Uint8Array(buffer);

        // Generate an encryption key and encrypt the content
        const key = generateKey();
        const startEncrypt = performance.now();  // Start measuring time
        const encryptedContent = encryptContent(uint8Array, key);
        const endEncrypt = performance.now();    // End measuring time
        const encryptionTime = endEncrypt - startEncrypt;
        console.log(`Encryption Time: ${encryptionTime} ms`);

         // Decryption for testing (optional)
         const startDecrypt = performance.now();  // Start measuring time
         decryptContent(encryptedContent, key);
         const endDecrypt = performance.now();    // End measuring time
         const decryptionTime = endDecrypt - startDecrypt;
         console.log(`Decryption Time: ${decryptionTime} ms`);

        const storage = new Storage({ projectId, keyFilename });
        const bucket = storage.bucket(bucketName as string);

        // Save the encrypted content to the bucket with a .enc extension
        const encryptedFileName = `${file.name}.enc`;
        await bucket.file(encryptedFileName).save(Buffer.from(encryptedContent, 'utf8'));

        const fileType = file.type;  // MIME type
        const fileSize = file.size;  // File size in bytes
        const uploadTime = new Date().toISOString();
        // Store the original file name and the user's email in metadata
        const metadata = {
            metadata: {
                originalName: file.name,
                userEmail: userEmail,  // Recipient's email
                senderName: senderName,  // Sender's name
                fileType: fileType,  // MIME type of the file
                fileSize: fileSize,  // Size in bytes
                uploadTime: uploadTime,  // Time of upload
            },
        };
        await bucket.file(encryptedFileName).setMetadata(metadata);

        return { success: true, key, encryptionTime, decryptionTime };  // Return the key
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
        const storage = new Storage({ projectId, keyFilename });
        const bucket = storage.bucket(bucketName as string);
        const [files] = await bucket.getFiles();

        // Fetch the metadata including senderEmail, fileType, fileSize, and uploadTime
        const fileList = await Promise.all(files.map(async (file) => {
            const [metadata] = await file.getMetadata();
            
            if (metadata.metadata?.userEmail === userEmail) {
                return {
                    originalName: metadata.metadata?.originalName as string || file.name.replace('.enc', ''),
                    encryptedName: file.name,
                    senderName: metadata.metadata?.senderName as string || 'Unknown',  // Get the sender's name
                    fileType: metadata.metadata?.fileType as string || 'Unknown',  // Get file MIME type
                    fileSize: metadata.metadata?.fileSize as number || 0,  // Get file size in bytes
                    uploadTime: metadata.metadata?.uploadTime as string || 'Unknown',  // Get upload time
                };
            }
            return null;
        }));

        // Filter out any null results (files not meant for the user)
        const userFiles = fileList.filter(file => file !== null);

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



export const DownloadFile = async (encryptedFileName: string, key: string) => {
    try {
        const storage = new Storage({ projectId, keyFilename });
        const bucket = storage.bucket(bucketName as string);
        const file = bucket.file(encryptedFileName);
        const exists = await file.exists();

        if (!exists[0]) {
            throw new Error("File does not exist");
        }

        const [encryptedContent] = await file.download();
        
        // Attempt decryption
        let decryptedContent;
        try {
            decryptedContent = decryptContent(encryptedContent.toString('utf8'), key);

            // Validate the decrypted content
            const magicString = "MAGICSTRING";  // Example of a known string to check after decryption
            const magicStringLength = magicString.length;
            const contentString = new TextDecoder().decode(decryptedContent.slice(0, magicStringLength));

            if (contentString !== magicString) {
                throw new Error("Invalid decryption key");
            }

            // Remove the magic string from the content
            decryptedContent = decryptedContent.slice(magicStringLength);

        } catch (error) {
            throw new Error("Invalid decryption key");
        }

        // If decryption was successful, retrieve the original file name from metadata
        const [metadata] = await file.getMetadata();
        const originalFileName = metadata.metadata?.originalName || encryptedFileName.replace('.enc', '');

        // Convert the Uint8Array to Base64 string
        const base64Content = Buffer.from(decryptedContent).toString('base64');

        return { content: base64Content, originalFileName };
    } catch (error) {
        if (error instanceof Error) {
        console.error("Error during file download:", error.message);
        throw new Error("Unable to retrieve or decrypt file. Please check the key and try again.");
        }else {
            console.error("An unknown error occurred");
            return { success: false, error: "Unknown error" };
        }
    }
};

