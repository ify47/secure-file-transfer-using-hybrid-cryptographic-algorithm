# Secure File Transfer Using Hybrid Cryptographic Algorithms

## Project Description

This project implements a secure file transfer system where users can send encrypted files to each other using hybrid cryptographic algorithms (RSA, ECC, AES). A unique encryption key is generated for each file and is shown to the user once. The key is never stored on the server, making the system highly secure. If a user loses the key, access to the file is lost.

The file transfer system incorporates multiple layers of security:

- **Encryption**: Files are encrypted using a combination of RSA, ECC, and AES algorithms.
- **Google Cloud Services**: Files are securely stored in Google Cloud Storage, and Google KMS is used to manage public/private keys.
- **User Authentication**: Passkey verification via [Hanko.io](https://hanko.io/) ensures only authorized users can download the files after key verification.

### Key Features:

- **Hybrid Encryption**: RSA and ECC algorithms are used in conjunction with AES for enhanced security.
- **Key Handling**: The encryption key is displayed once, never stored on the server.
- **Cloud Integration**: Google Cloud Storage and KMS are used for file storage and key management.
- **Passkey Authentication**: Users are required to pass [Hanko.io](https://hanko.io/) authentication before accessing encrypted files.

## Technologies Used

- **Next.js 14**
- **MongoDB**: For storing user information.
- **Google Cloud Storage**: For securely storing encrypted files.
- **Google Cloud KMS**: For key management.
- **Hanko.io**: For passkey-based user authentication.
- **Cryptographic Algorithms**: RSA, ECC, AES for encryption and decryption.

## Installation

### Prerequisites

Ensure you have the following installed:

- **Node.js** (v18 or above)
- **MongoDB**
- **Google Cloud SDK** (for Google Cloud services)
- **Hanko.io** API setup

### Setup Instructions

1. **Clone the Repository**:

   ```bash
   git clone
   cd your-repository
   ```

2. **Install Dependencies**:

   ```bash
   npm install
   ```

3. **Environment Variables**:
   Create a `.env.local` file in the root directory and include the following environment variables:
   ```bash
   MONGODB_URI=mongodb+srv://<your-db-connection-string>
   GOOGLE_CLOUD_PROJECT_ID=<your-google-cloud-project-id>
   GOOGLE_CLOUD_KMS_KEYRING=<your-kms-keyring-name>
   GOOGLE_CLOUD_KMS_KEY=<your-kms-key-name>
   GOOGLE_CLOUD_BUCKET_NAME=<your-gcs-bucket-name>
   HANKO_API_KEY=<your-hanko-api-key>
   ```
4. **Google Cloud Setup**:

   - Set up a Google Cloud Storage bucket for file storage.
   - Set up Google Cloud KMS for key management.
   - Ensure the necessary permissions are granted to the Google Cloud service account for accessing KMS and Storage.

5. **MongoDB Setup**:
   - Set up a MongoDB database (locally or using a cloud service like MongoDB Atlas) to store user information and file metadata.
   - Ensure the `MONGODB_URI` in the environment variables points to your MongoDB instance.

## Running the Application

To run the project locally:

1. **Development Mode**:

   ```bash
   npm run dev
   ```

   Open [http://localhost:3000](http://localhost:3000) to view it in your browser.

2. **Build for Production**:
   ```bash
   npm run build
   npm start
   ```

## File Structure

Below is a brief overview of key files in the project:

- **`encryptionAes.ts`**: Hybrid encryption implementation using AES and RSA.
- **`encryptionAesECC.ts`**: Hybrid encryption implementation using AES and ECC.
- **`fileOperations-AesEcc.ts`**: File operations (upload/download) with AES and ECC encryption.
- **`fileOperations-AesRsa.ts`**: File operations (upload/download) with AES and RSA encryption.
- **`kms.ts`**: Integrates Google Cloud KMS for key management.
- **`mongodb.ts`**: MongoDB connection and user operations.
- **`passkey.ts`**: Handles passkey verification using Hanko.io.
- **`userFileSharing.tsx`**: Main file-sharing component.

## Deployment

The application can be deployed to any platform that supports Node.js. Ensure that the necessary environment variables are set in your hosting platform.
