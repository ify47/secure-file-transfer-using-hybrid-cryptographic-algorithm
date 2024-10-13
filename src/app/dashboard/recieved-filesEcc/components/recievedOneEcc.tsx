"use client";
import { useEffect, useState } from "react";
import {
  DownloadFile,
  FetchFiles,
} from "../../../../../lib/fileOperations-AesEcc";
import { useSession } from "next-auth/react";
import {
  finishServerPasskeyLogin,
  startServerPasskeyLogin,
} from "../../../../../lib/passkey";
import { get } from "@github/webauthn-json";
import { Bounce, toast, ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

export default function RecievedOne() {
  const { data: session } = useSession();
  const [keyInput, setKeyInput] = useState<{ [key: string]: string }>({});
  const [files, setFiles] = useState<
    | {
        originalName: string;
        encryptedName: string;
        senderName: string;
        fileType: string;
        fileSize: number;
        uploadTime: string;
      }[]
    | undefined
  >([]);

  useEffect(() => {
    // Fetch the list of files for the logged-in user when the component mounts
    const fetchFiles = async () => {
      if (session?.user?.email) {
        const result = await FetchFiles(session.user.email);
        if (result.success) {
          setFiles(result.files);
        } else {
          console.error(result.error);
        }
      }
    };
    fetchFiles();
  }, [session]);

  const handleKeyInputChange = (fileName: string, value: string) => {
    setKeyInput((prev) => ({
      ...prev,
      [fileName]: value,
    }));
  };

  const handleDownload = async (selectedFile: {
    originalName: string;
    encryptedName: string;
  }) => {
    if (!session || session?.user?.passkeydone === false) {
      toast("Cant download until you verify passkey!", {
        position: "top-center",
        autoClose: 5000,
        hideProgressBar: false,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
        progress: undefined,
        theme: "light",
        transition: Bounce,
      });
      return;
    } else {
      const decryptionKey = keyInput[selectedFile.encryptedName];
      if (selectedFile && decryptionKey) {
        try {
          // Download the file with the provided first 16 characters of the key
          const { content, originalFileName, error } = await DownloadFile(
            selectedFile.encryptedName,
            decryptionKey // Pass the first part of the key
          );

          if (!content) {
            toast.error(error, {
              theme: "colored",
            });
            return;
          }

          try {
            // Step 1: Start the passkey login process using the server function
            const loginOptions = await startServerPasskeyLogin();

            // Step 2: Complete the passkey login using WebAuthn (on the client)
            const credential = await get(loginOptions as any);

            // Step 3: Finalize the passkey login using the server function
            const response = await finishServerPasskeyLogin(credential);

            // Step 4: Verify that the userId from Hanko matches the session userId
            const hankoUserId = response.token.sub;

            if (session?.user?.id === hankoUserId) {
            } else {
              alert("Verification failed: User ID mismatch");
              return;
            }
          } catch (error) {
            alert("Error during passkey verification:");
            return;
          }

          // Convert Base64 string back to Uint8Array
          const binaryString = atob(content);
          const len = binaryString.length;
          const uint8Array = new Uint8Array(len);
          for (let i = 0; i < len; i++) {
            uint8Array[i] = binaryString.charCodeAt(i);
          }

          // Create a blob from the content
          const blob = new Blob([uint8Array], {
            type: "application/octet-stream",
          });

          // Create a link element, set the download attribute, and click it to trigger download
          const link = document.createElement("a");
          link.href = URL.createObjectURL(blob);
          link.download = String(originalFileName); // Restore the original file name
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link); // Cleanup the link element
        } catch (error) {
          if (error instanceof Error) {
            console.error("Error downloading file:", error);
            alert("Error downloading file: " + error.message);
          } else {
            console.error("Unknown error occurred:", error);
          }
        }
      }
    }
  };

  return (
    <div className="max-w-screen-xl mx-auto px-4 md:px-8 mt-10">
      <div className="items-start justify-between md:flex">
        <ToastContainer />
        <div className="max-w-lg">
          <h3 className="text-gray-800 text-xl font-bold sm:text-2xl">
            Recieved Files
          </h3>
          <p className="text-gray-600 mt-2">
            All secured files recieved from Users
          </p>
        </div>
      </div>
      <div className="mt-12 relative h-max overflow-auto">
        <table className="w-full table-auto text-sm text-left">
          <thead className="text-gray-600 font-medium border-b">
            <tr>
              <th className="py-3 pr-6">Name</th>
              <th className="py-3 pr-6">Date</th>
              <th className="py-3 pr-6">Extension</th>
              <th className="py-3 pr-6">File Size</th>
              <th className="py-3 pr-6">Sender</th>
              <th className="py-3 pr-6">Decrytion Key</th>
              <th className="py-3 pr-6"></th>
            </tr>
          </thead>
          <tbody className="text-gray-600 divide-y">
            {files &&
              files.map((item, idx) => (
                <tr key={idx}>
                  <td className="pr-6 py-4 whitespace-nowrap">
                    {item.originalName}
                  </td>
                  <td className="pr-6 py-4 whitespace-nowrap">
                    {new Date(item.uploadTime).toLocaleDateString()}
                  </td>
                  <td className="pr-6 py-4 whitespace-nowrap">
                    <span className="px-3 py-2 rounded-full font-semibold text-xs text-green-600 bg-green-50">
                      {item.fileType}
                    </span>
                  </td>
                  <td className="pr-6 py-4 whitespace-nowrap">
                    {(item.fileSize / 1024).toFixed(2)} KB
                  </td>
                  <td className="pr-6 py-4 whitespace-nowrap">
                    {item.senderName}
                  </td>
                  <td className="pr-6 py-4 whitespace-nowrap">
                    <input
                      value={keyInput[item.encryptedName] || ""}
                      onChange={(e) =>
                        handleKeyInputChange(item.encryptedName, e.target.value)
                      }
                      placeholder="Enter your key"
                      className="p-1 border rounded"
                      type="text"
                    />
                  </td>
                  <td className="text-right whitespace-nowrap">
                    <button
                      onClick={() => handleDownload(item)}
                      className="py-1.5 px-3 text-gray-600 hover:text-gray-500 duration-150 hover:bg-gray-50 border rounded-lg"
                    >
                      Download
                    </button>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
