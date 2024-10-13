"use client";
import { useState, useEffect } from "react";
import { useSession } from "next-auth/react";
import { UploadFile } from "../../lib/fileOperations-AesEcc";
import "react-toastify/dist/ReactToastify.css";
import { Bounce, toast, ToastContainer } from "react-toastify";
import AlertNoVerification from "./alertNoVerification";
import Image from "next/image";
import copyIcon from "../assets/copy-svgrepo-com.svg";
import LoadingSpin from "./loadingSpin";

export default function UserFileSharingEcc() {
  const { data: session } = useSession();
  const [encryptionKey, setEncryptionKey] = useState<string | null>(null);
  const [users, setUsers] = useState<
    {
      name?: string;
      email?: string;
      id?: string;
    }[]
  >([]);

  const [selectedUser, setSelectedUser] = useState<string>("");
  const [loading, setLoading] = useState(false);

  const handleUpload = async (form: FormData) => {
    setLoading(true);
    if (!session || session?.user?.passkeydone === false) {
      toast("Cant send until you verify passkey!", {
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
      setLoading(false);
      return;
    } else {
      if (selectedUser) {
        const result = await UploadFile(
          form,
          selectedUser,
          session?.user?.name || ""
        );

        if (result.success) {
          setEncryptionKey(result.key || ""); // Set the key to display

          // Show success toast notification
          toast("File encrypted and sent!", {
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
        } else {
          // Show error toast notification
          toast.error(result.error || "Unknown error occurred", {
            theme: "colored",
          });
        }
      } else {
        alert("Please select a user to upload the file to.");
      }
    }
    setLoading(false);
  };

  useEffect(() => {
    const fetchUsers = async () => {
      const response = await fetch("/api/users");
      const data = await response.json();
      setUsers(data);
    };

    fetchUsers();
  }, []);

  const copyFunc = () => {
    navigator.clipboard.writeText(encryptionKey as string);
    toast("Copied to clipboard", {
      position: "top-center",
      hideProgressBar: false,
      closeOnClick: true,
      pauseOnHover: true,
      draggable: true,
      progress: undefined,
      theme: "light",
      transition: Bounce,
    });
  };

  return (
    <div className="max-w-screen-xl mx-auto px-4 md:px-8 mt-10">
      <ToastContainer />
      <div className="space-y-4">
        <h1 className="text-2xl font-bold">Hi {session?.user?.name}</h1>
        {session?.user?.passkeydone ? "" : <AlertNoVerification />}

        <h1 className="text-2xl font-bold">
          Ready to share with someone? Let`s keep your files safe!
        </h1>
        <div className="mt-4">
          <label htmlFor="users">Available Users:</label>
          <select
            id="users"
            value={selectedUser}
            onChange={(e) => setSelectedUser(e.target.value)}
            className="ml-2"
          >
            <option value="" disabled>
              Select user
            </option>
            {users.map((user, i) =>
              session?.user?.email === user.email ? null : (
                <option key={i} value={user.email}>
                  {user.name}
                </option>
              )
            )}
          </select>
        </div>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            const form = new FormData(e.currentTarget);
            await handleUpload(form);
          }}
        >
          <input type="file" name="file" required />
          <button
            type="submit"
            className="mt-2 p-2 bg-blue-500 text-white rounded"
          >
            {loading && <LoadingSpin />}
            Upload File
          </button>
        </form>

        {encryptionKey && (
          <div className="mt-4">
            <p className="flex items-center break-all max-w-full">
              Your encryption key: <strong>{encryptionKey}</strong>{" "}
              <Image
                width={20}
                className="cursor-pointer"
                onClick={copyFunc}
                src={copyIcon}
                alt="Copy Icon"
              />
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
