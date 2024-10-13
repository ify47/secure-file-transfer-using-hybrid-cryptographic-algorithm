"use client";

import { useSession } from "next-auth/react";
import {
  finishServerPasskeyRegistration,
  startServerPasskeyRegistration,
} from "../../../../../lib/passkey";
import {
  create,
  type CredentialCreationOptionsJSON,
} from "@github/webauthn-json";
import { Bounce, toast, ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

export default function SettingsOne() {
  const { data: session, update } = useSession();

  // Function to handle passkey verification

  async function registerPasskey() {
    if (!session || session?.user?.passkeydone) {
      toast("Device Already Authenticated!", {
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
      const createOptions = await startServerPasskeyRegistration();
      const credential = await create(
        createOptions as CredentialCreationOptionsJSON
      );
      await finishServerPasskeyRegistration(credential);

      const fetchUsers = async () => {
        const response = await fetch("/api/change-passkey");
        await response.json();
      };
      fetchUsers();

      await update({
        ...session,
        user: {
          ...session?.user,
          passkeydone: true,
        },
      });

      toast("Passkey Verification Complete!", {
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
    }
  }

  return (
    <div className="flex flex-col items-center justify-center h-screen">
      <ToastContainer />
      <h1>Hi, {session?.user?.name}, Please register your device</h1>
      <button
        onClick={() => registerPasskey()}
        className="p-2 bg-blue-500 text-white rounded"
      >
        {" "}
        {session?.user?.passkeydone
          ? "Contact Support to Enable Passkey "
          : "Register New Passkey"}
      </button>
    </div>
  );
}
