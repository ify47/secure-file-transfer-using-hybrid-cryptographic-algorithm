import Link from "next/link";
import React from "react";

export default function AlertNoVerification() {
  return (
    <div className="max-w-5xl mx-auto px-4 md:px-8">
      <div className="flex justify-between p-4 rounded-md bg-red-50 border border-red-300">
        <div className="flex gap-3">
          <div>
            <svg
              xmlns="http://www.w3.org/2000/svg"
              className="h-6 w-6 text-red-500"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
          </div>
          <div className="self-center">
            <span className="text-red-600 font-medium">
              Account is Inactive
            </span>
            <div className="text-red-600">
              <p className="mt-2 sm:text-sm">
                You can&apos;t send or recieve files from users until you
                activate your Passkey verication, Please go to{" "}
                <Link className="text-blue-400" href="/dashboard/settings">
                  Settings
                </Link>{" "}
                to verify your device
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
