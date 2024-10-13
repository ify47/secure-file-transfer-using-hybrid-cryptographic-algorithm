"use client";
import { decodeJwt } from "jose";
import { getServerSession } from "next-auth";
import { useSession } from "next-auth/react";

export async function getUserID(token: string) {
  const payload = decodeJwt(token ?? "");

  const userID = payload.sub;
  return userID;
}

// export async function loginWithPasskey(userId: string) {
//   const session = await getServerSession(authOptions);
//   console.log("session", session);
//   const user = session?.user.id === userId;
//   if (!user) {
//     throw new Error("Authentication failed");
//   }

//   console.log("yes it him");
// }
