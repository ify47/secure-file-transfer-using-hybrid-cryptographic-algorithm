"use server";

import { createRemoteJWKSet, jwtVerify } from "jose"; // Import JWT verify function
import { authOptions } from "@/app/api/auth/[...nextauth]/route";
import { tenant } from "@teamhanko/passkeys-sdk";
import { getServerSession } from "next-auth";

export type Sess = {
  user: {
      name: string;
      email: string;
      id: string;
      passkeydone: boolean
    }
}

const jwksUrl = process.env.JWKURL as string

const jwks = createRemoteJWKSet(new URL(jwksUrl));

const passkeyApi = tenant({
  apiKey: process.env.PASSKEYS_API_KEY as string,
  tenantId: process.env.NEXT_PUBLIC_PASSKEYS_TENANT_ID as string,
});

export async function startServerPasskeyRegistration() {
    const session = await getServerSession(authOptions) as Sess;
  console.log("sessionsss", session);
  const sessionUser = session?.user;

  const createOptions = await passkeyApi.registration.initialize({
    userId: sessionUser!.id,
    username: sessionUser!.email || "",
  });

  return createOptions;
}

export async function finishServerPasskeyRegistration(credential: any) {
    const session = await getServerSession(authOptions);
  if (!session) throw new Error("Not logged in");

  await passkeyApi.registration.finalize(credential);
}

export async function startServerPasskeyLogin() {
  const options = await passkeyApi.login.initialize();
  return options;
}


export async function finishServerPasskeyLogin(options: any) {
    const response = await passkeyApi.login.finalize(options);
  
    // Log the response for debugging
    console.log("Hanko response:", response);
  
    if (response.token) {
      // Use the JWKS URL to verify the JWT
      const { payload } = await jwtVerify(response.token, jwks);
  
      console.log("Decoded JWT payload:", payload);
  
      // Return the payload (where 'sub' is typically the userId)
      return { token: payload };
    } else {
      throw new Error("Authentication failed: No token received");
    }
  }
