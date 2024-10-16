import CredentialsProvider from "next-auth/providers/credentials";

import bcrypt from "bcryptjs";
import {
  PasskeyProvider,
  tenant,
} from "@teamhanko/passkeys-next-auth-provider";
import { connectMongoDB } from "../../../lib/mongodb";
import User from "../../../models/user";

type UserType = {
  passkeydone: any;
  name: string;
  email: string;
  password: string;
  id: string;
};

type Token = {
  passkeydone: boolean;
  name: string;
  email: string;
  id: string;
};

export const authOptions: any = {
  providers: [
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "email", required: true },
        password: { label: "Password", type: "password", required: true },
      },

      async authorize(credentials) {
        if (!credentials) {
          return null;
        }
        const { email, password } = credentials;

        try {
          await connectMongoDB();
          const user = await User.findOne({ email });

          if (!user) {
            return null;
          }

          const passwordsMatch = await bcrypt.compare(password, user.password);

          if (!passwordsMatch) {
            return null;
          }

          return user;
        } catch (error) {}
      },
    }),
    PasskeyProvider({
      tenant: tenant({
        apiKey: process.env.PASSKEYS_API_KEY as string,
        tenantId: process.env.NEXT_PUBLIC_PASSKEYS_TENANT_ID as string,
      }),
      async authorize({ userId }) {
        await connectMongoDB();

        const user = await User.findOne({ userId: userId });

        if (!user) return null;

        // Do more stuff

        return {
          user,
        };
      },
    }),
  ],
  callbacks: {
    async jwt({
      token,
      user,
      trigger,
      session,
    }: {
      token: Token;
      user?: UserType;
      trigger: string;
      session: any;
    }) {
      if (user) {
        token.name = user.name;
        token.email = user.email;
        token.id = user.id;
        token.passkeydone = user.passkeydone;
      }
      if (trigger === "update" && session?.user?.passkeydone !== undefined) {
        token.passkeydone = session.user.passkeydone; // Only update passkeydone field
      }
      return token;
    },
    async session({ session, token }: { session: any; token: Token }) {
      if (token) {
        session.user.name = token.name;
        session.user.email = token.email;
        session.user.id = token.id;
        session.user.passkeydone =
          token.passkeydone ?? session.user.passkeydone;
      }

      return session;
    },
  },
  // session: {
  //     strategy: 'jwt',
  // },
  secret: process.env.NEXTAUTH_SECRET,
  pages: {
    signIn: "/login",
  },
};
