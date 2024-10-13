import { authOptions } from "@/app/utils/authOptions";
import NextAuth from "next-auth";

declare module "next-auth" {
  interface Session {
    user:
      | {
          name?: string | null;
          email?: string | null;
          id?: string | null;
          passkeydone?: boolean;
        }
      | undefined;
  }
}

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };
