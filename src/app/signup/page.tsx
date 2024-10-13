import RegisterForm from "@/components/registerForm";
import { getServerSession } from "next-auth";

import { redirect } from "next/navigation";
import { authOptions } from "../utils/authOptions";

export default async function Signup() {
  const session = await getServerSession(authOptions);

  if (session) redirect("/dashboard");
  return <RegisterForm />;
}
