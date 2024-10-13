import RegisterForm from "@/components/registerForm";
import { getServerSession } from "next-auth";
import { authOptions } from "../api/auth/[...nextauth]/route";
import { redirect } from "next/navigation";

export default async function Signup() {
  const session = await getServerSession(authOptions);

  if (session) redirect("/dashboard");
  return <RegisterForm />;
}
