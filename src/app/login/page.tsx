import LoginForm from "@/components/loginForm";
import { getServerSession } from "next-auth";
import { redirect } from "next/navigation";
import { authOptions } from "../utils/authOptions";

export default async function Login() {
  const session = await getServerSession(authOptions);

  if (session) redirect("/dashboard");
  return <LoginForm />;
}
