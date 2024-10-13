import { NextResponse } from "next/server";
import { connectMongoDB } from "../../../../lib/mongodb";
import User from "../../../../models/user";
import { getServerSession } from "next-auth";
import { Sess } from "../../../../lib/passkey";
import { authOptions } from "@/app/utils/authOptions";
export const dynamic = "force-dynamic";
export async function GET() {
  const session = (await getServerSession(authOptions)) as Sess;
  await connectMongoDB();

  const users = await User.findOneAndUpdate(
    { _id: session?.user?.id },
    { passkeydone: true }
  );

  if (!users) {
    return NextResponse.json({ error: "User not found" }, { status: 404 });
  }

  return NextResponse.json({ success: true });
}
