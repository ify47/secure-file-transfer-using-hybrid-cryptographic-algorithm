import { NextResponse } from "next/server";
import { connectMongoDB } from "../../../../lib/mongodb";
import User from "../../../../models/user";

export const dynamic = "force-dynamic";
export async function GET() {
  await connectMongoDB();
  const users = await User.find({}, "name email"); // Fetch only username and email
  // const users = await User.findOneAndUpdate({email:'john3@gmail.com'}, {passkeydone:false});

  return NextResponse.json(users);
}
