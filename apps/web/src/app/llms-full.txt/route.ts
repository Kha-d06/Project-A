import { connection } from "next/server";

import { llmsFullTxt } from "@/lib/llms";

export async function GET() {
  await connection();
  return new Response(llmsFullTxt(), { headers: { "Content-Type": "text/markdown; charset=utf-8", "Cache-Control": "public, max-age=3600" } });
}
