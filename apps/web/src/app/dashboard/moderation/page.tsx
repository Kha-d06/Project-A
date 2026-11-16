import type { Metadata } from "next";

import { Moderation } from "@/components/admin/moderation";

export const metadata: Metadata = { title: "Moderation" };

export default function ModerationPage() {
  return <Moderation />;
}
