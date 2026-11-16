import type { Metadata } from "next";

import { Groups } from "@/components/dashboard/groups";

export const metadata: Metadata = { title: "Family & teams" };

export default function GroupsPage() {
  return <Groups />;
}
