import type { Metadata } from "next";

import { PasswordVault } from "@/components/dashboard/password-vault";

export const metadata: Metadata = { title: "Passwords" };

export default function PasswordsPage() {
  return <PasswordVault />;
}
