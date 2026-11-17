import type { Metadata } from "next";

import { PasswordGenerator } from "@/components/site/password-generator";

export const metadata: Metadata = {
  title: "Password generator",
  description: "Strong passwords and passphrases generated in your browser.",
};

export default function PasswordPage() {
  return <PasswordGenerator />;
}
