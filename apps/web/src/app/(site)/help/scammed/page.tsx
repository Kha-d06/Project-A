import type { Metadata } from "next";

import { ScammedGuide } from "@/components/site/scammed";

export const metadata: Metadata = {
  title: "I think I've been scammed",
  description: "Urgent steps by situation: card payments, transfers, shared codes, passwords, remote access and identity documents.",
};

export default function ScammedPage() {
  return <ScammedGuide />;
}
