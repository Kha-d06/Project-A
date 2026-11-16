import type { Metadata } from "next";

import { BreachCheck } from "@/components/dashboard/breach-check";

export const metadata: Metadata = { title: "Breach check" };

export default function BreachPage() {
  return <BreachCheck />;
}
