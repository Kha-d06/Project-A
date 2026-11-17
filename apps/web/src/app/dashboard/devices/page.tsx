import type { Metadata } from "next";

import { Devices } from "@/components/dashboard/devices";

export const metadata: Metadata = { title: "Devices" };

export default function DevicesPage() {
  return <Devices />;
}
