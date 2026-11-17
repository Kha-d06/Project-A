import type { Metadata } from "next";

import { Vpn } from "@/components/dashboard/vpn";

export const metadata: Metadata = { title: "VPN" };

export default function VpnPage() {
  return <Vpn />;
}
