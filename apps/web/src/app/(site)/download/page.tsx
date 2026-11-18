import type { Metadata } from "next";

import { DownloadView } from "@/components/site/download";

export const metadata: Metadata = {
  title: "Download",
  description: "Qalaa Desktop for Windows, macOS and Linux, and the Android app.",
};

export default function DownloadPage() {
  return <DownloadView />;
}
