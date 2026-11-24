import type { Metadata } from "next";

import { JsonLd } from "@/components/seo/json-ld";
import { DownloadView } from "@/components/site/download";
import { softwareApplicationLd } from "@/lib/seo";

export const metadata: Metadata = {
  title: "Download",
  description: "Qalaa Desktop for Windows, macOS and Linux, and the Android app.",
};

export default function DownloadPage() {
  return (
    <>
      <JsonLd data={softwareApplicationLd()} />
      <DownloadView />
    </>
  );
}
