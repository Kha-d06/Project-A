import type { ReportCategory, ReportStatus } from "./api/types";

export const CATEGORY: Record<ReportCategory, { label: string; subjectLabel: string; placeholder: string }> = {
  website: { label: "Scam website", subjectLabel: "Website address", placeholder: "https://parcel-fee.example/pay" },
  scam_message: { label: "Scam message", subjectLabel: "Short summary", placeholder: "Fake bank text asking for a code" },
  job_offer: { label: "Fake job offer", subjectLabel: "Job title or company named", placeholder: "Remote data entry, Example Ltd" },
  fraudulent_app: { label: "Fraudulent app", subjectLabel: "App name or package", placeholder: "com.example.fakebank" },
  phone_number: { label: "Scam phone number", subjectLabel: "Phone number", placeholder: "+44 20 7946 0958" },
  social_account: { label: "Fake social account", subjectLabel: "Profile link or handle", placeholder: "instagram.com/fake.support" },
};

export const REPORT_STATUS: Record<ReportStatus, { label: string; description: string }> = {
  pending: { label: "Awaiting review", description: "A moderator has not reviewed this report yet." },
  verified: { label: "Verified", description: "A moderator confirmed this report. Qalaa now warns about it." },
  rejected: { label: "Not confirmed", description: "A moderator could not confirm this report." },
  duplicate: { label: "Duplicate", description: "This was already reported; the original report is being used." },
};
