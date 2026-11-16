import { render, screen } from "@testing-library/react";

import { SessionProvider } from "@/lib/session";
import { jsonResponse } from "@/test/fixtures";
import { navigation } from "@/test/setup";

import { DashboardShell } from "./dashboard-shell";

function renderAs(role: string) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      jsonResponse({
        user: { id: "1", email: "a@example.com", display_name: null, role, created_at: "2026-11-16T10:00:00Z" },
        csrf_token: "t",
      }),
    ),
  );
  navigation.pathname = "/dashboard";
  render(
    <SessionProvider>
      <DashboardShell>content</DashboardShell>
    </SessionProvider>,
  );
}

describe("dashboard navigation", () => {
  it("hides staff pages from ordinary users", async () => {
    renderAs("user");
    expect(await screen.findAllByRole("link", { name: "Overview" })).not.toHaveLength(0);
    expect(screen.queryByRole("link", { name: "Moderation" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Administration" })).not.toBeInTheDocument();
  });

  it("shows moderation to moderators and everything to admins", async () => {
    renderAs("admin");
    expect(await screen.findAllByRole("link", { name: "Moderation" })).not.toHaveLength(0);
    expect(screen.getAllByRole("link", { name: "Administration" })).not.toHaveLength(0);
  });
});
