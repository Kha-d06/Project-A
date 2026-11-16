import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { SessionProvider } from "@/lib/session";
import { jsonResponse } from "@/test/fixtures";
import { navigation, router } from "@/test/setup";

import { AuthForm, safeNextPath } from "./auth-form";

const user = { id: "1", email: "a@example.com", display_name: null, role: "user", created_at: "2026-11-16T10:00:00Z" };

function serve(login: Response) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) =>
      url.endsWith("/auth/session") ? jsonResponse({ user: null, csrf_token: null }) : login.clone(),
    ),
  );
}

describe("safeNextPath", () => {
  it.each([
    ["/dashboard/history", "/dashboard/history"],
    ["https://evil.example", "/dashboard"],
    ["//evil.example", "/dashboard"],
    ["/\\evil.example", "/dashboard"],
    [null, "/dashboard"],
  ])("maps %s to %s", (input, expected) => {
    expect(safeNextPath(input)).toBe(expected);
  });
});

describe("AuthForm", () => {
  it("validates before contacting the server", async () => {
    serve(jsonResponse({}));
    render(<SessionProvider><AuthForm mode="sign-up" /></SessionProvider>);
    await userEvent.type(screen.getByLabelText("Email"), "not-an-email");
    await userEvent.type(screen.getByLabelText("Password"), "short");
    await userEvent.click(screen.getByRole("button", { name: "Create account" }));
    expect(screen.getByText("Enter a valid email address.")).toBeInTheDocument();
    expect(screen.getByText("Use at least 10 characters.")).toBeInTheDocument();
  });

  it("shows the server's message for wrong credentials", async () => {
    serve(jsonResponse({ error: { code: "invalid_credentials", message: "The email or password is incorrect." } }, 401));
    render(<SessionProvider><AuthForm mode="sign-in" /></SessionProvider>);
    await userEvent.type(screen.getByLabelText("Email"), "a@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "whatever-password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("The email or password is incorrect.");
  });

  it("returns to the requested page after signing in", async () => {
    navigation.search = new URLSearchParams("next=/dashboard/settings");
    serve(jsonResponse({ user, csrf_token: "t" }));
    render(<SessionProvider><AuthForm mode="sign-in" /></SessionProvider>);
    await userEvent.type(screen.getByLabelText("Email"), "a@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "whatever-password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await vi.waitFor(() => expect(router.push).toHaveBeenCalledWith("/dashboard/settings"));
  });
});

describe("two-step sign-in", () => {
  it("asks for the code after a correct password and only then signs in", async () => {
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        calls.push(url);
        if (url.endsWith("/auth/session")) return jsonResponse({ user: null, csrf_token: null });
        if (url.endsWith("/system/providers")) return jsonResponse([]);
        if (url.endsWith("/auth/login")) return jsonResponse({ two_factor_required: true, challenge: "c.1.2.sig" });
        return jsonResponse({ user, csrf_token: "t" });
      }),
    );
    render(<SessionProvider><AuthForm mode="sign-in" /></SessionProvider>);
    await userEvent.type(screen.getByLabelText("Email"), "a@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "whatever-password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Two-step sign-in")).toBeInTheDocument();
    expect(router.push).not.toHaveBeenCalled();
    await userEvent.type(screen.getByLabelText("Code"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Verify" }));
    await vi.waitFor(() => expect(router.push).toHaveBeenCalledWith("/dashboard"));
    expect(calls).toContain("/api/v1/auth/login/two-factor");
  });
});
