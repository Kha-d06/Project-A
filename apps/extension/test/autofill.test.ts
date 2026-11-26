import { describe, expect, it } from "vitest";

import { newItem } from "../../web/src/lib/vault";
import { canFillOn, fillLoginForm, isPublicSuffix, loginsFor, refusal } from "../src/lib/autofill";

const bank = newItem("login", { title: "Bank", url: "https://www.mybank.example.com/login", username: "sara", password: "b4nk-Pass!" });
const mail = newItem("login", { title: "Mail", url: "mail.example.org", username: "sara@x", password: "m4il" });
const note = newItem("note", { title: "Alarm", notes: "1234" });

describe("which logins belong to a page", () => {
  it("matches the same host and its subdomains, never lookalikes", () => {
    expect(loginsFor([bank, mail, note], "https://mybank.example.com/account").map((i) => i.title)).toEqual(["Bank"]);
    expect(loginsFor([bank], "https://online.mybank.example.com/").map((i) => i.title)).toEqual(["Bank"]);
    expect(loginsFor([bank], "https://mybank.example.com.evil.test/")).toEqual([]);
    expect(loginsFor([bank], "https://evil-mybank.example.com/")).toEqual([]);
    expect(loginsFor([mail], "https://mail.example.org/")).toHaveLength(1);
  });
});

describe("when Qalaa refuses to fill", () => {
  it("needs https, a safe verdict and a saved login", () => {
    expect(canFillOn("https://a.example/")).toBe(true);
    expect(canFillOn("http://a.example/")).toBe(false);
    expect(canFillOn("http://localhost:3000/")).toBe(true);
    expect(refusal("http://a.example/", null, 1)).toBe("not_https");
    expect(refusal("https://a.example/", "dangerous", 1)).toBe("dangerous_site");
    expect(refusal("https://a.example/", "blocked_by_family", 1)).toBe("dangerous_site");
    expect(refusal("https://a.example/", "no_known_threat", 0)).toBe("no_match");
    expect(refusal("https://a.example/", "no_known_threat", 1)).toBeNull();
  });
});

describe("filling the form in the page", () => {
  it("fills the visible username and password fields", () => {
    document.body.innerHTML = `
      <form>
        <input type="hidden" name="csrf" value="x">
        <input type="email" id="email">
        <input type="password" id="pw">
      </form>`;
    // jsdom has no layout; give the fields a size so they count as visible.
    for (const field of document.querySelectorAll("input")) field.getBoundingClientRect = () => ({ width: 100, height: 20 }) as DOMRect;
    let inputEvents = 0;
    document.getElementById("pw")!.addEventListener("input", () => inputEvents++);
    expect(fillLoginForm("sara", "s3cret", location.origin)).toEqual({ filled: true, usernameFilled: true });
    expect((document.getElementById("email") as HTMLInputElement).value).toBe("sara");
    expect((document.getElementById("pw") as HTMLInputElement).value).toBe("s3cret");
    expect(inputEvents).toBe(1);
  });

  it("skips invisible password fields (a common skimming trick)", () => {
    document.body.innerHTML = `<input type="text" id="u"><input type="password" id="trap">`;
    for (const field of document.querySelectorAll("input")) field.getBoundingClientRect = () => ({ width: 0, height: 0 }) as DOMRect;
    expect(fillLoginForm("sara", "s3cret", location.origin).filled).toBe(false);
    expect((document.getElementById("trap") as HTMLInputElement).value).toBe("");
  });

  it("fills nothing if the page is no longer on the origin that was checked", () => {
    document.body.innerHTML = `<input type="password" id="pw">`;
    for (const field of document.querySelectorAll("input")) field.getBoundingClientRect = () => ({ width: 100, height: 20 }) as DOMRect;
    expect(fillLoginForm("sara", "s3cret", "https://bank.example").filled).toBe(false);
    expect((document.getElementById("pw") as HTMLInputElement).value).toBe("");
  });
});

describe("logins saved for a shared suffix", () => {
  const login = (url: string) => newItem("login", { title: url, url, username: "u", password: "p" });

  it("are offered only on that exact host, never on every site under it", () => {
    for (const saved of ["github.io", "herokuapp.com", "co.uk"]) {
      expect(isPublicSuffix(saved)).toBe(true);
      expect(loginsFor([login(saved)], `https://attacker.${saved}/login`)).toEqual([]);
    }
    expect(isPublicSuffix("example.com")).toBe(false);
    expect(isPublicSuffix("sara.github.io")).toBe(false);
    expect(loginsFor([login("sara.github.io")], "https://docs.sara.github.io/").length).toBe(1);
    expect(loginsFor([login("sara.github.io")], "https://omar.github.io/")).toEqual([]);
  });
});

