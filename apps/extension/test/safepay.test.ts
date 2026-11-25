import { describe, expect, it } from "vitest";

import { isBankingHost, safePayLink } from "../src/lib/safepay";

describe("SafePay offer", () => {
  it("recognises banks and payment sites, including subdomains", () => {
    for (const host of ["www.emiratesnbd.com", "online.adcb.com", "alrajhibank.com.sa", "www.paypal.com", "secure.chase.com", "onlinebanking.example.org", "ebank.example.com", "bank.example"]) {
      expect(isBankingHost(host), host).toBe(true);
    }
    expect(isBankingHost("shop.example", ["shop.example"])).toBe(true);
  });

  it("leaves ordinary sites alone", () => {
    for (const host of ["bankrate.com", "example.com", "paypal.com.evil.example", "notpaypal.com", "databank-news.example", "bank"]) {
      expect(isBankingHost(host), host).toBe(false);
    }
  });

  it("hands over https pages only", () => {
    expect(safePayLink("https://www.paypal.com/signin?x=1")).toBe(`qalaa://safepay?url=${encodeURIComponent("https://www.paypal.com/signin?x=1")}`);
    expect(safePayLink("http://bank.example/")).toBeNull();
    expect(safePayLink("https://u:p@bank.example/")).toBeNull();
    expect(safePayLink("not a url")).toBeNull();
  });
});
