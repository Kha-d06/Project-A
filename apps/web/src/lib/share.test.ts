import { shareDestination } from "./share";

const dest = (query: string) => new URLSearchParams(shareDestination(new URLSearchParams(query)).split("?")[1]);

describe("shareDestination", () => {
  it("opens the link scanner for a shared link", () => {
    const params = dest("url=https%3A%2F%2Fexample.org%2Fx");
    expect(params.get("type")).toBe("url");
    expect(params.get("url")).toBe("https://example.org/x");
  });

  it("treats text that is only a link as a link", () => {
    expect(dest("text=%20https%3A%2F%2Fbit.ly%2Fabc%20").get("type")).toBe("url");
  });

  it("opens the message scanner for shared text, keeping any link with it", () => {
    const params = dest("text=Your%20parcel%20is%20held&url=https%3A%2F%2Fparcel.example%2Fpay");
    expect(params.get("type")).toBe("message");
    expect(params.get("text")).toBe("Your parcel is held\nhttps://parcel.example/pay");
  });

  it("caps very long shared text", () => {
    expect(dest(`text=${"a".repeat(20_000)}`).get("text")).toHaveLength(10_000);
  });
});
