import { jsonResponse, mockFetch } from "@/test/fixtures";

import { ApiError, api, setCsrfToken } from "./client";

describe("api client", () => {
  afterEach(() => setCsrfToken(null));

  it("turns the error envelope into an ApiError with field messages", async () => {
    mockFetch(
      jsonResponse(
        {
          error: {
            code: "validation_error",
            message: "Only http:// and https:// links can be checked.",
            details: [{ field: "url", message: "Only http:// and https:// links can be checked." }],
          },
        },
        422,
      ),
    );
    const error = await api.scans.url("ftp://x").catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).fieldErrors()).toEqual({
      url: "Only http:// and https:// links can be checked.",
    });
  });

  it("reports a network failure in plain language", async () => {
    mockFetch(new TypeError("Failed to fetch"));
    await expect(api.system.providers()).rejects.toMatchObject({
      code: "network_error",
      message: expect.stringMatching(/could not reach SENTINEL/),
    });
  });

  it("explains a proxy error page instead of showing it", async () => {
    mockFetch(new Response("<html>Bad gateway</html>", { status: 502 }));
    await expect(api.system.providers()).rejects.toMatchObject({ code: "service_unavailable" });
  });

  it("sends the CSRF token on state-changing requests only", async () => {
    setCsrfToken("token-123");
    const fetchMock = mockFetch(jsonResponse({ items: [], total: 0, page: 1, page_size: 20 }));
    await api.scans.history({ type: "url", risk: "" });
    const [getUrl, getInit] = fetchMock.mock.calls[0]!;
    expect(getUrl).toBe("/api/v1/scans/history?type=url");
    expect((getInit!.headers as Record<string, string>)["X-CSRF-Token"]).toBeUndefined();

    const deleteMock = mockFetch(jsonResponse(null, 204));
    await api.scans.clearHistory();
    const [, deleteInit] = deleteMock.mock.calls[0]!;
    expect((deleteInit!.headers as Record<string, string>)["X-CSRF-Token"]).toBe("token-123");
  });

  it("encodes scan identifiers in the path", async () => {
    const fetchMock = mockFetch(jsonResponse({}, 404));
    await api.scans.get("../user/export").catch(() => undefined);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/v1/scans/..%2Fuser%2Fexport");
  });
});
