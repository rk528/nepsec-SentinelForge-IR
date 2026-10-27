import { describe, expect, it } from "vitest";

import { buildQuery } from "./api";
import { formatBytes, formatMinutes, plural, relativeTime } from "./format";
import { safeNext } from "./navigation";

describe("safeNext (open-redirect guard)", () => {
  it.each([
    ["/incidents/abc", "/incidents/abc"],
    ["/alerts?status=new", "/alerts?status=new"],
    [null, "/dashboard"],
    ["https://evil.example/", "/dashboard"],
    ["//evil.example", "/dashboard"],
    ["/\\evil.example", "/dashboard"],
    ["javascript:alert(1)", "/dashboard"],
    ["/ok\r\nSet-Cookie: x", "/dashboard"],
  ])("%s -> %s", (input, expected) => {
    expect(safeNext(input)).toBe(expected);
  });
});

describe("buildQuery", () => {
  it("encodes arrays, skips empty values and escapes input", () => {
    expect(buildQuery({ status: ["new", "open"], q: "a&b=c", page: 2, empty: "", nothing: undefined })).toBe("?status=new&status=open&q=a%26b%3Dc&page=2");
    expect(buildQuery({})).toBe("");
  });
});

describe("formatting", () => {
  it("never fabricates a duration", () => {
    expect(formatMinutes(null)).toBe("No data");
    expect(formatMinutes(42)).toBe("42m");
    expect(formatMinutes(185)).toBe("3h 5m");
  });
  it("formats bytes and plurals", () => {
    expect(formatBytes(251_658_240)).toBe("240.0 MiB");
    expect(plural(1, "alert")).toBe("1 alert");
    expect(plural(3, "alert")).toBe("3 alerts");
  });
  it("describes relative time", () => {
    const now = Date.parse("2026-01-01T12:00:00Z");
    expect(relativeTime("2026-01-01T11:30:00Z", now)).toBe("30m ago");
    expect(relativeTime("2026-01-01T09:00:00Z", now)).toBe("3h ago");
  });
});
