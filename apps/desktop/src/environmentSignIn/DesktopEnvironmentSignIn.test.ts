import { describe, expect, it } from "vite-plus/test";

import {
  environmentOrigin,
  isSignInResponse,
  mergeCookieHeader,
  parseSetCookie,
} from "./DesktopEnvironmentSignIn.ts";

const origin = "https://box.example.com";

describe("isSignInResponse", () => {
  it("treats a redirect to another origin or a bare 401/403 as the proxy asking for sign-in", () => {
    expect(
      isSignInResponse({
        origin,
        statusCode: 302,
        location: "https://auth.example.com/oauth2/authorize",
        allowOrigin: undefined,
      }),
    ).toBe(true);
    expect(
      isSignInResponse({ origin, statusCode: 401, location: undefined, allowOrigin: undefined }),
    ).toBe(true);
  });

  it("treats any 401 from the environment as an ended session", () => {
    expect(
      isSignInResponse({ origin, statusCode: 401, location: undefined, allowOrigin: "*" }),
    ).toBe(true);
  });

  it("leaves same-origin redirects and the environment's own 403s alone", () => {
    expect(
      isSignInResponse({ origin, statusCode: 302, location: "/pair", allowOrigin: undefined }),
    ).toBe(false);
    expect(
      isSignInResponse({ origin, statusCode: 403, location: undefined, allowOrigin: "*" }),
    ).toBe(false);
    expect(
      isSignInResponse({ origin, statusCode: 200, location: undefined, allowOrigin: undefined }),
    ).toBe(false);
  });
});

describe("parseSetCookie", () => {
  it("keeps the attributes a replaced session cookie needs", () => {
    expect(
      parseSetCookie(
        "t3_session_abc=token=1; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=60",
        1000,
      ),
    ).toEqual({
      name: "t3_session_abc",
      value: "token=1",
      path: "/",
      secure: true,
      httpOnly: true,
      sameSite: "lax",
      expirationDate: 1060,
      expired: false,
    });
  });

  it("marks a cleared cookie as expired", () => {
    expect(parseSetCookie("albsess=; Max-Age=0", 1000)?.expired).toBe(true);
    expect(parseSetCookie("no-equals-sign", 1000)).toBeNull();
  });
});

describe("environmentOrigin", () => {
  it("maps WebSocket URLs to the origin that holds their cookies", () => {
    expect(environmentOrigin("wss://box.example.com/ws?x=1")).toBe(origin);
    expect(environmentOrigin("t3code://app/")).toBeNull();
  });
});

describe("mergeCookieHeader", () => {
  it("keeps cookies the request already has", () => {
    expect(mergeCookieHeader("a=1", [{ name: "b", value: "2" }])).toBe("a=1; b=2");
    expect(mergeCookieHeader(undefined, [{ name: "b", value: "2" }])).toBe("b=2");
    expect(mergeCookieHeader("a=1", [])).toBe("a=1");
  });
});
