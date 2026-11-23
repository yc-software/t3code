import { assert, describe, it } from "@effect/vitest";

import {
  installMainWindowRemoteRequestHeaderPolicy,
  stripDesktopOriginHeaders,
  type MainWindowRequestHeaderPolicy,
} from "./RemoteRequestHeaders.ts";

const packagedPolicy: MainWindowRequestHeaderPolicy = {
  desktopOrigin: "t3code://app",
  mainWebContentsId: 42,
  clerkFrontendApiHostname: "clerk.t3.codes",
  isDevelopment: false,
};

const devPolicy: MainWindowRequestHeaderPolicy = {
  desktopOrigin: "t3code-dev://app",
  mainWebContentsId: 42,
  clerkFrontendApiHostname: "clerk.t3.codes",
  devServerOrigin: "http://devbox.internal:5733",
  isDevelopment: true,
};

describe("RemoteRequestHeaders", () => {
  it.each([
    "https://remote.example.com/.well-known/t3/environment",
    "http://127.0.0.1:8080/api/auth/bootstrap",
    "ws://127.0.0.1:8080/ws?ticket=abc",
    "wss://remote.example.com/ws?ticket=abc",
  ])("strips Origin and Sec-Fetch-* on outbound main-window %s requests", (url) => {
    const headers = stripDesktopOriginHeaders(packagedPolicy, {
      url,
      webContentsId: 42,
      frame: { parent: null },
      requestHeaders: {
        Origin: "t3code://app",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "sec-fetch-user": "?1",
        Authorization: "Bearer secret",
        DPoP: "proof-jwt",
      },
    });

    assert.deepEqual(headers, {
      Authorization: "Bearer secret",
      DPoP: "proof-jwt",
    });
  });

  it("strips lowercase origin headers and allows null frames (WebSocket upgrades and workers)", () => {
    const headers = stripDesktopOriginHeaders(packagedPolicy, {
      url: "wss://remote.example.com/ws",
      webContentsId: 42,
      frame: null,
      requestHeaders: {
        origin: "t3code://app",
        "Sec-Fetch-Site": "cross-site",
        Upgrade: "websocket",
      },
    });

    assert.deepEqual(headers, {
      Upgrade: "websocket",
    });
  });

  it("preserves headers for Clerk frontend API requests", () => {
    for (const url of ["https://clerk.t3.codes/v1/client", "https://CLERK.T3.CODES./v1/client"]) {
      const headers = stripDesktopOriginHeaders(packagedPolicy, {
        url,
        webContentsId: 42,
        frame: { parent: null },
        requestHeaders: {
          Origin: "t3code://app",
          "Sec-Fetch-Site": "cross-site",
        },
      });
      assert.isUndefined(headers);
    }
  });

  it("preserves headers for dev loopback and exact devServerOrigin, while stripping other ports and remote hosts", () => {
    for (const url of [
      "http://localhost:3773/api/health",
      "http://app.localhost:3773/api/health",
      "http://127.0.0.1:3773/api/health",
      "http://[::1]:3773/api/health",
      "ws://127.0.0.1:3773/ws",
      "http://devbox.internal:5733/api/health",
      "ws://devbox.internal:5733/ws",
    ]) {
      assert.isUndefined(
        stripDesktopOriginHeaders(devPolicy, {
          url,
          webContentsId: 42,
          frame: { parent: null },
          requestHeaders: {
            Origin: "t3code-dev://app",
            "Sec-Fetch-Site": "cross-site",
          },
        }),
      );
    }

    for (const url of [
      "http://devbox.internal:8080/api/auth/bootstrap",
      "https://remote.example.com/api/auth/bootstrap",
    ]) {
      assert.deepEqual(
        stripDesktopOriginHeaders(devPolicy, {
          url,
          webContentsId: 42,
          frame: { parent: null },
          requestHeaders: {
            Origin: "t3code-dev://app",
            "Sec-Fetch-Site": "cross-site",
            "Content-Type": "application/json",
          },
        }),
        { "Content-Type": "application/json" },
      );
    }
  });

  it("never touches sandboxed iframes (Origin: null), subframes, or other webContents", () => {
    assert.isUndefined(
      stripDesktopOriginHeaders(packagedPolicy, {
        url: "https://remote.example.com/api/test",
        webContentsId: 42,
        frame: { parent: null },
        requestHeaders: {
          Origin: "null",
          "Sec-Fetch-Site": "cross-site",
        },
      }),
    );

    assert.isUndefined(
      stripDesktopOriginHeaders(packagedPolicy, {
        url: "https://remote.example.com/api/test",
        webContentsId: 42,
        frame: { parent: {} },
        requestHeaders: {
          Origin: "t3code://app",
          "Sec-Fetch-Site": "cross-site",
        },
      }),
    );

    assert.isUndefined(
      stripDesktopOriginHeaders(packagedPolicy, {
        url: "https://remote.example.com/api/test",
        webContentsId: 99,
        frame: { parent: null },
        requestHeaders: {
          Origin: "t3code://app",
          "Sec-Fetch-Site": "cross-site",
        },
      }),
    );

    assert.isUndefined(
      stripDesktopOriginHeaders(packagedPolicy, {
        url: "https://remote.example.com/api/test",
        webContentsId: undefined,
        frame: null,
        requestHeaders: {
          Origin: "t3code://app",
          "Sec-Fetch-Site": "cross-site",
        },
      }),
    );

    assert.isUndefined(
      stripDesktopOriginHeaders(packagedPolicy, {
        url: "https://remote.example.com/api/test",
        webContentsId: 42,
        frame: { parent: null },
        requestHeaders: {
          "Sec-Fetch-Site": "cross-site",
        },
      }),
    );
  });

  it("adds headers only to the main window's own requests, after stripping Origin", async () => {
    type Listener = (
      details: {
        readonly id: number;
        readonly url: string;
        readonly webContentsId?: number;
        readonly frame?: { readonly parent: unknown } | null;
        readonly requestHeaders: Record<string, string>;
      },
      callback: (response: { readonly requestHeaders?: Record<string, string> }) => void,
    ) => void;
    let listener: Listener | undefined;
    const seen: Array<Record<string, string>> = [];
    const session = {
      webRequest: {
        onBeforeSendHeaders: (_filter: unknown, next: Listener | null) => {
          listener = next ?? undefined;
        },
      },
    } as unknown as Parameters<typeof installMainWindowRemoteRequestHeaderPolicy>[0];
    installMainWindowRemoteRequestHeaderPolicy(session, {
      ...packagedPolicy,
      addHeaders: async (request) => {
        seen.push(request.requestHeaders);
        return { ...request.requestHeaders, Cookie: "proxy=1" };
      },
    });
    const send = (details: Omit<Parameters<Listener>[0], "id" | "url" | "requestHeaders">) =>
      new Promise<Record<string, string> | undefined>((resolve) =>
        listener?.(
          {
            id: 1,
            url: "https://remote.example.com/api",
            requestHeaders: { Origin: "t3code://app" },
            ...details,
          },
          (response) => resolve(response.requestHeaders),
        ),
      );

    assert.deepStrictEqual(await send({ webContentsId: 42, frame: { parent: null } }), {
      Cookie: "proxy=1",
    });
    assert.deepStrictEqual(await send({ webContentsId: 42, frame: null }), { Cookie: "proxy=1" });
    assert.deepStrictEqual(seen, [{}, {}]);
    assert.strictEqual(await send({ webContentsId: 42, frame: { parent: {} } }), undefined);
    assert.strictEqual(await send({ webContentsId: 7, frame: { parent: null } }), undefined);
    assert.strictEqual(seen.length, 2);
  });
});
