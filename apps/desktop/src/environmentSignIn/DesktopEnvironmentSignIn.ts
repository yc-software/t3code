import type { HeadersReceivedResponse, OnHeadersReceivedListenerDetails, Session } from "electron";
import { BrowserWindow, net, session as electronSession } from "electron";
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Fiber from "effect/Fiber";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Schedule from "effect/Schedule";
import * as Schema from "effect/Schema";
import type * as Scope from "effect/Scope";

import * as ElectronWindow from "../electron/ElectronWindow.ts";
import { ENVIRONMENT_SIGN_IN_REQUIRED_CHANNEL } from "../ipc/channels.ts";

const ENVIRONMENT_SIGN_IN_PARTITION = "persist:t3code-environment-sign-in";
const SESSION_PATH = "/api/auth/session";
const SESSION_POLL_MS = 1_500;
const NETWORK_URL_PATTERNS = ["http://*/*", "https://*/*", "ws://*/*", "wss://*/*"];

export const DesktopEnvironmentSignInResult = Schema.Literals(["ready", "cancelled"]);
export type DesktopEnvironmentSignInResult = typeof DesktopEnvironmentSignInResult.Type;

export class DesktopEnvironmentSignInError extends Schema.TaggedError<DesktopEnvironmentSignInError>()(
  "DesktopEnvironmentSignInError",
  {
    origin: Schema.String,
    cause: Schema.Defect(),
  },
) {
  override get message(): string {
    return `Could not sign in to ${this.origin}.`;
  }
}

export class DesktopEnvironmentSignIn extends Context.Service<
  DesktopEnvironmentSignIn,
  {
    readonly install: Effect.Effect<void, never, Scope.Scope>;
    readonly addCookies: (request: {
      readonly id: number;
      readonly url: string;
      readonly requestHeaders: Record<string, string>;
    }) => Promise<Record<string, string> | undefined>;
    readonly signIn: (
      httpBaseUrl: string,
    ) => Effect.Effect<DesktopEnvironmentSignInResult, DesktopEnvironmentSignInError>;
  }
>()("@t3tools/desktop/environmentSignIn/DesktopEnvironmentSignIn") {}

export function environmentOrigin(url: string): string | null {
  try {
    const parsed = new URL(url);
    const protocol =
      parsed.protocol === "ws:" ? "http:" : parsed.protocol === "wss:" ? "https:" : parsed.protocol;
    if (protocol !== "http:" && protocol !== "https:") return null;
    return `${protocol}//${parsed.host}`;
  } catch {
    return null;
  }
}

function findHeader<T>(
  headers: Readonly<Record<string, T>> | undefined,
  name: string,
): T | undefined {
  if (headers === undefined) return undefined;
  const key = Object.keys(headers).find((candidate) => candidate.toLowerCase() === name);
  return key === undefined ? undefined : headers[key];
}

export function mergeCookieHeader(
  existing: string | undefined,
  cookies: ReadonlyArray<{ readonly name: string; readonly value: string }>,
): string | undefined {
  if (cookies.length === 0) return existing;
  const added = cookies.map(({ name, value }) => `${name}=${value}`).join("; ");
  return existing === undefined || existing.trim() === "" ? added : `${existing}; ${added}`;
}

export function isSignInResponse(input: {
  readonly origin: string;
  readonly statusCode: number;
  readonly location: string | undefined;
  readonly allowOrigin: string | undefined;
}): boolean {
  if (input.statusCode >= 300 && input.statusCode < 400) {
    if (input.location === undefined) return false;
    try {
      return environmentOrigin(new URL(input.location, input.origin).href) !== input.origin;
    } catch {
      return false;
    }
  }
  if (input.statusCode === 401) return true;
  return input.statusCode === 403 && input.allowOrigin === undefined;
}

export interface ParsedSetCookie {
  readonly name: string;
  readonly value: string;
  readonly path?: string;
  readonly domain?: string;
  readonly secure: boolean;
  readonly httpOnly: boolean;
  readonly sameSite?: "lax" | "strict" | "no_restriction";
  readonly expirationDate?: number;
  readonly expired: boolean;
}

export function parseSetCookie(header: string, nowSeconds: number): ParsedSetCookie | null {
  const [pair, ...attributes] = header.split(";");
  const separator = pair?.indexOf("=") ?? -1;
  if (pair === undefined || separator <= 0) return null;
  let path: string | undefined;
  let domain: string | undefined;
  let secure = false;
  let httpOnly = false;
  let sameSite: ParsedSetCookie["sameSite"];
  let expirationDate: number | undefined;
  let maxAge: number | undefined;
  for (const attribute of attributes) {
    const [rawKey = "", ...rest] = attribute.split("=");
    const key = rawKey.trim().toLowerCase();
    const value = rest.join("=").trim();
    if (key === "path") path = value;
    else if (key === "domain") domain = value;
    else if (key === "secure") secure = true;
    else if (key === "httponly") httpOnly = true;
    else if (key === "samesite") {
      const lowered = value.toLowerCase();
      sameSite = lowered === "none" ? "no_restriction" : lowered === "strict" ? "strict" : "lax";
    } else if (key === "max-age" && value !== "" && !Number.isNaN(Number(value))) {
      maxAge = Number(value);
    } else if (key === "expires") {
      const parsed = Date.parse(value);
      if (!Number.isNaN(parsed)) expirationDate = parsed / 1000;
    }
  }
  if (maxAge !== undefined) expirationDate = nowSeconds + maxAge;
  return {
    name: pair.slice(0, separator).trim(),
    value: pair.slice(separator + 1).trim(),
    ...(path === undefined ? {} : { path }),
    ...(domain === undefined ? {} : { domain }),
    secure,
    httpOnly,
    ...(sameSite === undefined ? {} : { sameSite }),
    ...(expirationDate === undefined ? {} : { expirationDate }),
    expired: expirationDate !== undefined && expirationDate <= nowSeconds,
  };
}

const hasSession = (signInSession: Session, origin: string) =>
  new Promise<boolean>((resolve) => {
    const request = net.request({
      url: `${origin}${SESSION_PATH}`,
      session: signInSession,
      useSessionCookies: true,
      redirect: "manual",
    });
    request.on("redirect", () => {
      request.abort();
      resolve(false);
    });
    request.on("response", (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        try {
          const body: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          resolve(
            typeof body === "object" &&
              body !== null &&
              "authenticated" in body &&
              body.authenticated === true,
          );
        } catch {
          resolve(false);
        }
      });
      response.on("error", () => resolve(false));
    });
    request.on("error", () => resolve(false));
    request.end();
  });

const make = Effect.gen(function* () {
  const electronWindow = yield* ElectronWindow.ElectronWindow;
  const signInSession = () => electronSession.fromPartition(ENVIRONMENT_SIGN_IN_PARTITION);
  const injectedRequests = new Set<number>();
  const reportedOrigins = new Set<string>();
  const pendingSignIns = new Map<string, Promise<DesktopEnvironmentSignInResult>>();
  const context = yield* Effect.context<never>();
  const runFork = Effect.runForkWith(context);
  const runPromise = Effect.runPromiseWith(context);
  const runSync = Effect.runSyncWith(context);

  const storeResponseCookies = (origin: string, headers: ReadonlyArray<string>) => {
    const cookies = signInSession().cookies;
    const nowSeconds = runSync(Clock.currentTimeMillis) / 1000;
    for (const header of headers) {
      const parsed = parseSetCookie(header, nowSeconds);
      if (parsed === null) continue;
      const write = parsed.expired
        ? cookies.remove(origin, parsed.name)
        : cookies.set({
            url: origin,
            name: parsed.name,
            value: parsed.value,
            secure: parsed.secure,
            httpOnly: parsed.httpOnly,
            ...(parsed.path === undefined ? {} : { path: parsed.path }),
            ...(parsed.domain === undefined ? {} : { domain: parsed.domain }),
            ...(parsed.sameSite === undefined ? {} : { sameSite: parsed.sameSite }),
            ...(parsed.expirationDate === undefined
              ? {}
              : { expirationDate: parsed.expirationDate }),
          });
      void write.catch(() => undefined);
    }
  };

  const addCookies: DesktopEnvironmentSignIn["Service"]["addCookies"] = async (request) => {
    const origin = environmentOrigin(request.url);
    if (origin === null) return undefined;
    const cookies = await signInSession()
      .cookies.get({ url: `${origin}${new URL(request.url).pathname}` })
      .catch(() => []);
    if (cookies.length === 0) return undefined;
    injectedRequests.add(request.id);
    const cookieHeaderName =
      Object.keys(request.requestHeaders).find((name) => name.toLowerCase() === "cookie") ??
      "Cookie";
    const cookie = mergeCookieHeader(request.requestHeaders[cookieHeaderName], cookies);
    return cookie === undefined
      ? undefined
      : { ...request.requestHeaders, [cookieHeaderName]: cookie };
  };

  const onHeadersReceived = (
    details: OnHeadersReceivedListenerDetails,
    callback: (response: HeadersReceivedResponse) => void,
  ) => {
    callback({});
    if (!injectedRequests.delete(details.id)) return;
    const origin = environmentOrigin(details.url);
    if (origin === null) return;
    storeResponseCookies(origin, findHeader(details.responseHeaders, "set-cookie") ?? []);
    const location = findHeader(details.responseHeaders, "location")?.[0];
    const allowOrigin = findHeader(details.responseHeaders, "access-control-allow-origin")?.[0];
    if (!isSignInResponse({ origin, statusCode: details.statusCode, location, allowOrigin })) {
      return;
    }
    if (reportedOrigins.has(origin)) return;
    reportedOrigins.add(origin);
    runFork(electronWindow.sendAll(ENVIRONMENT_SIGN_IN_REQUIRED_CHANNEL, origin));
  };

  const install = Effect.acquireRelease(
    Effect.sync(() => {
      const { webRequest } = electronSession.defaultSession;
      webRequest.onHeadersReceived({ urls: NETWORK_URL_PATTERNS }, onHeadersReceived);
      webRequest.onErrorOccurred({ urls: NETWORK_URL_PATTERNS }, (details) => {
        injectedRequests.delete(details.id);
      });
      return webRequest;
    }),
    (webRequest) =>
      Effect.sync(() => {
        webRequest.onHeadersReceived(null);
        webRequest.onErrorOccurred(null);
      }),
  ).pipe(Effect.asVoid);

  const openSignInWindow = (origin: string, parent: Option.Option<BrowserWindow>) =>
    new Promise<DesktopEnvironmentSignInResult>((resolve) => {
      const window = new BrowserWindow({
        width: 520,
        height: 720,
        title: origin,
        autoHideMenuBar: true,
        ...(Option.isSome(parent) ? { parent: parent.value, modal: false } : {}),
        webPreferences: {
          partition: ENVIRONMENT_SIGN_IN_PARTITION,
          sandbox: true,
          contextIsolation: true,
          nodeIntegration: false,
        },
      });
      let settled = false;
      let checking = false;
      const settle = (result: DesktopEnvironmentSignInResult) => {
        if (settled) return;
        settled = true;
        runFork(Fiber.interrupt(poll));
        resolve(result);
        if (!window.isDestroyed()) window.close();
      };
      const check = () => {
        if (settled || checking || window.isDestroyed()) return;
        if (environmentOrigin(window.webContents.getURL()) !== origin) return;
        checking = true;
        void hasSession(signInSession(), origin).then((signedIn) => {
          checking = false;
          if (signedIn) settle("ready");
        });
      };
      const poll = runFork(
        Effect.sync(check).pipe(Effect.repeat(Schedule.spaced(SESSION_POLL_MS))),
      );
      window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
      window.webContents.on("did-finish-load", check);
      window.on("closed", () => settle("cancelled"));
      void window.loadURL(`${origin}/`).catch(() => undefined);
    });

  const runSignIn = (origin: string) => {
    const pending = pendingSignIns.get(origin);
    if (pending !== undefined) return pending;
    const started = runPromise(electronWindow.main).then(async (parent) => {
      const result = await openSignInWindow(origin, parent);
      if (result === "ready") reportedOrigins.delete(origin);
      return result;
    });
    const tracked = started.finally(() => pendingSignIns.delete(origin));
    pendingSignIns.set(origin, tracked);
    return tracked;
  };

  const resolveOrigin = (httpBaseUrl: string) =>
    Effect.suspend(() => {
      const origin = environmentOrigin(httpBaseUrl);
      return origin === null
        ? Effect.fail(
            new DesktopEnvironmentSignInError({
              origin: httpBaseUrl,
              cause: new Error("Not an HTTP URL."),
            }),
          )
        : Effect.succeed(origin);
    });

  const signIn: DesktopEnvironmentSignIn["Service"]["signIn"] = (httpBaseUrl) =>
    resolveOrigin(httpBaseUrl).pipe(
      Effect.flatMap((origin) =>
        Effect.tryPromise({
          try: () => runSignIn(origin),
          catch: (cause) => new DesktopEnvironmentSignInError({ origin, cause }),
        }),
      ),
      Effect.withSpan("DesktopEnvironmentSignIn.signIn"),
    );

  return DesktopEnvironmentSignIn.of({ install, addCookies, signIn });
});

export const layer = Layer.effect(DesktopEnvironmentSignIn, make);
