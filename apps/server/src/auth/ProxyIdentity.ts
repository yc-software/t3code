import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import { HttpClient, HttpClientRequest } from "effect/http";
import type * as HttpServerRequest from "effect/http/HttpServerRequest";
import {
  createLocalJWKSet,
  decodeProtectedHeader,
  type JSONWebKeySet,
  type JWTPayload,
  importSPKI,
  jwtVerify,
} from "jose";

import * as ServerConfig from "../config.ts";
import type { ProxyJwtConfig } from "../config.ts";

export const PROXY_SESSION_SUBJECT_PREFIX = "proxy:";
const KID_PLACEHOLDER = "{kid}";
const KID_PATTERN = /^[A-Za-z0-9._-]+$/;
const ALGORITHMS = ["RS256", "ES256", "PS256", "EdDSA"];
const DEFAULT_KEY_MAX_AGE_SECONDS = 600;
const MIN_REFETCH_INTERVAL_MS = 60_000;

export interface ProxyJwtEnv {
  readonly cookieName: string | undefined;
  readonly headerName: string | undefined;
  readonly keysUrl: string | undefined;
  readonly issuer: string | undefined;
  readonly audience: string | undefined;
  readonly signer: string | undefined;
  readonly allowed: string | undefined;
}

export type ProxyJwtConfigResult =
  | { readonly _tag: "Disabled" }
  | { readonly _tag: "Enabled"; readonly config: ProxyJwtConfig }
  | { readonly _tag: "Invalid"; readonly message: string };

const isHttpsUrl = (value: string) => {
  try {
    return new URL(value.replace(KID_PLACEHOLDER, "kid")).protocol === "https:";
  } catch {
    return false;
  }
};

export const parseProxyJwtConfig = (env: ProxyJwtEnv): ProxyJwtConfigResult => {
  const read = (value: string | undefined) => {
    const trimmed = value?.trim() ?? "";
    return trimmed === "" ? undefined : trimmed;
  };
  const cookieName = read(env.cookieName);
  const headerName = read(env.headerName)?.toLowerCase();
  const keysUrl = read(env.keysUrl);
  const issuer = read(env.issuer);
  const audience = read(env.audience);
  const signers = (env.signer ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  const allowed = (env.allowed ?? "")
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry.length > 0);
  if (
    [cookieName, headerName, keysUrl, issuer, audience].every((v) => v === undefined) &&
    signers.length === 0 &&
    allowed.length === 0
  ) {
    return { _tag: "Disabled" };
  }
  if (cookieName === undefined && headerName === undefined) {
    return {
      _tag: "Invalid",
      message: "Set T3CODE_PROXY_JWT_COOKIE or T3CODE_PROXY_JWT_HEADER to read the proxy JWT.",
    };
  }
  if (keysUrl === undefined || !isHttpsUrl(keysUrl)) {
    return {
      _tag: "Invalid",
      message:
        "T3CODE_PROXY_JWT_KEYS_URL must be an https JWKS URL, or an https URL with {kid} for one PEM key per key ID.",
    };
  }
  if (issuer === undefined) {
    return { _tag: "Invalid", message: "T3CODE_PROXY_JWT_ISSUER is required." };
  }
  if (allowed.length === 0) {
    return {
      _tag: "Invalid",
      message: "T3CODE_PROXY_JWT_ALLOWED must list one or more emails or subjects.",
    };
  }
  return {
    _tag: "Enabled",
    config: {
      ...(cookieName === undefined ? {} : { cookieName }),
      ...(headerName === undefined ? {} : { headerName }),
      keysUrl,
      issuer,
      ...(audience === undefined ? {} : { audience }),
      ...(signers.length === 0 ? {} : { signers }),
      allowed,
    },
  };
};

class ProxyIdentityError extends Schema.TaggedError<ProxyIdentityError>()("ProxyIdentityError", {
  reason: Schema.String,
}) {
  override get message(): string {
    return `Proxy identity verification failed: ${this.reason}.`;
  }
}

const isProxyIdentityError = Schema.is(ProxyIdentityError);

export interface FetchedKeys {
  readonly body: string;
  readonly maxAgeSeconds: number;
}

export type ProxyKeyFetcher = (url: string) => Effect.Effect<FetchedKeys, ProxyIdentityError>;

const parseMaxAgeSeconds = (cacheControl: string | undefined): number => {
  const match = /max-age=(\d+)/i.exec(cacheControl ?? "");
  return match?.[1] === undefined ? DEFAULT_KEY_MAX_AGE_SECONDS : Number.parseInt(match[1], 10);
};

const makeHttpKeyFetcher =
  (client: HttpClient.HttpClient): ProxyKeyFetcher =>
  (url) =>
    Effect.gen(function* () {
      const response = yield* client.execute(HttpClientRequest.get(url));
      if (response.status !== 200) {
        return yield* new ProxyIdentityError({ reason: `key fetch returned ${response.status}` });
      }
      return {
        body: yield* response.text,
        maxAgeSeconds: parseMaxAgeSeconds(response.headers["cache-control"]),
      };
    }).pipe(
      Effect.timeout("5 seconds"),
      Effect.mapError((cause) =>
        isProxyIdentityError(cause)
          ? cause
          : new ProxyIdentityError({ reason: "key fetch failed" }),
      ),
    );

type PemKey = Awaited<ReturnType<typeof importSPKI>>;
type KeySet = ReturnType<typeof createLocalJWKSet>;
const decodeJson = Schema.decodeUnknownEffect(Schema.fromJsonString(Schema.Unknown));

const matchAllowedIdentity = (
  payload: JWTPayload,
  allowed: ReadonlySet<string>,
): string | undefined => {
  for (const claim of [payload["email"], payload.sub]) {
    if (typeof claim === "string" && allowed.has(claim.toLowerCase())) return claim.toLowerCase();
  }
  return undefined;
};

export const makeProxyJwtVerifier = (config: ProxyJwtConfig, fetchKeys: ProxyKeyFetcher) => {
  const allowed = new Set(config.allowed);
  const perKid = config.keysUrl.includes(KID_PLACEHOLDER);
  const pemKeys = new Map<string, { readonly key: PemKey; readonly expiresAtMs: number }>();
  let jwks:
    | {
        readonly keys: ReturnType<typeof createLocalJWKSet>;
        readonly fetchedAtMs: number;
        readonly expiresAtMs: number;
      }
    | undefined;

  const loadJwks = Effect.fn("ProxyIdentity.loadJwks")(function* (force: boolean) {
    const now = yield* Clock.currentTimeMillis;
    if (
      jwks !== undefined &&
      (force ? now - jwks.fetchedAtMs < MIN_REFETCH_INTERVAL_MS : now < jwks.expiresAtMs)
    ) {
      return jwks.keys;
    }
    const fetched = yield* fetchKeys(config.keysUrl);
    const parsed = yield* decodeJson(fetched.body).pipe(
      Effect.mapError(() => new ProxyIdentityError({ reason: "invalid key set" })),
    );
    const keys = yield* Effect.try({
      try: () => createLocalJWKSet(parsed as JSONWebKeySet),
      catch: () => new ProxyIdentityError({ reason: "invalid key set" }),
    });
    jwks = { keys, fetchedAtMs: now, expiresAtMs: now + fetched.maxAgeSeconds * 1000 };
    return keys;
  });

  const loadPemKey = Effect.fn("ProxyIdentity.loadPemKey")(function* (kid: string, alg: string) {
    const now = yield* Clock.currentTimeMillis;
    const cached = pemKeys.get(kid);
    if (cached !== undefined && now < cached.expiresAtMs) return cached.key;
    const fetched = yield* fetchKeys(config.keysUrl.replace(KID_PLACEHOLDER, kid));
    const key = yield* Effect.tryPromise({
      try: () => importSPKI(fetched.body, alg),
      catch: () => new ProxyIdentityError({ reason: "invalid public key" }),
    });
    pemKeys.set(kid, { key, expiresAtMs: now + fetched.maxAgeSeconds * 1000 });
    return key;
  });

  const verifyWith = (token: string, key: PemKey | KeySet) =>
    DateTime.now.pipe(
      Effect.flatMap((now) =>
        Effect.tryPromise({
          try: () => {
            const options = {
              algorithms: ALGORITHMS,
              issuer: config.issuer,
              ...(config.audience === undefined ? {} : { audience: config.audience }),
              currentDate: DateTime.toDate(now),
            };
            return typeof key === "function"
              ? jwtVerify(token, key, options)
              : jwtVerify(token, key, options);
          },
          catch: (cause) =>
            new ProxyIdentityError({
              reason:
                typeof cause === "object" && cause !== null && "code" in cause
                  ? String(cause.code)
                  : "invalid token",
            }),
        }),
      ),
    );

  const verify = Effect.fn("ProxyIdentity.verify")(function* (token: string) {
    const header = yield* Effect.try({
      try: () => decodeProtectedHeader(token),
      catch: () => new ProxyIdentityError({ reason: "malformed token" }),
    });
    if (
      config.signers !== undefined &&
      (typeof header["signer"] !== "string" || !config.signers.includes(header["signer"]))
    ) {
      return yield* new ProxyIdentityError({ reason: "unexpected signer" });
    }
    if (typeof header.alg !== "string" || !ALGORITHMS.includes(header.alg)) {
      return yield* new ProxyIdentityError({ reason: "unexpected algorithm" });
    }
    let verified: { readonly payload: JWTPayload };
    if (perKid) {
      const kid = header.kid;
      if (typeof kid !== "string" || !KID_PATTERN.test(kid)) {
        return yield* new ProxyIdentityError({ reason: "invalid key id" });
      }
      verified = yield* verifyWith(token, yield* loadPemKey(kid, header.alg));
    } else {
      verified = yield* verifyWith(token, yield* loadJwks(false)).pipe(
        Effect.catchIf(
          (error) => error.reason === "ERR_JWKS_NO_MATCHING_KEY",
          () => loadJwks(true).pipe(Effect.flatMap((keys) => verifyWith(token, keys))),
        ),
      );
    }
    const identity = matchAllowedIdentity(verified.payload, allowed);
    if (identity === undefined) {
      return yield* new ProxyIdentityError({ reason: "identity not allowed" });
    }
    return identity;
  });

  return { verify };
};

const readProxyJwt = (
  request: HttpServerRequest.HttpServerRequest,
  config: Pick<ProxyJwtConfig, "cookieName" | "headerName">,
): string | undefined => {
  const fromHeader =
    config.headerName === undefined ? undefined : request.headers[config.headerName];
  if (typeof fromHeader === "string" && fromHeader.trim() !== "") {
    return fromHeader.trim().replace(/^Bearer\s+/i, "");
  }
  const fromCookie =
    config.cookieName === undefined ? undefined : request.cookies[config.cookieName];
  return typeof fromCookie === "string" && fromCookie !== "" ? fromCookie : undefined;
};

export class ProxyIdentity extends Context.Service<
  ProxyIdentity,
  {
    readonly identify: (
      request: HttpServerRequest.HttpServerRequest,
    ) => Effect.Effect<Option.Option<string>>;
  }
>()("t3/auth/ProxyIdentity") {}

export const proxySessionSubject = (identity: string) =>
  `${PROXY_SESSION_SUBJECT_PREFIX}${identity}`;

export const makeProxyIdentity = (
  config: ProxyJwtConfig,
  fetchKeys: ProxyKeyFetcher,
): ProxyIdentity["Service"] => {
  const verifier = makeProxyJwtVerifier(config, fetchKeys);
  return ProxyIdentity.of({
    identify: Effect.fn("ProxyIdentity.identify")(function* (request) {
      const token = readProxyJwt(request, config);
      if (token === undefined) return Option.none<string>();
      return yield* verifier.verify(token).pipe(
        Effect.asSome,
        Effect.catch((error) =>
          Effect.logWarning("Rejected a proxy JWT.").pipe(
            Effect.annotateLogs({ reason: error.reason }),
            Effect.as(Option.none<string>()),
          ),
        ),
      );
    }),
  });
};

export const layer = Layer.effect(
  ProxyIdentity,
  Effect.gen(function* () {
    const config = yield* ServerConfig.ServerConfig;
    if (config.proxyJwt === undefined) {
      return ProxyIdentity.of({
        identify: Effect.fn("ProxyIdentity.identify")(() => Effect.succeedNone),
      });
    }
    const client = yield* HttpClient.HttpClient;
    return makeProxyIdentity(config.proxyJwt, makeHttpKeyFetcher(client));
  }),
);
