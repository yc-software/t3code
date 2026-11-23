import * as Effect from "effect/Effect";
import { exportJWK, exportSPKI, generateKeyPair, type JWTPayload, SignJWT } from "jose";

import type { ProxyJwtConfig } from "../config.ts";
import { makeProxyIdentity, type ProxyKeyFetcher } from "./ProxyIdentity.ts";

const PROXY_ISSUER = "https://proxy.example.test";
const PROXY_AUDIENCE = "t3-app";
export const JWKS_URL = "https://proxy.example.test/certs";

export const makeProxySigner = async (alg: "RS256" | "ES256" = "RS256") => {
  const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
  const kid = `key-${alg.toLowerCase()}`;
  const jwk = { ...(await exportJWK(publicKey)), kid, alg, use: "sig" };
  const pem = await exportSPKI(publicKey);
  const sign = (
    claims: JWTPayload,
    options?: {
      readonly issuer?: string;
      readonly audience?: string;
      readonly expiresIn?: string;
      readonly header?: Record<string, unknown>;
    },
  ) =>
    new SignJWT(claims)
      .setProtectedHeader({ alg, kid, ...options?.header })
      .setIssuer(options?.issuer ?? PROXY_ISSUER)
      .setAudience(options?.audience ?? PROXY_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime(options?.expiresIn ?? "5m")
      .sign(privateKey);
  return { kid, jwks: { keys: [jwk] }, pem, sign };
};

export type ProxySigner = Awaited<ReturnType<typeof makeProxySigner>>;

export const staticKeyFetcher =
  (bodies: Readonly<Record<string, string>>, calls?: Array<string>): ProxyKeyFetcher =>
  (url) => {
    calls?.push(url);
    const body = bodies[url];
    return body === undefined
      ? Effect.die(new Error(`Unexpected key URL ${url}`))
      : Effect.succeed({ body, maxAgeSeconds: 600 });
  };

export const proxyConfig = (overrides?: Partial<ProxyJwtConfig>): ProxyJwtConfig => ({
  cookieName: "proxy_jwt",
  headerName: "x-proxy-jwt",
  keysUrl: JWKS_URL,
  issuer: PROXY_ISSUER,
  audience: PROXY_AUDIENCE,
  allowed: ["owner@example.com"],
  ...overrides,
});

export const makeTestProxyIdentity = (signer: ProxySigner, overrides?: Partial<ProxyJwtConfig>) =>
  makeProxyIdentity(
    proxyConfig(overrides),
    staticKeyFetcher({ [JWKS_URL]: JSON.stringify(signer.jwks) }),
  );
