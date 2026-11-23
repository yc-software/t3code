import { describe, expect, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as HttpServerRequest from "effect/http/HttpServerRequest";

import { makeProxyJwtVerifier, parseProxyJwtConfig, type ProxyJwtEnv } from "./ProxyIdentity.ts";
import {
  JWKS_URL,
  makeProxySigner,
  makeTestProxyIdentity,
  proxyConfig,
  staticKeyFetcher,
} from "./ProxyIdentity.testkit.ts";

const emptyEnv: ProxyJwtEnv = {
  cookieName: undefined,
  headerName: undefined,
  keysUrl: undefined,
  issuer: undefined,
  audience: undefined,
  signer: undefined,
  allowed: undefined,
};

const requestWith = (headers: Record<string, string>) =>
  HttpServerRequest.fromWeb(new Request("http://127.0.0.1/api/auth/session", { headers }));

describe("parseProxyJwtConfig", () => {
  it("stays off until a variable is set", () => {
    expect(parseProxyJwtConfig(emptyEnv)).toEqual({ _tag: "Disabled" });
  });

  it("refuses a partial configuration instead of trusting every token", () => {
    expect(parseProxyJwtConfig({ ...emptyEnv, cookieName: "CF_Authorization" })._tag).toBe(
      "Invalid",
    );
    expect(
      parseProxyJwtConfig({
        ...emptyEnv,
        cookieName: "CF_Authorization",
        keysUrl: "http://team.cloudflareaccess.com/cdn-cgi/access/certs",
        issuer: "https://team.cloudflareaccess.com",
        allowed: "a@example.com",
      })._tag,
    ).toBe("Invalid");
    expect(
      parseProxyJwtConfig({
        ...emptyEnv,
        headerName: "x-goog-iap-jwt-assertion",
        keysUrl: "https://www.gstatic.com/iap/verify/public_key-jwk",
        issuer: "https://cloud.google.com/iap",
      })._tag,
    ).toBe("Invalid");
  });

  it("reads each proxy's settings", () => {
    expect(
      parseProxyJwtConfig({
        ...emptyEnv,
        headerName: "X-Amzn-Oidc-Data",
        keysUrl: "https://public-keys.auth.elb.us-east-1.amazonaws.com/{kid}",
        issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc",
        signer: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/t3/abc",
        allowed: " Owner@Example.com , sub-123 ",
      }),
    ).toEqual({
      _tag: "Enabled",
      config: {
        headerName: "x-amzn-oidc-data",
        keysUrl: "https://public-keys.auth.elb.us-east-1.amazonaws.com/{kid}",
        issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc",
        signers: ["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/t3/abc"],
        allowed: ["owner@example.com", "sub-123"],
      },
    });
  });
});

describe("proxy JWT verification", () => {
  it.live("accepts an allowed email or subject from a JWKS-signed token", () =>
    Effect.gen(function* () {
      const signer = yield* Effect.promise(() => makeProxySigner("RS256"));
      const verifier = makeProxyJwtVerifier(
        proxyConfig({ allowed: ["owner@example.com", "service-123"] }),
        staticKeyFetcher({ [JWKS_URL]: JSON.stringify(signer.jwks) }),
      );
      const byEmail = yield* Effect.promise(() =>
        signer.sign({ email: "Owner@Example.com", sub: "other" }),
      );
      const bySubject = yield* Effect.promise(() => signer.sign({ sub: "service-123" }));
      expect(yield* verifier.verify(byEmail)).toBe("owner@example.com");
      expect(yield* verifier.verify(bySubject)).toBe("service-123");
    }),
  );

  it.live("rejects a token for another identity, issuer, audience, key, or time", () =>
    Effect.gen(function* () {
      const signer = yield* Effect.promise(() => makeProxySigner("RS256"));
      const stranger = yield* Effect.promise(() => makeProxySigner("RS256"));
      const verifier = makeProxyJwtVerifier(
        proxyConfig(),
        staticKeyFetcher({ [JWKS_URL]: JSON.stringify(signer.jwks) }),
      );
      const tokens = yield* Effect.promise(() =>
        Promise.all([
          signer.sign({ email: "intruder@example.com" }),
          signer.sign({ email: "owner@example.com" }, { issuer: "https://other.example.test" }),
          signer.sign({ email: "owner@example.com" }, { audience: "another-app" }),
          signer.sign({ email: "owner@example.com" }, { expiresIn: "-1m" }),
          stranger.sign({ email: "owner@example.com" }),
        ]),
      );
      for (const token of tokens) {
        const result = yield* verifier.verify(token).pipe(Effect.flip);
        expect(result._tag).toBe("ProxyIdentityError");
      }
    }),
  );

  it.live("loads one PEM key per key ID and checks the signer, as an AWS ALB sends them", () =>
    Effect.gen(function* () {
      const signer = yield* Effect.promise(() => makeProxySigner("ES256"));
      const calls: Array<string> = [];
      const arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/t3/abc";
      const verifier = makeProxyJwtVerifier(
        proxyConfig({ keysUrl: "https://keys.example.test/{kid}", signers: [`${arn}-other`, arn] }),
        staticKeyFetcher({ [`https://keys.example.test/${signer.kid}`]: signer.pem }, calls),
      );
      const signed = yield* Effect.promise(() =>
        signer.sign({ email: "owner@example.com" }, { header: { signer: arn } }),
      );
      const otherSigner = yield* Effect.promise(() =>
        signer.sign({ email: "owner@example.com" }, { header: { signer: `${arn}x` } }),
      );
      expect(yield* verifier.verify(signed)).toBe("owner@example.com");
      expect(yield* verifier.verify(signed)).toBe("owner@example.com");
      expect(calls).toEqual([`https://keys.example.test/${signer.kid}`]);
      expect((yield* verifier.verify(otherSigner).pipe(Effect.flip)).reason).toBe(
        "unexpected signer",
      );
    }),
  );

  it.live("reads the token from the configured header first, then the cookie", () =>
    Effect.gen(function* () {
      const signer = yield* Effect.promise(() => makeProxySigner("RS256"));
      const identity = makeTestProxyIdentity(signer);
      const token = yield* Effect.promise(() => signer.sign({ email: "owner@example.com" }));
      const fromCookie = yield* identity.identify(requestWith({ cookie: `proxy_jwt=${token}` }));
      const fromHeader = yield* identity.identify(requestWith({ "x-proxy-jwt": token }));
      const missing = yield* identity.identify(requestWith({ cookie: "other=1" }));
      const forged = yield* identity.identify(requestWith({ "x-proxy-jwt": `${token}x` }));
      expect(fromCookie).toEqual(Option.some("owner@example.com"));
      expect(fromHeader).toEqual(Option.some("owner@example.com"));
      expect(missing).toEqual(Option.none());
      expect(forged).toEqual(Option.none());
    }),
  );
});
