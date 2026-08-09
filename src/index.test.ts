import { createPrivateKey, createPublicKey, verify } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  createVallumAdmissionHandler,
  issueVallumAdmission,
  parseVallumAdmissionRequest,
  type VallumAdmissionConfiguration,
} from "./index.js";

const seed = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
const requestBody = {
  session: "session_0123456789abcdef",
  public_key: { kty: "RSA", n: Buffer.alloc(256, 7).toString("base64url"), e: "AQAB", alg: "RSA-OAEP-256", ext: true },
  proof_key: { kty: "EC", crv: "P-256", x: Buffer.alloc(32, 8).toString("base64url"), y: Buffer.alloc(32, 9).toString("base64url"), ext: true },
};
const configuration: VallumAdmissionConfiguration = {
  privateKey: seed.toString("base64url"),
  keyId: "primary",
  issuer: "northstar-web",
  audience: "northstar:production",
  applicationId: "northstar-production",
  environment: "production",
  scopes: ["route:internal-api"],
  ttlSeconds: 30,
};

function request(body: unknown = requestBody, headers: HeadersInit = {}): Request {
  return new Request("https://app.example.com/.well-known/vallum/admission", {
    method: "POST",
    headers: { Origin: "https://app.example.com", "Sec-Fetch-Site": "same-origin", "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

describe("@vallum/admission", () => {
  it("fails fast when a browser build resolves the server package", async () => {
    await expect(import("./browser.js")).rejects.toThrow("server-only");
  });

  it("issues a deterministic, proof-bound Ed25519 grant", () => {
    const parsed = parseVallumAdmissionRequest(requestBody);
    const issued = issueVallumAdmission(parsed, configuration, {
      subject: "user_123",
      scopes: ["route:account"],
      now: new Date("2026-08-08T12:00:00.000Z"),
      tokenId: Buffer.alloc(18, 10),
    });
    const [header, payload, signature] = issued.admission.split(".") as [string, string, string];
    expect(JSON.parse(Buffer.from(payload, "base64url").toString())).toMatchObject({
      sub: "user_123",
      sid: parsed.session,
      scp: ["route:account"],
      exp: 1_786_190_430,
    });
    const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
    const publicKey = createPublicKey(createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" }));
    expect(verify(null, Buffer.from(`${header}.${payload}`), publicKey, Buffer.from(signature, "base64url"))).toBe(true);
  });

  it("serves a bounded, authenticated, rate-limited Fetch API route", async () => {
    const authenticate = vi.fn().mockResolvedValue({ subject: "user_123" });
    const rateLimit = vi.fn().mockResolvedValue({ allowed: true });
    const handler = createVallumAdmissionHandler({ authenticate, rateLimit, configuration });
    const response = await handler(request());

    expect(response.status).toBe(201);
    expect(response.headers.get("Cache-Control")).toContain("no-store");
    expect((await response.json() as { admission: string }).admission.split(".")).toHaveLength(3);
    expect(authenticate).toHaveBeenCalledOnce();
    expect(rateLimit).toHaveBeenCalledOnce();
  });

  it("rejects cross-origin, unauthenticated, and exhausted requests", async () => {
    const allowed = createVallumAdmissionHandler({
      authenticate: async () => ({ subject: "user_123" }),
      rateLimit: async () => ({ allowed: true }),
      configuration,
    });
    const crossOrigin = request(requestBody, { Origin: "https://attacker.example" });
    expect((await allowed(crossOrigin)).status).toBe(403);

    const anonymous = createVallumAdmissionHandler({
      authenticate: async () => null,
      rateLimit: async () => ({ allowed: true }),
      configuration,
    });
    expect((await anonymous(request())).status).toBe(401);

    const limited = createVallumAdmissionHandler({
      authenticate: async () => ({ subject: "user_123" }),
      rateLimit: async () => ({ allowed: false, retryAfterSeconds: 9 }),
      configuration,
    });
    const response = await limited(request());
    expect(response.status).toBe(429);
    expect(response.headers.get("Retry-After")).toBe("9");
  });

  it("requires the exact JSON media type while accepting parameters", async () => {
    const handler = createVallumAdmissionHandler({
      authenticate: async () => ({ subject: "user_123" }),
      rateLimit: async () => ({ allowed: true }),
      configuration,
    });

    expect((await handler(request(requestBody, {
      "Content-Type": "application/jsonp",
    }))).status).toBe(415);
    expect((await handler(request(requestBody, {
      "Content-Type": "application/json; charset=utf-8",
    }))).status).toBe(201);
  });

  it("rejects malformed keys and oversized bodies without signing", async () => {
    expect(() => parseVallumAdmissionRequest({ ...requestBody, public_key: { kty: "RSA", n: "AA", e: "AQAB" } })).toThrow();
    const handler = createVallumAdmissionHandler({
      authenticate: async () => ({ subject: "user_123" }),
      rateLimit: async () => ({ allowed: true }),
      configuration,
      maxBodyBytes: 8,
    });
    expect((await handler(request())).status).toBe(413);
  });

  it("stops reading a chunked body as soon as the byte limit is crossed", async () => {
    let pulls = 0;
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        controller.enqueue(new Uint8Array(6));
        if (pulls >= 100) controller.close();
      },
      cancel() {
        cancelled = true;
      },
    });
    const streamed = new Request("https://app.example.com/.well-known/vallum/admission", {
      method: "POST",
      headers: {
        Origin: "https://app.example.com",
        "Sec-Fetch-Site": "same-origin",
        "Content-Type": "application/json",
      },
      body,
      duplex: "half",
    } as RequestInit & { duplex: "half" });
    const handler = createVallumAdmissionHandler({
      authenticate: async () => ({ subject: "user_123" }),
      rateLimit: async () => ({ allowed: true }),
      configuration,
      maxBodyBytes: 8,
    });

    expect((await handler(streamed)).status).toBe(413);
    expect(cancelled).toBe(true);
    expect(pulls).toBeLessThan(100);
  });

  it("returns a generic failure even when the error observer throws", async () => {
    const handler = createVallumAdmissionHandler({
      authenticate: async () => ({ subject: "user_123" }),
      rateLimit: async () => ({ allowed: true }),
      configuration: async () => { throw new Error("signer offline"); },
      onError: () => { throw new Error("logger offline"); },
    });

    const response = await handler(request());
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "admission issuer unavailable" });
  });
});
