import { createHash, createPrivateKey, randomBytes, sign } from "node:crypto";

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const ED25519_PKCS8_SEED_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const DEFAULT_MAX_BODY_BYTES = 32 * 1024;

export type VallumAdmissionRequest = {
  session: string;
  public_key: { kty: "RSA"; n: string; e: string };
  proof_key: { kty: "EC"; crv: "P-256"; x: string; y: string };
};

export type VallumAdmissionConfiguration = {
  privateKey: string;
  keyId: string;
  issuer: string;
  audience: string;
  applicationId: string;
  environment: string;
  scopes: readonly string[];
  ttlSeconds: number;
};

export type VallumAdmissionContext = {
  subject: string;
  scopes?: readonly string[];
  now?: Date;
  tokenId?: Uint8Array;
};

export type VallumAdmissionPrincipal = {
  /** Stable, server-derived application identity. Never accept this from the request body. */
  subject: string;
  /** Optional route scopes derived from the application's authorization state. */
  scopes?: readonly string[];
};

export type VallumAdmissionRateLimit = {
  allowed: boolean;
  retryAfterSeconds?: number;
};

export type VallumAdmissionHandlerOptions = {
  /** Authenticate the ordinary application session and return its server-derived principal. */
  authenticate(request: Request): VallumAdmissionPrincipal | null | Promise<VallumAdmissionPrincipal | null>;
  /**
   * Enforce a shared issuance budget before a grant is signed. Production
   * deployments should use an atomic shared store, not process-local memory.
   */
  rateLimit(
    request: Request,
    principal: VallumAdmissionPrincipal,
  ): VallumAdmissionRateLimit | Promise<VallumAdmissionRateLimit>;
  configuration:
    | VallumAdmissionConfiguration
    | (() => VallumAdmissionConfiguration | Promise<VallumAdmissionConfiguration>);
  maxBodyBytes?: number;
  /** Additional origin policy evaluated after the built-in strict same-origin check. */
  allowOrigin?(origin: URL, requestURL: URL, request: Request): boolean | Promise<boolean>;
  onError?(error: unknown): void;
};

type RawObject = Record<string, unknown>;

class AdmissionBodyTooLargeError extends Error {}

export class VallumAdmissionError extends Error {
  readonly category: "configuration" | "invalid_request";

  constructor(category: "configuration" | "invalid_request", message: string) {
    super(message);
    this.name = "VallumAdmissionError";
    this.category = category;
  }
}

function isObject(value: unknown): value is RawObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: RawObject, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function decodeBase64Url(value: string, expectedBytes?: number): Buffer {
  if (!value || !BASE64URL_PATTERN.test(value)) {
    throw new VallumAdmissionError("invalid_request", "invalid base64url value");
  }
  const decoded = Buffer.from(value, "base64url");
  if (!decoded.length || decoded.toString("base64url") !== value || (expectedBytes && decoded.length !== expectedBytes)) {
    throw new VallumAdmissionError("invalid_request", "invalid base64url value");
  }
  return decoded;
}

export function parseVallumAdmissionRequest(value: unknown): VallumAdmissionRequest {
  if (!isObject(value) || !hasOnlyKeys(value, ["session", "public_key", "proof_key"])) {
    throw new VallumAdmissionError("invalid_request", "invalid admission request");
  }
  if (typeof value.session !== "string" || value.session.length < 8 || value.session.length > 256 || !BASE64URL_PATTERN.test(value.session)) {
    throw new VallumAdmissionError("invalid_request", "invalid Vallum session");
  }
  if (!isObject(value.public_key) || !hasOnlyKeys(value.public_key, ["kty", "n", "e", "alg", "use", "key_ops", "ext"])) {
    throw new VallumAdmissionError("invalid_request", "invalid RSA public key");
  }
  if (value.public_key.kty !== "RSA" || typeof value.public_key.n !== "string" || typeof value.public_key.e !== "string") {
    throw new VallumAdmissionError("invalid_request", "invalid RSA public key");
  }
  const modulus = decodeBase64Url(value.public_key.n);
  const exponent = decodeBase64Url(value.public_key.e);
  if (modulus.length < 256 || modulus.length > 1024 || !["Aw", "AQAB"].includes(exponent.toString("base64url"))) {
    throw new VallumAdmissionError("invalid_request", "unsupported RSA public key");
  }
  if (!isObject(value.proof_key) || !hasOnlyKeys(value.proof_key, ["kty", "crv", "x", "y", "alg", "use", "key_ops", "ext"])) {
    throw new VallumAdmissionError("invalid_request", "invalid proof public key");
  }
  if (value.proof_key.kty !== "EC" || value.proof_key.crv !== "P-256" || typeof value.proof_key.x !== "string" || typeof value.proof_key.y !== "string") {
    throw new VallumAdmissionError("invalid_request", "invalid proof public key");
  }
  decodeBase64Url(value.proof_key.x, 32);
  decodeBase64Url(value.proof_key.y, 32);

  return {
    session: value.session,
    public_key: { kty: "RSA", n: value.public_key.n, e: value.public_key.e },
    proof_key: { kty: "EC", crv: "P-256", x: value.proof_key.x, y: value.proof_key.y },
  };
}

function required(value: string | undefined, name: string): string {
  const normalized = value?.trim();
  if (!normalized) throw new VallumAdmissionError("configuration", `${name} is required`);
  return normalized;
}

function validateScopes(value: readonly string[], category: VallumAdmissionError["category"]): string[] {
  const scopes = value.map((scope) => scope.trim()).filter(Boolean);
  if (scopes.length === 0 || scopes.length > 32 || scopes.some((scope) => scope.length > 128 || /[\x00\r\n\t ]/.test(scope))) {
    throw new VallumAdmissionError(category, "Vallum admission scopes are invalid");
  }
  return [...new Set(scopes)];
}

function parseScopes(value: string | undefined): string[] {
  return validateScopes((value || "route:internal-api").split(","), "configuration");
}

export function admissionConfiguration(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): VallumAdmissionConfiguration {
  const ttlSeconds = Number(environment.VALLUM_ADMISSION_TTL_SECONDS || "30");
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 30) {
    throw new VallumAdmissionError("configuration", "VALLUM_ADMISSION_TTL_SECONDS must be between 1 and 30");
  }
  return {
    privateKey: required(environment.VALLUM_ADMISSION_PRIVATE_KEY, "VALLUM_ADMISSION_PRIVATE_KEY"),
    keyId: required(environment.VALLUM_ADMISSION_KEY_ID, "VALLUM_ADMISSION_KEY_ID"),
    issuer: required(environment.VALLUM_ADMISSION_ISSUER, "VALLUM_ADMISSION_ISSUER"),
    audience: required(environment.VALLUM_ADMISSION_AUDIENCE, "VALLUM_ADMISSION_AUDIENCE"),
    applicationId: required(environment.VALLUM_APPLICATION_ID, "VALLUM_APPLICATION_ID"),
    environment: required(environment.VALLUM_APPLICATION_ENVIRONMENT, "VALLUM_APPLICATION_ENVIRONMENT"),
    scopes: parseScopes(environment.VALLUM_ADMISSION_SCOPES),
    ttlSeconds,
  };
}

function validateConfiguration(configuration: VallumAdmissionConfiguration): void {
  for (const [name, value] of [
    ["privateKey", configuration.privateKey],
    ["keyId", configuration.keyId],
    ["issuer", configuration.issuer],
    ["audience", configuration.audience],
    ["applicationId", configuration.applicationId],
    ["environment", configuration.environment],
  ] as const) required(value, name);
  if (!Number.isInteger(configuration.ttlSeconds) || configuration.ttlSeconds < 1 || configuration.ttlSeconds > 30) {
    throw new VallumAdmissionError("configuration", "ttlSeconds must be between 1 and 30");
  }
  validateScopes(configuration.scopes, "configuration");
}

function thumbprint(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

function signingKey(encoded: string) {
  let raw: Buffer;
  try {
    raw = Buffer.from(encoded.trim(), BASE64URL_PATTERN.test(encoded.trim()) ? "base64url" : "base64");
  } catch {
    throw new VallumAdmissionError("configuration", "Vallum admission private key is not valid base64");
  }
  if (raw.length === 64) raw = raw.subarray(0, 32);
  if (raw.length !== 32) {
    throw new VallumAdmissionError("configuration", "Vallum admission private key must contain a 32-byte seed or 64-byte private key");
  }
  try {
    return createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_SEED_PREFIX, raw]), format: "der", type: "pkcs8" });
  } catch {
    throw new VallumAdmissionError("configuration", "Vallum admission private key could not be loaded");
  }
}

function encodeJSON(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

export function issueVallumAdmission(
  request: VallumAdmissionRequest,
  configuration: VallumAdmissionConfiguration,
  context: VallumAdmissionContext,
) {
  validateConfiguration(configuration);
  const subject = context.subject.trim();
  if (!subject || subject.length > 256 || /[\x00\r\n]/.test(subject)) {
    throw new VallumAdmissionError("configuration", "invalid admission subject");
  }
  const scopes = context.scopes
    ? validateScopes(context.scopes, "configuration")
    : validateScopes(configuration.scopes, "configuration");
  const tokenId = Buffer.from(context.tokenId || randomBytes(18));
  if (tokenId.length !== 18) throw new VallumAdmissionError("configuration", "invalid admission token identifier");
  const now = (context.now || new Date()).getTime();
  if (!Number.isFinite(now)) throw new VallumAdmissionError("configuration", "invalid admission time");
  const issuedAt = Math.floor(now / 1000);
  const expiresAt = issuedAt + configuration.ttlSeconds;
  const rsaCanonical = JSON.stringify({ e: request.public_key.e, kty: request.public_key.kty, n: request.public_key.n });
  const proofCanonical = JSON.stringify({ crv: request.proof_key.crv, kty: request.proof_key.kty, x: request.proof_key.x, y: request.proof_key.y });
  const header = encodeJSON({ alg: "EdDSA", kid: configuration.keyId, typ: "vallum-admission+jwt" });
  const claims = {
    v: 1,
    iss: configuration.issuer,
    aud: configuration.audience,
    purpose: "vallum.decode",
    jti: tokenId.toString("base64url"),
    iat: issuedAt,
    nbf: issuedAt - 1,
    exp: expiresAt,
    app: configuration.applicationId,
    env: configuration.environment,
    sid: request.session,
    sub: subject,
    scp: scopes,
    cnf: { jkt: thumbprint(rsaCanonical), pjkt: thumbprint(proofCanonical) },
  };
  const payload = encodeJSON(claims);
  const unsigned = `${header}.${payload}`;
  const signature = sign(null, Buffer.from(unsigned), signingKey(configuration.privateKey)).toString("base64url");
  return { admission: `${unsigned}.${signature}`, expiresAt: new Date(expiresAt * 1000), claims };
}

function jsonResponse(status: number, body: Record<string, unknown>, headers?: HeadersInit): Response {
  return Response.json(body, {
    status,
    headers: {
      "Cache-Control": "private, no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers,
    },
  });
}

async function readBoundedBody(request: Request, maxBodyBytes: number): Promise<string> {
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      size += value.byteLength;
      if (size > maxBodyBytes) {
        await reader.cancel("Vallum admission request is too large").catch(() => undefined);
        throw new AdmissionBodyTooLargeError();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength)), size)
    .toString("utf8");
}

async function sameOrigin(request: Request, allowOrigin?: VallumAdmissionHandlerOptions["allowOrigin"]): Promise<boolean> {
  const fetchSite = request.headers.get("Sec-Fetch-Site")?.trim().toLowerCase();
  if (fetchSite && fetchSite !== "same-origin") return false;
  const rawOrigin = request.headers.get("Origin");
  if (!rawOrigin) return false;
  try {
    const origin = new URL(rawOrigin);
    const requestURL = new URL(request.url);
    if (origin.origin !== requestURL.origin) return false;
    return allowOrigin ? await allowOrigin(origin, requestURL, request) : true;
  } catch {
    return false;
  }
}

/**
 * Create a Fetch API route handler for `/.well-known/vallum/admission`.
 *
 * The caller owns application authentication and a distributed issuance
 * budget. The helper owns strict transport validation, same-origin checks,
 * bounded parsing, grant signing, and non-cacheable responses.
 */
export function createVallumAdmissionHandler(
  options: VallumAdmissionHandlerOptions,
): (request: Request) => Promise<Response> {
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  if (!Number.isInteger(maxBodyBytes) || maxBodyBytes < 1 || maxBodyBytes > 1024 * 1024) {
    throw new TypeError("maxBodyBytes must be between 1 and 1048576");
  }

  return async (request: Request): Promise<Response> => {
    if (request.method !== "POST") {
      return jsonResponse(405, { error: "method not allowed" }, { Allow: "POST" });
    }
    if (!await sameOrigin(request, options.allowOrigin)) {
      return jsonResponse(403, { error: "same-origin request required" });
    }
    const mediaType = request.headers.get("Content-Type")
      ?.split(";", 1)[0]
      ?.trim()
      .toLowerCase();
    if (mediaType !== "application/json") {
      return jsonResponse(415, { error: "application/json is required" });
    }

    try {
      const principal = await options.authenticate(request);
      if (!principal) return jsonResponse(401, { error: "application session required" });

      const budget = await options.rateLimit(request, principal);
      if (!budget.allowed) {
        const retryAfter = Math.max(1, Math.ceil(budget.retryAfterSeconds ?? 60));
        return jsonResponse(429, { error: "admission issuance budget exhausted" }, { "Retry-After": String(retryAfter) });
      }

      const declaredLength = Number(request.headers.get("Content-Length") || "0");
      if (!Number.isFinite(declaredLength) || declaredLength < 0 || declaredLength > maxBodyBytes) {
        return jsonResponse(413, { error: "admission request is too large" });
      }
      const raw = await readBoundedBody(request, maxBodyBytes);
      const parsed = parseVallumAdmissionRequest(JSON.parse(raw));
      const configuration = typeof options.configuration === "function"
        ? await options.configuration()
        : options.configuration;
      const issued = issueVallumAdmission(parsed, configuration, principal);
      return jsonResponse(201, { admission: issued.admission, expires_at: issued.expiresAt.toISOString() });
    } catch (error) {
      if (error instanceof AdmissionBodyTooLargeError) {
        return jsonResponse(413, { error: "admission request is too large" });
      }
      if (error instanceof SyntaxError || (error instanceof VallumAdmissionError && error.category === "invalid_request")) {
        return jsonResponse(400, { error: "invalid admission request" });
      }
      try {
        options.onError?.(error);
      } catch {
        // Observability hooks must not replace the handler's bounded, generic
        // failure response with an application exception or framework page.
      }
      return jsonResponse(503, { error: "admission issuer unavailable" });
    }
  };
}
