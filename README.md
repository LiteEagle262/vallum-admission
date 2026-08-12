# `@liteeagle226/admission`

Node-side admission grant issuer for the Vallum browser SDK. This package must
only be imported by a trusted application backend. It contains the Ed25519
private-key path and must never enter a browser bundle.

The export map resolves to a fail-fast stub under the `browser` condition so a
misconfigured frontend build cannot silently bundle the Node signing path.

```sh
npm install @liteeagle226/admission
```

The framework-neutral handler uses the standard Fetch API on Node.js, so it can
be used by Next.js, Remix, SvelteKit, Nuxt/Nitro, or any Node server framework
that can translate a request to `Request` and a response from `Response`:

```ts
import {
  admissionConfiguration,
  createVallumAdmissionHandler,
} from "@liteeagle226/admission";

export const issueAdmission = createVallumAdmissionHandler({
  configuration: () => admissionConfiguration(),

  async authenticate(request) {
    const session = await applicationSessions.read(request);
    return session
      ? { subject: session.userId, scopes: session.vallumScopes }
      : null;
  },

  async rateLimit(_request, principal) {
    // Use an atomic, shared store in a multi-instance deployment.
    return admissionBudgets.consume(principal.subject, 20, "1m");
  },
});
```

Mount the returned handler at `POST /.well-known/vallum/admission`. It enforces
the method, strict same-origin requests, JSON content type, a bounded body,
public-key validation, non-cacheable responses, and generic failure messages.
Your callbacks remain responsible for the application's normal authentication,
server-derived authorization scopes, and a distributed issuance budget.

Required environment variables for `admissionConfiguration()`:

- `VALLUM_ADMISSION_PRIVATE_KEY` — base64/base64url 32-byte Ed25519 seed;
- `VALLUM_ADMISSION_KEY_ID`, `VALLUM_ADMISSION_ISSUER`, and
  `VALLUM_ADMISSION_AUDIENCE`;
- `VALLUM_APPLICATION_ID` and `VALLUM_APPLICATION_ENVIRONMENT`;
- `VALLUM_ADMISSION_SCOPES` — comma-separated fallback scopes;
- `VALLUM_ADMISSION_TTL_SECONDS` — 1–30 seconds (default 30).

Only the matching public verification key belongs in Vallum. See the root
security documentation before deploying an admission broker.
