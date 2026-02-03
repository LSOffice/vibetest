import { Check, Finding } from "../core/types.js";

export const corsCredentialsCheck: Check = {
  id: "cors-credentials",
  name: "CORS Credential Abuse",
  description:
    "Tests for CORS misconfiguration with credentials including wildcard origins, credential reflection, and preflight bypass",
  async run({ axios, apiAxios, discoveredRoutes }) {
    const findings: Finding[] = [];

    // Test various origins
    const testOrigins = [
      "https://evil.com",
      "https://attacker.com",
      "null",
      "http://localhost:8080",
      "http://127.0.0.1:8080",
    ];

    for (const route of discoveredRoutes.slice(0, 10)) {
      for (const origin of testOrigins) {
        try {
          const client = route.path.startsWith("/api") ? apiAxios : axios;
          const response = await client.request({
            method: route.method,
            url: route.path,
            headers: {
              Origin: origin,
            },
            validateStatus: () => true,
          });

          const allowOrigin = response.headers["access-control-allow-origin"];
          const allowCredentials =
            response.headers["access-control-allow-credentials"];

          // Critical: Wildcard with credentials (invalid but sometimes attempted)
          if (allowOrigin === "*" && allowCredentials === "true") {
            findings.push({
              id: `cors-wildcard-creds-${route.path}`,
              checkId: "cors-credentials",
              category: "config",
              name: "Wildcard Origin with Credentials Enabled",
              description: `Endpoint allows credentials with wildcard origin (technically invalid but dangerous if implemented).`,
              endpoint: `${route.method} ${route.path}`,
              risk: "critical",
              assumption:
                "Server misconfiguration allows wildcard CORS with credentials which browser will reject but may expose internal APIs.",
              reproduction: `curl -H "Origin: ${origin}" ${axios.defaults.baseURL}${route.path}`,
              fix: "Never use wildcard (*) origin with credentials: true. Specify exact origins or disable credentials.",
            });
          }

          // High: Reflected origin with credentials
          if (allowOrigin === origin && allowCredentials === "true") {
            findings.push({
              id: `cors-reflected-creds-${route.path}-${origin.replace(/\W/g, "")}`,
              checkId: "cors-credentials",
              category: "config",
              name: "Attacker Origin Accepted with Credentials",
              description: `Server reflects untrusted origin (${origin}) and allows credentials. This enables cross-origin attacks.`,
              endpoint: `${route.method} ${route.path}`,
              risk: "high",
              assumption:
                "Server blindly reflects Origin header with credentials enabled, allowing any origin to make credentialed requests.",
              reproduction: `curl -H "Origin: ${origin}" ${axios.defaults.baseURL}${route.path}`,
              fix: "Maintain a strict allowlist of trusted origins. Never reflect arbitrary origins with credentials enabled.",
            });
          }

          // Medium: Broad origin patterns
          if (
            allowOrigin &&
            allowOrigin !== axios.defaults.baseURL &&
            allowCredentials === "true"
          ) {
            findings.push({
              id: `cors-creds-nonce-origin-${route.path}-${allowOrigin.replace(/\W/g, "")}`,
              checkId: "cors-credentials",
              category: "config",
              name: "Credentials Enabled with Non-Same-Origin",
              description: `Endpoint allows credentials from origin: ${allowOrigin}`,
              endpoint: `${route.method} ${route.path}`,
              risk: "medium",
              assumption:
                "CORS credentials allow requests from non-same-origin, potentially exposing user data across origins.",
              reproduction: `curl -H "Origin: ${allowOrigin}" ${axios.defaults.baseURL}${route.path}`,
              fix: "Review CORS configuration. Ensure only trusted origins can make credentialed requests.",
            });
          }
        } catch (error: any) {
          // Network errors are fine
        }
      }
    }

    // Test preflight requests
    for (const route of discoveredRoutes.slice(0, 5)) {
      if (route.method !== "GET") {
        try {
          const client = route.path.startsWith("/api") ? apiAxios : axios;
          const response = await client.options(route.path, {
            headers: {
              Origin: "https://evil.com",
              "Access-Control-Request-Method": route.method,
            },
            validateStatus: () => true,
          });

          const allowOrigin = response.headers["access-control-allow-origin"];
          const allowCredentials =
            response.headers["access-control-allow-credentials"];
          const allowMethods = response.headers["access-control-allow-methods"];

          if (
            allowOrigin &&
            allowOrigin !== axios.defaults.baseURL &&
            allowCredentials === "true"
          ) {
            findings.push({
              id: `cors-preflight-creds-${route.path}`,
              checkId: "cors-credentials",
              category: "config",
              name: "Preflight Allows Untrusted Origin with Credentials",
              description: `Preflight (OPTIONS) request allows attacker origin with credentials.`,
              endpoint: `OPTIONS ${route.path}`,
              risk: "high",
              assumption:
                "Preflight bypass allows attackers to make credentialed cross-origin requests by exploiting CORS misconfiguration.",
              reproduction: `curl -X OPTIONS -H "Origin: https://evil.com" -H "Access-Control-Request-Method: ${route.method}" ${axios.defaults.baseURL}${route.path}`,
              fix: "Restrict preflight responses to trusted origins only. This is the first step of a CORS attack.",
            });
          }
        } catch (error: any) {
          // Errors are fine
        }
      }
    }

    return findings;
  },
};
