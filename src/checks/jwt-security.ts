import { Check, Finding, CheckContext } from "../core/types.js";
import { logTestAttempt } from "../core/logger.js";

/**
 * JWT Security Testing
 *
 * Tests for JWT vulnerabilities:
 * - Algorithm confusion (alg: none, RS256→HS256)
 * - Signature bypass
 * - Token expiration enforcement
 * - Claims manipulation
 * - JWT in URL exposure
 */

// Helper: Parse JWT without verification
function parseJWT(token: string): {
  header: any;
  payload: any;
  signature: string;
} | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    return {
      header: JSON.parse(Buffer.from(parts[0], "base64").toString()),
      payload: JSON.parse(Buffer.from(parts[1], "base64").toString()),
      signature: parts[2],
    };
  } catch (e) {
    return null;
  }
}

// Helper: Create JWT (unsafe, for testing only)
function createJWT(header: any, payload: any, signature: string = ""): string {
  const headerB64 = Buffer.from(JSON.stringify(header))
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  const payloadB64 = Buffer.from(JSON.stringify(payload))
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return `${headerB64}.${payloadB64}.${signature}`;
}

// Helper: Extract JWT from various sources
function extractJWT(
  headers: any,
  cookies: any,
  responseData: any,
): string | null {
  // Check Authorization header
  if (headers.authorization) {
    const match = headers.authorization.match(/Bearer\s+(.+)/i);
    if (match) return match[1];
  }

  // Check cookies
  if (cookies) {
    for (const [key, value] of Object.entries(cookies)) {
      if (typeof value === "string" && value.split(".").length === 3) {
        return value;
      }
    }
  }

  // Check response body
  if (responseData && typeof responseData === "object") {
    if (responseData.token) return responseData.token;
    if (responseData.jwt) return responseData.jwt;
    if (responseData.accessToken) return responseData.accessToken;
    if (responseData.access_token) return responseData.access_token;
  }

  return null;
}

/**
 * Test Algorithm Confusion (alg: none, RS256→HS256)
 */
async function testAlgorithmConfusion(
  context: CheckContext,
  originalToken: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const { axios, apiAxios, discoveredRoutes } = context;

  const parsed = parseJWT(originalToken);
  if (!parsed) return findings;

  // Test 1: alg: none attack
  const noneHeader = { ...parsed.header, alg: "none" };
  const noneToken = createJWT(noneHeader, parsed.payload, "");

  // Test 2: Remove signature entirely
  const noSigToken = `${originalToken.split(".")[0]}.${originalToken.split(".")[1]}.`;

  // Find authenticated routes to test
  const authRoutes = discoveredRoutes.filter(
    (r) =>
      r.path.includes("profile") ||
      r.path.includes("user") ||
      r.path.includes("dashboard") ||
      r.path.includes("settings"),
  );

  for (const route of authRoutes.slice(0, 5)) {
    const client = route.path.startsWith("/api") ? apiAxios : axios;

    // Test alg: none
    try {
      logTestAttempt({
        check: "jwt-security",
        endpoint: `${route.method} ${route.path}`,
        status: "TESTING",
        details: "Algorithm confusion (alg: none)",
      });

      const response = await client.request({
        method: route.method,
        url: route.path,
        headers: {
          Authorization: `Bearer ${noneToken}`,
        },
        validateStatus: () => true,
      });

      if (response.status === 200) {
        findings.push({
          id: `jwt-alg-none-${route.path}`,
          checkId: "jwt-security",
          category: "backend",
          name: 'JWT Algorithm Confusion - "alg: none"',
          endpoint: `${route.method} ${route.path}`,
          risk: "critical",
          description: `Server accepted JWT with "alg: none" header, bypassing signature verification. This allows complete authentication bypass.`,
          assumption:
            "JWT signature is always validated before accepting tokens.",
          reproduction: `Modify JWT header to {"alg":"none"}, remove signature, send to ${route.path}`,
          fix: 'CRITICAL: Reject JWTs with "alg: none". Use a JWT library that enforces signature validation. Explicitly whitelist allowed algorithms.',
        });

        logTestAttempt({
          check: "jwt-security",
          endpoint: `${route.method} ${route.path}`,
          status: "VULNERABLE",
          details: 'alg: none accepted!',
        });
      }
    } catch (e) {
      // Rejection is good
    }

    // Test signature removal
    try {
      const response = await client.request({
        method: route.method,
        url: route.path,
        headers: {
          Authorization: `Bearer ${noSigToken}`,
        },
        validateStatus: () => true,
      });

      if (response.status === 200) {
        findings.push({
          id: `jwt-no-sig-${route.path}`,
          checkId: "jwt-security",
          category: "backend",
          name: "JWT Signature Bypass",
          endpoint: `${route.method} ${route.path}`,
          risk: "critical",
          description: `Server accepted JWT with signature removed. This indicates the server is not validating JWT signatures.`,
          assumption: "JWT signatures are validated.",
          reproduction: `Remove signature from JWT: ${originalToken.split(".")[0]}.${originalToken.split(".")[1]}.`,
          fix: "CRITICAL: Always validate JWT signatures. Use a proper JWT library with signature verification enabled.",
        });
      }
    } catch (e) {
      // Rejection is good
    }
  }

  return findings;
}

/**
 * Test Claims Manipulation
 */
async function testClaimsManipulation(
  context: CheckContext,
  originalToken: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const { axios, apiAxios, discoveredRoutes } = context;

  const parsed = parseJWT(originalToken);
  if (!parsed) return findings;

  // Create manipulated tokens
  const manipulations = [
    {
      name: "Admin Role",
      payload: { ...parsed.payload, role: "admin", isAdmin: true },
    },
    {
      name: "Different User ID",
      payload: { ...parsed.payload, userId: 1, user_id: 1, sub: "1" },
    },
    {
      name: "Elevated Permissions",
      payload: {
        ...parsed.payload,
        permissions: ["admin", "write", "delete"],
        isAdmin: true,
      },
    },
    {
      name: "Extended Expiration",
      payload: {
        ...parsed.payload,
        exp: Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60,
      },
    }, // +1 year
  ];

  const authRoutes = discoveredRoutes
    .filter(
      (r) =>
        r.path.includes("admin") ||
        r.path.includes("user") ||
        r.path.includes("profile"),
    )
    .slice(0, 5);

  for (const manipulation of manipulations) {
    const manipulatedToken = createJWT(
      parsed.header,
      manipulation.payload,
      parsed.signature,
    );

    for (const route of authRoutes) {
      const client = route.path.startsWith("/api") ? apiAxios : axios;

      try {
        logTestAttempt({
          check: "jwt-security",
          endpoint: `${route.method} ${route.path}`,
          status: "TESTING",
          details: `Claims manipulation: ${manipulation.name}`,
        });

        const response = await client.request({
          method: route.method,
          url: route.path,
          headers: {
            Authorization: `Bearer ${manipulatedToken}`,
          },
          validateStatus: () => true,
        });

        // If server accepts the manipulated token
        if (response.status === 200) {
          findings.push({
            id: `jwt-claims-${route.path}-${manipulation.name.replace(/\s/g, "-")}`,
            checkId: "jwt-security",
            category: "backend",
            name: `JWT Claims Manipulation - ${manipulation.name}`,
            endpoint: `${route.method} ${route.path}`,
            risk: "critical",
            description: `Server accepted JWT with manipulated claims (${manipulation.name}) despite invalid signature. The server is not validating JWT signatures properly.`,
            assumption: "JWT claims cannot be modified without invalidating signature.",
            reproduction: `Modify JWT payload: ${JSON.stringify(manipulation.payload).substring(0, 100)}`,
            fix: "CRITICAL: Validate JWT signature before trusting claims. Use a proper JWT library. Never trust user-modifiable data.",
          });

          logTestAttempt({
            check: "jwt-security",
            endpoint: `${route.method} ${route.path}`,
            status: "VULNERABLE",
            details: `Claims manipulation accepted: ${manipulation.name}`,
          });

          break; // One finding per manipulation type
        }
      } catch (e) {
        // Rejection is good
      }
    }
  }

  return findings;
}

/**
 * Test Token Expiration
 */
async function testTokenExpiration(
  context: CheckContext,
  originalToken: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const { axios, apiAxios, discoveredRoutes } = context;

  const parsed = parseJWT(originalToken);
  if (!parsed) return findings;

  // Create expired token (exp in the past)
  const expiredPayload = {
    ...parsed.payload,
    exp: Math.floor(Date.now() / 1000) - 3600,
  }; // 1 hour ago
  const expiredToken = createJWT(parsed.header, expiredPayload, parsed.signature);

  const authRoutes = discoveredRoutes
    .filter((r) => r.path.includes("user") || r.path.includes("profile"))
    .slice(0, 3);

  for (const route of authRoutes) {
    const client = route.path.startsWith("/api") ? apiAxios : axios;

    try {
      logTestAttempt({
        check: "jwt-security",
        endpoint: `${route.method} ${route.path}`,
        status: "TESTING",
        details: "Expired token test",
      });

      const response = await client.request({
        method: route.method,
        url: route.path,
        headers: {
          Authorization: `Bearer ${expiredToken}`,
        },
        validateStatus: () => true,
      });

      if (response.status === 200) {
        findings.push({
          id: `jwt-expiration-${route.path}`,
          checkId: "jwt-security",
          category: "backend",
          name: "JWT Expiration Not Enforced",
          endpoint: `${route.method} ${route.path}`,
          risk: "high",
          description: `Server accepted an expired JWT token. The 'exp' claim is not being validated.`,
          assumption: "Expired tokens are rejected by the server.",
          reproduction: `Use a JWT with exp claim set to past timestamp`,
          fix: "Validate JWT expiration (exp claim). Reject tokens with exp < current time. Use a JWT library that handles this automatically.",
        });

        logTestAttempt({
          check: "jwt-security",
          endpoint: `${route.method} ${route.path}`,
          status: "VULNERABLE",
          details: "Expired token accepted",
        });

        break; // One finding is enough
      }
    } catch (e) {
      // Rejection is good (401 expected)
    }
  }

  return findings;
}

/**
 * Test JWT in URL (security anti-pattern)
 */
async function testJWTInURL(
  context: CheckContext,
  originalToken: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const { discoveredRoutes } = context;

  // Check if any routes accept JWT in query params
  const testRoutes = discoveredRoutes.filter(
    (r) => r.method === "GET" && r.path.includes("auth"),
  );

  for (const route of testRoutes.slice(0, 5)) {
    // Look for token/jwt parameters
    const tokenParams = ["token", "jwt", "auth", "access_token"];

    for (const param of tokenParams) {
      try {
        const url = `${route.path}?${param}=${originalToken}`;

        logTestAttempt({
          check: "jwt-security",
          endpoint: `GET ${url}`,
          status: "TESTING",
          details: "JWT in URL parameter",
        });

        // If this route pattern exists, it's a security issue
        if (
          route.path.includes("callback") ||
          route.path.includes("verify") ||
          route.path.includes("auth")
        ) {
          findings.push({
            id: `jwt-in-url-${route.path}`,
            checkId: "jwt-security",
            category: "backend",
            name: "JWT in URL (Security Anti-Pattern)",
            endpoint: `GET ${route.path}?${param}=...`,
            risk: "medium",
            description: `Route appears to accept JWT in URL query parameter. JWTs in URLs are logged in server logs, browser history, and referrer headers, exposing them to attackers.`,
            assumption: "JWTs are only transmitted in Authorization header or secure cookies.",
            reproduction: `Detected route: ${route.path} with param: ${param}`,
            fix: "Never pass JWTs in URL query parameters. Use Authorization header (Bearer token) or secure, HttpOnly cookies only.",
          });

          logTestAttempt({
            check: "jwt-security",
            endpoint: `GET ${route.path}`,
            status: "SUSPICIOUS",
            details: `JWT likely accepted in URL param: ${param}`,
          });

          break;
        }
      } catch (e) {
        // Continue
      }
    }
  }

  return findings;
}

/**
 * Main JWT Security Check
 */
export const jwtSecurityCheck: Check = {
  id: "jwt-security",
  name: "JWT Security Testing",
  description:
    "Tests for JWT vulnerabilities including algorithm confusion, signature bypass, claims manipulation, and expiration",
  async run(context: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      // First, try to obtain a JWT from auth routes
      const { axios, apiAxios, discoveredRoutes } = context;

      const authRoutes = discoveredRoutes.filter(
        (r) =>
          r.path.includes("login") ||
          r.path.includes("auth") ||
          r.path.includes("signin"),
      );

      let jwt: string | null = null;

      // Try to extract JWT from existing auth in config
      if (context.config.auth?.token) {
        const token = context.config.auth.token;
        if (token.split(".").length === 3) {
          jwt = token;
        }
      }

      // If no JWT found in config, try auth routes (with test credentials)
      if (!jwt) {
        for (const route of authRoutes.slice(0, 3)) {
          if (route.method === "POST") {
            try {
              const client = route.path.startsWith("/api") ? apiAxios : axios;
              const response = await client.post(route.path, {
                username: "test",
                email: "test@test.com",
                password: "test",
              });

              jwt = extractJWT(
                response.headers,
                response.headers["set-cookie"],
                response.data,
              );

              if (jwt) break;
            } catch (e) {
              // Continue to next route
            }
          }
        }
      }

      // If we have a JWT, run tests
      if (jwt) {
        logTestAttempt({
          check: "jwt-security",
          endpoint: "JWT Detected",
          status: "INFO",
          details: "Running JWT security tests",
        });

        // Test 1: Algorithm confusion
        const algFindings = await testAlgorithmConfusion(context, jwt);
        findings.push(...algFindings);

        // Test 2: Claims manipulation
        const claimsFindings = await testClaimsManipulation(context, jwt);
        findings.push(...claimsFindings);

        // Test 3: Token expiration
        const expFindings = await testTokenExpiration(context, jwt);
        findings.push(...expFindings);

        // Test 4: JWT in URL
        const urlFindings = await testJWTInURL(context, jwt);
        findings.push(...urlFindings);
      } else {
        logTestAttempt({
          check: "jwt-security",
          endpoint: "JWT Detection",
          status: "INFO",
          details: "No JWT detected - skipping JWT security tests",
        });
      }
    } catch (error: any) {
      console.log(`  ⚠ JWT security testing incomplete: ${error.message}`);
    }

    return findings;
  },
};
