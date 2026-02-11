import { Check, Finding } from "../core/types.js";

const SENSITIVE_KEYWORDS = [
  "admin",
  "user",
  "settings",
  "profile",
  "dashboard",
  "order",
  "billing",
];

export const authPresenceCheck: Check = {
  id: "auth-presence",
  name: "Authentication Enforcement",
  description:
    "Checks if sensitive routes allow anonymous access, session fixation, and auth bypass via parameters/headers",
  async run({ axios, apiAxios, discoveredRoutes }) {
    const findings: Finding[] = [];

    const sensitiveRoutes = discoveredRoutes.filter(
      (r) =>
        SENSITIVE_KEYWORDS.some((k) => r.path.toLowerCase().includes(k)) &&
        !["login", "register", "signin", "signup"].some((k) =>
          r.path.toLowerCase().includes(k),
        ),
    );

    // Test 1: Unprotected sensitive routes (original test)
    for (const route of sensitiveRoutes) {
      try {
        // Use apiAxios for /api routes, axios for frontend routes
        const client = route.path.startsWith("/api") ? apiAxios : axios;
        const res = await client.get(route.path);

        if (res.status === 200) {
          // Heuristic for JSON API
          if (res.headers["content-type"]?.includes("application/json")) {
            findings.push({
              id: `unauth-access-${route.path}`,
              checkId: "auth-presence",
              category: "backend",
              name: "Unprotected Sensitive Route",
              endpoint: route.path,
              risk: "high",
              description: `The route ${route.path} returns a 200 OK with JSON data without any authentication.`,
              assumption:
                "Developer assumed middleware defaults to mapped private routes, or forgot to apply @UseGuards/middleware.",
              reproduction: `curl ${axios.defaults.baseURL}${route.path}`,
              fix: "Apply authentication middleware to this route globally or specifically.",
            });
          }
          // Heuristic for "Admin" appearing in body
          else if (
            typeof res.data === "string" &&
            res.data.toLowerCase().includes("admin dashboard")
          ) {
            findings.push({
              id: `unauth-admin-${route.path}`,
              checkId: "auth-presence",
              category: "backend",
              name: "Exposed Admin Interface",
              endpoint: route.path,
              risk: "critical",
              description: `The route ${route.path} renders an admin dashboard without auth.`,
              assumption:
                "Admin routes protected by obscurity or client-side routing only.",
              reproduction: `Visit ${axios.defaults.baseURL}${route.path}`,
              fix: "Ensure server-side session checks are in place before rendering.",
            });
          }
        }
      } catch (e) {
        // 401/403 is good!
      }
    }

    // Test 2: Session Fixation
    const loginRoutes = discoveredRoutes.filter(
      (r) =>
        r.method === "POST" &&
        (r.path.includes("login") ||
          r.path.includes("signin") ||
          r.path.includes("auth")),
    );

    for (const route of loginRoutes.slice(0, 3)) {
      try {
        const client = route.path.startsWith("/api") ? apiAxios : axios;

        // Get initial session ID
        const preLoginRes = await client.get("/", { validateStatus: () => true });
        const preLoginCookies = preLoginRes.headers["set-cookie"];
        const preSessionId = preLoginCookies
          ? preLoginCookies.find((c: string) => c.includes("session"))
          : null;

        // Attempt login
        const loginRes = await client.post(
          route.path,
          {
            username: "test",
            email: "test@test.com",
            password: "test",
          },
          { validateStatus: () => true },
        );

        const postLoginCookies = loginRes.headers["set-cookie"];
        const postSessionId = postLoginCookies
          ? postLoginCookies.find((c: string) => c.includes("session"))
          : null;

        // If session ID unchanged after login, potential session fixation
        if (
          preSessionId &&
          postSessionId &&
          preSessionId.split("=")[1]?.split(";")[0] ===
            postSessionId.split("=")[1]?.split(";")[0]
        ) {
          findings.push({
            id: `session-fixation-${route.path}`,
            checkId: "auth-presence",
            category: "backend",
            name: "Session Fixation Vulnerability",
            endpoint: `POST ${route.path}`,
            risk: "high",
            description: `Session ID remains unchanged after login. An attacker can fixate a victim's session ID before they log in, then hijack the authenticated session.`,
            assumption: "Session ID is regenerated upon login to prevent fixation.",
            reproduction: `1. Get session ID before login\n2. Login\n3. Check if session ID is the same`,
            fix: "Regenerate session ID upon successful login. Use req.session.regenerate() or equivalent in your framework.",
          });
        }
      } catch (e) {
        // Error is fine, continue
      }
    }

    // Test 3: Parameter Pollution Auth Bypass
    const paramBypassTests = [
      { param: "admin", value: "true" },
      { param: "isAdmin", value: "true" },
      { param: "role", value: "admin" },
      { param: "user_role", value: "admin" },
      { param: "auth", value: "true" },
      { param: "authenticated", value: "1" },
      { param: "debug", value: "true" },
    ];

    for (const route of sensitiveRoutes.slice(0, 10)) {
      const client = route.path.startsWith("/api") ? apiAxios : axios;

      for (const test of paramBypassTests) {
        try {
          const res = await client.get(route.path, {
            params: { [test.param]: test.value },
            validateStatus: () => true,
          });

          // If 200 OK with the bypass param, potential vulnerability
          if (res.status === 200) {
            findings.push({
              id: `param-bypass-${route.path}-${test.param}`,
              checkId: "auth-presence",
              category: "backend",
              name: `Auth Bypass via Query Parameter: ${test.param}`,
              endpoint: `GET ${route.path}?${test.param}=${test.value}`,
              risk: "critical",
              description: `Adding ?${test.param}=${test.value} to the URL allowed access to protected route ${route.path}. The server trusts client-provided authorization parameters.`,
              assumption: "Authorization is enforced server-side, not via URL parameters.",
              reproduction: `curl "${axios.defaults.baseURL}${route.path}?${test.param}=${test.value}"`,
              fix: "CRITICAL: Never trust authorization flags from URL parameters. Implement proper server-side session/token validation.",
            });
            break; // One finding per route is enough
          }
        } catch (e) {
          // Error is good
        }
      }
    }

    // Test 4: Header-Based Auth Bypass
    const headerBypassTests = [
      { header: "X-Admin", value: "true" },
      { header: "X-User-Role", value: "admin" },
      { header: "X-Authenticated", value: "true" },
      { header: "X-Auth", value: "true" },
      { header: "X-Is-Admin", value: "1" },
      { header: "X-Forwarded-User", value: "admin" },
      { header: "X-Original-User", value: "admin" },
    ];

    for (const route of sensitiveRoutes.slice(0, 10)) {
      const client = route.path.startsWith("/api") ? apiAxios : axios;

      for (const test of headerBypassTests) {
        try {
          const res = await client.get(route.path, {
            headers: { [test.header]: test.value },
            validateStatus: () => true,
          });

          if (res.status === 200) {
            findings.push({
              id: `header-bypass-${route.path}-${test.header}`,
              checkId: "auth-presence",
              category: "backend",
              name: `Auth Bypass via HTTP Header: ${test.header}`,
              endpoint: `GET ${route.path}`,
              risk: "critical",
              description: `Adding header "${test.header}: ${test.value}" allowed access to protected route ${route.path}. The server trusts client-controlled headers for authorization.`,
              assumption: "Authorization headers cannot be set by clients.",
              reproduction: `curl -H "${test.header}: ${test.value}" "${axios.defaults.baseURL}${route.path}"`,
              fix: "CRITICAL: Never trust X-* headers for authorization. Only trust cryptographically signed tokens (JWT) or server-side sessions. X-* headers are easily spoofed.",
            });
            break;
          }
        } catch (e) {
          // Error is good
        }
      }
    }

    // Test 5: Cookie-Based Auth Bypass
    const cookieBypassTests = [
      { name: "admin", value: "true" },
      { name: "isAdmin", value: "1" },
      { name: "role", value: "admin" },
      { name: "user_role", value: "admin" },
    ];

    for (const route of sensitiveRoutes.slice(0, 10)) {
      const client = route.path.startsWith("/api") ? apiAxios : axios;

      for (const test of cookieBypassTests) {
        try {
          const res = await client.get(route.path, {
            headers: {
              Cookie: `${test.name}=${test.value}`,
            },
            validateStatus: () => true,
          });

          if (res.status === 200) {
            findings.push({
              id: `cookie-bypass-${route.path}-${test.name}`,
              checkId: "auth-presence",
              category: "backend",
              name: `Auth Bypass via Cookie: ${test.name}`,
              endpoint: `GET ${route.path}`,
              risk: "critical",
              description: `Setting cookie "${test.name}=${test.value}" allowed access to protected route ${route.path}. The server trusts unsigned cookies for authorization decisions.`,
              assumption: "Authorization cookies are cryptographically signed and validated.",
              reproduction: `curl --cookie "${test.name}=${test.value}" "${axios.defaults.baseURL}${route.path}"`,
              fix: "CRITICAL: Sign and validate all authorization cookies. Use HttpOnly, Secure, and SameSite flags. Never trust raw cookie values for authorization.",
            });
            break;
          }
        } catch (e) {
          // Error is good
        }
      }
    }

    return findings;
  },
};
