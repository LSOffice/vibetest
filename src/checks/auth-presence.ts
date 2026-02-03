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
  description: "Checks if sensitive routes allow anonymous access",
  async run({ axios, apiAxios, discoveredRoutes }) {
    const findings: Finding[] = [];

    const sensitiveRoutes = discoveredRoutes.filter(
      (r) =>
        SENSITIVE_KEYWORDS.some((k) => r.path.toLowerCase().includes(k)) &&
        !["login", "register", "signin", "signup"].some((k) =>
          r.path.toLowerCase().includes(k),
        ),
    );

    for (const route of sensitiveRoutes) {
      try {
        // Use apiAxios for /api routes, axios for frontend routes
        const client = route.path.startsWith("/api") ? apiAxios : axios;
        const res = await client.get(route.path);

        // Logic: specific HTTP status codes or content heuristics
        // If 200 OK and JSON is returned, unlikely to be a login page (which serves HTML)
        // If 200 OK and HTML, might be a dashboard OR a login page.
        // We look for 401/403 usually.

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

    return findings;
  },
};
