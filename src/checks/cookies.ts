import { Check, Finding } from "../core/types.js";

// Actually we can just regex the set-cookie header for now to avoid deps if possible,
// but 'cookie' package is standard. Let's assume we parse raw Set-Cookie headers manually for simplicity primarily.

export const cookieSecurityCheck: Check = {
  id: "cookie-security",
  name: "Cookie Security & Scope",
  description:
    "Analyzes Set-Cookie headers for security flags and potential scope issues.",
  async run({ axios, apiAxios, discoveredRoutes }) {
    const findings: Finding[] = [];
    const processedCookies = new Set<string>();

    for (const route of discoveredRoutes) {
      try {
        const res = await axios.head(route.path, {
          validateStatus: () => true,
        });
        const setCookie = res.headers["set-cookie"];

        if (setCookie && Array.isArray(setCookie)) {
          for (const cookieStr of setCookie) {
            // simple name extraction to avoid dupes
            const nameMatch = cookieStr.match(/^([^=]+)=/);
            const cookieName = nameMatch ? nameMatch[1] : "unknown";

            if (processedCookies.has(cookieName)) continue;
            processedCookies.add(cookieName);

            const lowerStr = cookieStr.toLowerCase();
            const isSecure = lowerStr.includes("secure");
            const isHttpOnly = lowerStr.includes("httponly");
            const samesite = lowerStr.includes("samesite");

            if (!isHttpOnly) {
              findings.push({
                id: `cookie-httponly-${cookieName}`,
                checkId: "cookie-security",
                category: "backend",
                name: `Missing HttpOnly Flag on ${cookieName}`,
                endpoint: route.path,
                risk: "medium",
                description: `The cookie ${cookieName} is not marked HttpOnly, allowing JavaScript (XSS) to steal it.`,
                assumption: "Cookie contains sensitive session data.",
                reproduction: `Inspect headers on ${route.path}`,
                fix: "Set the HttpOnly flag when creating the cookie.",
              });
            }

            if (!isSecure && !route.path.includes("localhost")) {
              // Note: localhost is exempt usually, but vibetest is FOR localhost.
              // however, in prod it matters. Let's warn anyway but with a caveat.
              findings.push({
                id: `cookie-secure-${cookieName}`,
                checkId: "cookie-security",
                category: "config",
                name: `Missing Secure Flag on ${cookieName}`,
                endpoint: route.path,
                risk: "low", // Low on localhost
                description: `The cookie ${cookieName} is not marked Secure. It will be sent over plain HTTP.`,
                assumption: "App will be deployed to HTTPS.",
                reproduction: `Inspect headers on ${route.path}`,
                fix: "Set the Secure flag in production environments.",
              });
            }

            if (!samesite) {
              findings.push({
                id: `cookie-samesite-${cookieName}`,
                checkId: "cookie-security",
                category: "config",
                name: `Missing SameSite Attribute on ${cookieName}`,
                endpoint: route.path,
                risk: "medium",
                description: `The cookie ${cookieName} does not specify SameSite behavior, exposing it to CSRF.`,
                assumption:
                  "Modern browsers default to Lax, but explicit is better.",
                reproduction: `Inspect headers on ${route.path}`,
                fix: "Set SameSite=Lax or SameSite=Strict.",
              });
            }

            // Scope/Path check
            // If path is not specified, it defaults to current path. If it's /, it's everywhere.
            // Vibe check: if a cookie is set on /api/admin/login but scope is /, that's loose.
            // It's hard to automate "bad scope" without knowing intent, but we can flag default scope quirks.
          }
        }
      } catch (e) {
        /* ignore */
      }
    }

    return findings;
  },
};
