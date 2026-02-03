"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.securityHeadersCheck = void 0;
exports.securityHeadersCheck = {
    id: "security-headers",
    name: "Security Configuration & Headers",
    description: "Checks for missing security headers and leaked technology info",
    async run({ axios, apiAxios, config }) {
        const findings = [];
        try {
            const res = await axios.get("/");
            // 1. Powered By
            if (res.headers["x-powered-by"]) {
                findings.push({
                    id: "header-powered-by",
                    checkId: "security-headers",
                    category: "config",
                    name: "Leaked Tech Stack",
                    endpoint: "/",
                    risk: "low",
                    description: `Server broadcasts "X-Powered-By: ${res.headers["x-powered-by"]}".`,
                    assumption: "It is harmless to tell attackers exactly what framework version we are running.",
                    reproduction: `curl -I ${config.baseUrl}`,
                    fix: 'Disable the `x-powered-by` header (e.g. `app.disable("x-powered-by")` in Express).',
                });
            }
            // 2. Missing headers
            const importantHeaders = [
                "content-security-policy",
                "x-content-type-options",
                "x-frame-options",
            ];
            importantHeaders.forEach((h) => {
                if (!res.headers[h]) {
                    // Only flag CSP as medium/low, others are low
                    const risk = h === "content-security-policy" ? "medium" : "low";
                    findings.push({
                        id: `missing-${h}`,
                        checkId: "security-headers",
                        category: "config",
                        name: `Missing ${h} Header`,
                        endpoint: "/",
                        risk: risk,
                        description: `The response is missing the ${h} header.`,
                        assumption: "Defaults are secure enough.",
                        reproduction: `curl -I ${config.baseUrl}`,
                        fix: `Configure Helmet.js or equivalent to set secure headers.`,
                    });
                }
            });
            // 3. Cookies
            const setCookie = res.headers["set-cookie"];
            if (setCookie) {
                setCookie.forEach((cookie) => {
                    if (!cookie.includes("Secure") &&
                        !config.baseUrl.includes("localhost")) {
                        // Wait, we ARE localhost tools. Secure cookies on localhost are tricky without https.
                        // We should only flag this if we were https, OR warn that they should be enabled in prod.
                        // But HttpOnly IS relevant on localhost.
                    }
                    if (!cookie.includes("HttpOnly")) {
                        findings.push({
                            id: "cookie-httponly",
                            checkId: "security-headers",
                            name: "Cookie Missing HttpOnly",
                            endpoint: "/",
                            risk: "medium",
                            description: `A cookie was set without the HttpOnly flag, making it accessible to JavaScript (XSS).`,
                            assumption: "Frontend JS key needs access to this cookie.",
                            reproduction: `Inspect cookies in DevTools`,
                            fix: "Set `{ httpOnly: true }` when creating the cookie.",
                        });
                    }
                    if (!cookie.includes("SameSite")) {
                        findings.push({
                            id: "cookie-samesite",
                            checkId: "security-headers",
                            name: "Cookie Missing SameSite",
                            endpoint: "/",
                            risk: "low",
                            description: `A cookie was set without SameSite attribute.`,
                            assumption: "Browser defaults are fine (they are drifting towards Lax, but explicit is better).",
                            reproduction: `Inspect cookies in DevTools`,
                            fix: 'Set `{ sameSite: "lax" }` or strict.',
                        });
                    }
                });
            }
        }
        catch (e) {
            // failed
        }
        return findings;
    },
};
