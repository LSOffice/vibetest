"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.unsafeMethodsCheck = void 0;
const SAFE_KEYWORDS = [
    "login",
    "signin",
    "register",
    "signup",
    "forgot-password",
    "reset",
    "contact",
    "webhook",
    "public",
];
exports.unsafeMethodsCheck = {
    id: "unsafe-methods",
    name: "Unprotected State Change",
    description: "Checks for state-changing methods (POST/PUT/DELETE) that accept anonymous requests",
    async run({ axios, apiAxios, discoveredRoutes }) {
        const findings = [];
        // We only know discovered routes. If we found a GET /api/posts, we might guess POST /api/posts exists.
        // Or if the crawler found a POST in HTML forms.
        // Let's assume for mapped routes specificially.
        const candidates = discoveredRoutes.filter((r) => ["POST", "PUT", "DELETE", "PATCH"].includes(r.method));
        // Also guess standard resource creation endpoint from GETs
        discoveredRoutes
            .filter((r) => r.method === "GET" && r.path.startsWith("/api"))
            .forEach((r) => {
            // If we have GET /api/items, try POST /api/items
            candidates.push({ path: r.path, method: "POST" });
            // If we have GET /api/items/1, try DELETE /api/items/1
            if (/\d+$/.test(r.path)) {
                candidates.push({ path: r.path, method: "DELETE" });
            }
        });
        const uniqueCandidates = new Set();
        for (const route of candidates) {
            const key = `${route.method}:${route.path}`;
            if (uniqueCandidates.has(key))
                continue;
            uniqueCandidates.add(key);
            const lowerPath = route.path.toLowerCase();
            if (SAFE_KEYWORDS.some((k) => lowerPath.includes(k)))
                continue;
            try {
                // We send an empty body or random data
                const client = route.path.startsWith('/api') ? apiAxios : axios;
                const res = await client.request({
                    method: route.method,
                    url: route.path,
                    data: {},
                    validateStatus: () => true,
                });
                // If we get 200/201/204, it might be open!
                // 400 Bad Request means "I tried to process it but your input sucked" -> which implies NO AUTH check happened first!
                // Usually auth middleware runs BEFORE validation middleware.
                // So 400 is actually a sign of "Auth Missing" often.
                // 401/403 is what we want.
                const isSuspicious = res.status < 300 || res.status === 400 || res.status === 500;
                // 500 often means it crashed trying to read `req.user.id` which is undefined -> Proof of missing auth + crash!
                if (isSuspicious) {
                    let findingName = "Unprotected State Change";
                    let desc = `The endpoint ${route.method} ${route.path} responded with ${res.status}, suggesting it processed the request without authentication.`;
                    if (res.status === 500) {
                        findingName = "Crash on Unauth Request (Likely Missing Guard)";
                        desc +=
                            " A 500 error suggests the code tried to access a user object that wasn't present, causing a crash.";
                    }
                    else if (res.status === 400) {
                        // Only report 400 if strictly mapped, otherwise too noisy?
                        // Actually 400 is noisy. Let's stick to 2xx or 500.
                        if (res.status === 400)
                            continue;
                    }
                    findings.push({
                        id: `unsafe-method-${route.method}-${route.path}`,
                        checkId: "unsafe-methods",
                        category: "backend",
                        name: findingName,
                        endpoint: `${route.method} ${route.path}`,
                        risk: res.status === 500 ? "medium" : "high",
                        description: desc,
                        assumption: "Developer assumed this specific method was protected because the route group is, or forgot it entirely.",
                        reproduction: `curl -X ${route.method} ${axios.defaults.baseURL}${route.path}`,
                        fix: "Ensure authentication middleware runs before any request processing or validation.",
                    });
                }
            }
            catch (e) {
                // Check failed
            }
        }
        return findings;
    },
};
