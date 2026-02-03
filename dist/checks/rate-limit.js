"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.rateLimitCheck = void 0;
exports.rateLimitCheck = {
    id: "rate-limit",
    name: "Rate Limiting & Brute Force Protection",
    description: "Checks if endpoints stop responding after too many requests.",
    async run({ axios, apiAxios, discoveredRoutes }) {
        const findings = [];
        // Focus on login/auth endpoints
        const targets = discoveredRoutes.filter((r) => ["login", "auth", "signin", "token", "otp"].some((k) => r.path.toLowerCase().includes(k)) && r.method === "POST");
        for (const route of targets) {
            const ATTEMPT_COUNT = 15;
            let blocked = false;
            let lastStatus = 0;
            try {
                for (let i = 0; i < ATTEMPT_COUNT; i++) {
                    const client = route.path.startsWith("/api") ? apiAxios : axios;
                    const res = await client.request({
                        method: route.method,
                        url: route.path,
                        data: { username: "test_brute_force", password: `try_${i}` },
                        validateStatus: () => true,
                    });
                    lastStatus = res.status;
                    if (res.status === 429) {
                        blocked = true;
                        break;
                    }
                    // Also check for 403 blocks that might trigger after N attempts
                    if (i > 5 && res.status === 403) {
                        blocked = true;
                        break;
                    }
                }
                if (!blocked) {
                    findings.push({
                        id: `no-rate-limit-${route.path}`,
                        checkId: "rate-limit",
                        category: "config",
                        name: "Missing Rate Limiting",
                        endpoint: route.path,
                        risk: "medium",
                        description: `Sent ${ATTEMPT_COUNT} requests to ${route.path} without receiving a 429 Too Many Requests response.`,
                        assumption: "Auth endpoints should limit retries (e.g. 5 per minute).",
                        reproduction: `Send multiple requests to ${route.path}`,
                        fix: "Implement rate limiting (e.g., express-rate-limit, Redis counters).",
                    });
                }
            }
            catch (e) {
                /* ignore network errors */
            }
        }
        return findings;
    },
};
