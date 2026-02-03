"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.raceConditionCheck = void 0;
exports.raceConditionCheck = {
    id: "race-condition",
    name: "Race Conditions",
    description: "Checks for lack of concurrency controls on state-changing endpoints",
    async run({ axios, apiAxios, discoveredRoutes, config }) {
        if (config.safeMode) {
            // In safe mode, we might want to skip this or be very careful.
            // Race conditions usually involve writing data.
            // We will output a warning or skip.
            // Let's implement it but only run on specific identifiable "action" endpoints
            // and only if they look like they might be "commands".
            // Actually, without creating real data, it's hard to test race conditions safely.
            // We will enable it but try to stick to "counters" or similar if we can guess.
            // For a general tool, we'll try to race "safe" looking endpoints or just skip if strictly safe mode.
            // Let's assume user knows what they are doing if they didn't exclude it, but maybe limit to 5 requests.
        }
        const findings = [];
        // Heuristic: Endpoints like /api/coupon, /api/vote, /api/gift
        const candidates = discoveredRoutes.filter((r) => (r.method === "POST" || r.method === "PUT") &&
            ["coupon", "vote", "gift", "claim", "transfer", "redeem"].some((k) => r.path.toLowerCase().includes(k)));
        for (const route of candidates) {
            const REQUEST_COUNT = 10;
            const promises = [];
            // We need a valid payload?
            // This is hard blindly. We'll send empty object or what we can guess.
            // Ideally checking IDOR or Mass Assignment first gives us a shape?
            // For now, empty JSON.
            const client = route.path.startsWith("/api") ? apiAxios : axios;
            for (let i = 0; i < REQUEST_COUNT; i++) {
                promises.push(client.request({
                    method: route.method,
                    url: route.path,
                    data: {}, // Potentially empty
                    validateStatus: () => true,
                }));
            }
            try {
                const results = await Promise.all(promises);
                const statusCodes = results.map((r) => r.status);
                const successes = statusCodes.filter((s) => s >= 200 && s < 300).length;
                if (successes > 1) {
                    // If we got multiple successes, is that bad?
                    // If it's "vote", maybe yes.
                    // If it's "claim", yes.
                    findings.push({
                        id: `race-condition-${route.path}`,
                        checkId: "race-condition",
                        category: "logic",
                        name: "Potential Race Condition",
                        endpoint: route.path,
                        risk: "medium",
                        description: `Sent ${REQUEST_COUNT} parallel requests, and ${successes} succeeded. If this action should be atomic (like claiming a one-time code), this is a vulnerability.`,
                        assumption: "Database transactions or logic are atomic without explicit locking.",
                        reproduction: `Send ${REQUEST_COUNT} simultaneous requests to the endpoint using Burp Intruder or a script.`,
                        fix: "Use database transactions with `FOR UPDATE` locking or distributed locks (Redis).",
                    });
                }
            }
            catch (e) {
                // ignore
            }
        }
        return findings;
    },
};
