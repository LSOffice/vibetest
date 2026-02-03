"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.securityByCommentCheck = void 0;
const INTENT_MISMATCH_KEYWORDS = [
    { keyword: "private", impliedType: "private" },
    { keyword: "admin", impliedType: "admin" },
    { keyword: "internal", impliedType: "internal" },
    { keyword: "secure", impliedType: "secure" },
    { keyword: "auth", impliedType: "authenticated" },
    { keyword: "dashboard", impliedType: "authenticated" },
    { keyword: "settings", impliedType: "authenticated" },
    { keyword: "billing", impliedType: "authenticated" },
    { keyword: "profile", impliedType: "authenticated" },
];
exports.securityByCommentCheck = {
    id: "security-by-comment",
    name: "Security by Comment (Intent Mismatch)",
    description: "Detects endpoints whose names imply security but are publicly accessible",
    async run({ axios, apiAxios, discoveredRoutes }) {
        const findings = [];
        for (const route of discoveredRoutes) {
            const lowerPath = route.path.toLowerCase();
            // 1. Check if path implies security
            const mismatch = INTENT_MISMATCH_KEYWORDS.find((k) => lowerPath.includes(k.keyword));
            if (mismatch) {
                // 2. Check strict accessibility
                try {
                    // Double check: is it actually accessible anonymously?
                    // We assume discoveredRoutes might include some that returned 401/403 previously.
                    // But our crawler logic in crawler.ts only pushed routes if status !== 404.
                    // However, crawler logic didn't filter 401/403. Let's verify here.
                    const client = route.path.startsWith('/api') ? apiAxios : axios;
                    const res = await client.get(route.path, {
                        validateStatus: () => true,
                    });
                    // If it returns 200 OK and is accessible
                    if (res.status >= 200 && res.status < 300) {
                        // Refine heuristic: Login pages themselves contain 'login' or 'auth' but are public.
                        // Exclude common public auth-related paths
                        if (lowerPath.includes("login") ||
                            lowerPath.includes("signin") ||
                            lowerPath.includes("register") ||
                            lowerPath.includes("forgot")) {
                            continue;
                        }
                        findings.push({
                            id: `intent-mismatch-${route.path}`,
                            checkId: "security-by-comment",
                            category: "backend",
                            name: `Publicly Accessible '${mismatch.keyword}' Route`,
                            endpoint: route.path,
                            risk: mismatch.impliedType === "admin" ? "critical" : "high",
                            description: `The route contains "${mismatch.keyword}", implying it should be ${mismatch.impliedType}, but it returns ${res.status} OK to anonymous requests.`,
                            assumption: `Developer named it "${mismatch.keyword}" assuming the name itself or folder structure implies protection.`,
                            reproduction: `curl ${axios.defaults.baseURL}${route.path}`,
                            fix: "Explicitly apply authentication middleware.",
                        });
                    }
                }
                catch (e) {
                    // ignore
                }
            }
        }
        return findings;
    },
};
