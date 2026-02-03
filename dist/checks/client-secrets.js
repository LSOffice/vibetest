"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.clientSideSecretsCheck = void 0;
exports.clientSideSecretsCheck = {
    id: "client-side-secrets",
    name: "Client-Side Secrets & Hardcoded Keys",
    description: "Scans JavaScript files and HTML for exposed API keys, tokens, or credentials",
    async run({ axios, discoveredRoutes }) {
        const findings = [];
        // Pattern to find JS files referenced in HTML or directly discovered
        const jsFiles = new Set();
        // 1. Look for common JS bundle paths
        const commonPaths = [
            "/_next/static/chunks/main.js",
            "/_next/static/chunks/pages/_app.js",
            "/static/js/main.js",
            "/js/app.js",
            "/bundle.js",
            "/main.js",
        ];
        for (const path of commonPaths) {
            try {
                const res = await axios.get(path, { validateStatus: () => true });
                if (res.status === 200 && typeof res.data === "string") {
                    jsFiles.add(path);
                }
            }
            catch { }
        }
        // 2. Extract JS from discovered HTML pages
        for (const route of discoveredRoutes.filter((r) => !r.path.startsWith("/api"))) {
            try {
                const res = await axios.get(route.path, { validateStatus: () => true });
                if (res.status === 200 &&
                    res.headers["content-type"]?.includes("text/html")) {
                    const scriptMatches = res.data.matchAll(/<script[^>]*src=["']([^"']+)["']/gi);
                    for (const match of scriptMatches) {
                        if (match[1] && match[1].startsWith("/")) {
                            jsFiles.add(match[1]);
                        }
                    }
                }
            }
            catch { }
        }
        // Filter out third-party/library code
        const THIRD_PARTY_PATTERNS = [
            "node_modules",
            "vendor",
            "libraries",
            "lib/",
            "libs/",
            ".min.js", // Typically third-party minified libraries
        ];
        const appJsFiles = Array.from(jsFiles).filter((path) => !THIRD_PARTY_PATTERNS.some((pattern) => path.includes(pattern)));
        // 3. Analyze JS content for secrets
        const SECRET_PATTERNS = [
            {
                pattern: /[\"']([A-Za-z0-9_-]{20,})[\"']/,
                name: "Long Base64-like String",
                minLength: 30,
            },
            {
                pattern: /api[_-]?key[\"':\s]*[\"']([A-Za-z0-9_-]+)[\"']/i,
                name: "API Key",
            },
            { pattern: /secret[\"':\s]*[\"']([A-Za-z0-9_-]+)[\"']/i, name: "Secret" },
            { pattern: /token[\"':\s]*[\"']([A-Za-z0-9._-]+)[\"']/i, name: "Token" },
            { pattern: /password[\"':\s]*[\"']([^\"']+)[\"']/i, name: "Password" },
            { pattern: /(sk_live_[A-Za-z0-9]+)/, name: "Stripe Live Secret Key" },
            {
                pattern: /(pk_live_[A-Za-z0-9]+)/,
                name: "Stripe Live Publishable Key (OK in frontend)",
            },
            { pattern: /(AIza[A-Za-z0-9_-]{35})/, name: "Google API Key" },
            {
                pattern: /([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/,
                name: "UUID (possible key)",
            },
        ];
        for (const jsPath of appJsFiles.slice(0, 10)) {
            // Limit to 10 files to avoid overload
            try {
                const res = await axios.get(jsPath, { validateStatus: () => true });
                if (res.status !== 200 || typeof res.data !== "string")
                    continue;
                const content = res.data;
                for (const { pattern, name, minLength } of SECRET_PATTERNS) {
                    const matches = content.matchAll(new RegExp(pattern.source, "gi"));
                    for (const match of matches) {
                        const captured = match[1] || match[0];
                        // Skip common false positives
                        if (captured.includes("example") ||
                            captured.includes("placeholder") ||
                            captured.includes("YOUR_") ||
                            captured.includes("xxx") ||
                            captured === "undefined" ||
                            captured === "null") {
                            continue;
                        }
                        // Skip if too short (unless it's a specific format like Stripe)
                        if (minLength && captured.length < minLength)
                            continue;
                        // For generic long strings, be more conservative
                        if (name === "Long Base64-like String") {
                            // Only flag if it looks like an actual key format
                            if (!/^[A-Za-z0-9+/=_-]+$/.test(captured))
                                continue;
                        }
                        // Determine risk
                        let risk = "medium";
                        if (name.includes("Stripe Live Secret") ||
                            name.includes("Password")) {
                            risk = "critical";
                        }
                        else if (name.includes("API Key") || name.includes("Secret")) {
                            risk = "high";
                        }
                        else if (name.includes("Publishable Key") ||
                            name.includes("UUID")) {
                            risk = "low";
                        }
                        findings.push({
                            id: `secret-${jsPath}-${name}`,
                            checkId: "client-side-secrets",
                            category: "frontend",
                            name: `Exposed ${name} in JavaScript`,
                            endpoint: jsPath,
                            risk,
                            description: `Found a ${name} in the client-side JavaScript bundle. Value: ${captured.substring(0, 20)}...`,
                            assumption: "Secrets in bundled JS are safe because they're minified.",
                            reproduction: `View source of ${jsPath} and search for the pattern.`,
                            fix: "Move all secrets to server-side environment variables. Use public API keys only when necessary (e.g., Stripe publishable keys).",
                        });
                        break; // Only report one secret per pattern per file to avoid noise
                    }
                }
            }
            catch { }
        }
        return findings;
    },
};
