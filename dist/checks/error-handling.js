"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.errorHandlingCheck = void 0;
const ERROR_PATTERNS = [
    { pattern: /SyntaxError:.+at/i, name: "Stack Trace (Syntax)" },
    { pattern: /ReferenceError:.+at/i, name: "Stack Trace (Reference)" },
    { pattern: /TypeError:.+at/i, name: "Stack Trace (Type)" },
    { pattern: /node_modules\//, name: "File Path Leak (node_modules)" },
    { pattern: /\/var\/www\//, name: "File Path Leak (Linux)" },
    { pattern: /[A-Z]:\\[\w]+\\/, name: "File Path Leak (Windows)" },
    { pattern: /SQL syntax/i, name: "Database Error (SQL)" },
    { pattern: /MongoError/, name: "Database Error (Mongo)" },
    { pattern: /Sequelize/, name: "Database Error (Sequelize)" },
    { pattern: /PrismaClient/, name: "Database Error (Prisma)" },
];
exports.errorHandlingCheck = {
    id: "error-handling",
    name: "Broken Error Handling & Info Leakage",
    description: "Triggers errors to check for leaked stack traces or database info",
    async run({ axios, apiAxios, discoveredRoutes }) {
        const findings = [];
        // 1. Basic 404/Bad Request fuzzing
        // We try to trigger 500s or 400s with verbose bodies
        const testRoutes = discoveredRoutes.slice(0, 10); // Check first 10 for broad coverage
        for (const route of testRoutes) {
            try {
                // Method A: Malformed JSON
                if (route.method === "POST" || route.method === "PUT") {
                    try {
                        const client = route.path.startsWith("/api") ? apiAxios : axios;
                        const res = await client.request({
                            method: route.method,
                            url: route.path,
                            headers: { "Content-Type": "application/json" },
                            data: '{ "broken": json, }', // Invalid JSON
                            validateStatus: () => true,
                        });
                        checkResponse(res, route.path, "Malformed JSON");
                    }
                    catch { }
                }
                // Method B: Bad Parameter Types
                // append garbage query params
                const client = route.path.startsWith("/api") ? apiAxios : axios;
                const res = await client.get(`${route.path}?id=NaN&page=-1&sort=INVALID`, { validateStatus: () => true });
                checkResponse(res, route.path, "Invalid Query Params");
            }
            catch (e) {
                // ignore network err
            }
        }
        function checkResponse(res, endpoint, vector) {
            if (res.status >= 400) {
                const body = typeof res.data === "string" ? res.data : JSON.stringify(res.data);
                for (const p of ERROR_PATTERNS) {
                    if (p.pattern.test(body)) {
                        findings.push({
                            id: `info-leak-${endpoint}-${p.name}`,
                            checkId: "error-handling",
                            category: "config",
                            name: `Information Leakage: ${p.name}`,
                            endpoint: endpoint,
                            risk: "medium",
                            description: `The endpoint returned a verbose error containing internal details when sent '${vector}'. Match: ${p.name}`,
                            assumption: "Developer enabled verbose logging for debugging and forgot to disable it in this environment.",
                            reproduction: `Trigger an error on ${endpoint} using ${vector}.`,
                            fix: "Ensure `NODE_ENV` is set to production and error handlers sanitize output.",
                        });
                        break; // Report one leak per endpoint/request to avoid noise
                    }
                }
            }
        }
        return findings;
    },
};
