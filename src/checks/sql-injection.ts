import { Check, Finding } from "../core/types.js";

// Non-destructive SQL injection payloads
const SQL_PAYLOADS = [
  {
    name: "Quote Break",
    value: "test'",
    markers: ["syntax", "sql", "mysql", "postgres", "sqlite"],
  },
  {
    name: "Comment Injection",
    value: "test'--",
    markers: ["syntax", "error", "unclosed"],
  },
  { name: "Boolean Test", value: "1' OR '1'='1", markers: [] },
  {
    name: "Union Test",
    value: "1' UNION SELECT NULL--",
    markers: ["union", "syntax", "column"],
  },
  { name: "Time Delay (Safe)", value: "1' AND SLEEP(0)--", markers: [] },
  { name: "Quote Escape", value: "test\\'", markers: ["escape", "backslash"] },
];

const SQL_FIELD_PATTERNS = [
  "search",
  "query",
  "q",
  "filter",
  "sort",
  "order",
  "id",
  "user_id",
  "username",
  "email",
  "name",
  "category",
  "tag",
  "status",
  "type",
];

export const sqlInjectionCheck: Check = {
  id: "sql-injection",
  name: "SQL Injection (CWE-89)",
  description:
    "Detects potential SQL injection vulnerabilities via frontend fields",
  async run({ axios, apiAxios, discoveredRoutes }) {
    const findings: Finding[] = [];

    // Test both GET (query params) and POST (body params)
    const candidates = discoveredRoutes.filter(
      (r) =>
        r.path.includes("search") ||
        r.path.includes("filter") ||
        r.path.includes("list") ||
        r.path.includes("query") ||
        (r.inputs &&
          Object.keys(r.inputs).some((k) =>
            SQL_FIELD_PATTERNS.some((pattern) =>
              k.toLowerCase().includes(pattern),
            ),
          )),
    );

    for (const route of candidates) {
      const client = route.path.startsWith("/api") ? apiAxios : axios;

      // Determine which fields to test
      let testFields: string[] = [];
      if (route.inputs) {
        testFields = Object.keys(route.inputs).filter((k) =>
          SQL_FIELD_PATTERNS.some((pattern) =>
            k.toLowerCase().includes(pattern),
          ),
        );
      }
      if (testFields.length === 0) {
        testFields = ["search", "q", "filter", "id", "sort"];
      }

      for (const field of testFields) {
        for (const payload of SQL_PAYLOADS) {
          try {
            const startTime = Date.now();

            let res;
            if (route.method === "GET") {
              res = await client.get(route.path, {
                params: { [field]: payload.value },
                validateStatus: () => true,
              });
            } else {
              res = await client.request({
                method: route.method,
                url: route.path,
                data: { [field]: payload.value },
                validateStatus: () => true,
              });
            }

            const responseTime = Date.now() - startTime;
            const bodyStr = JSON.stringify(res.data).toLowerCase();
            const headersStr = JSON.stringify(res.headers).toLowerCase();

            // Detection 1: SQL error messages in response
            const hasErrorMarker = payload.markers.some(
              (marker) =>
                bodyStr.includes(marker) || headersStr.includes(marker),
            );

            if (hasErrorMarker && (res.status === 500 || res.status === 400)) {
              findings.push({
                id: `sql-injection-error-${route.path}-${field}-${payload.name}`,
                checkId: "sql-injection",
                category: "backend",
                name: "SQL Injection - Error-Based",
                endpoint: `${route.method} ${route.path}`,
                risk: "critical",
                description: `Field '${field}' with payload "${payload.value}" triggered SQL error patterns in response. This indicates raw SQL query construction.`,
                assumption:
                  "ORM usage means SQL injection is impossible, or raw queries are properly parameterized.",
                reproduction: `curl -X ${route.method} "${client.defaults.baseURL}${route.path}${route.method === "GET" ? `?${field}=${encodeURIComponent(payload.value)}` : ""}" ${route.method !== "GET" ? `-d '{"${field}":"${payload.value}"}' -H "Content-Type: application/json"` : ""}`,
                fix: "Use parameterized queries or ORM methods. Never concatenate user input into SQL strings. Example: Use db.query('SELECT * FROM users WHERE id = ?', [userId]) instead of db.query(`SELECT * FROM users WHERE id = ${userId}`).",
              });
              break; // One finding per field is enough
            }

            // Detection 2: Response shape changes (different fields/structure)
            if (res.status === 200 && payload.name === "Boolean Test") {
              // Store baseline for comparison (in real implementation, would need state)
              // For now, just flag suspicious successful injections
              const hasExtraData =
                res.data &&
                ((Array.isArray(res.data) && res.data.length > 100) ||
                  (typeof res.data === "object" &&
                    Object.keys(res.data).length > 20));

              if (hasExtraData) {
                findings.push({
                  id: `sql-injection-blind-${route.path}-${field}`,
                  checkId: "sql-injection",
                  category: "backend",
                  name: "SQL Injection - Blind/Boolean-Based",
                  endpoint: `${route.method} ${route.path}`,
                  risk: "critical",
                  description: `Field '${field}' with boolean injection returned unexpected data volume, suggesting query manipulation.`,
                  assumption:
                    "Input validation and ORM prevent query manipulation.",
                  reproduction: `Test with: ${field}=1' OR '1'='1`,
                  fix: "Implement strict input validation and use parameterized queries exclusively.",
                });
                break;
              }
            }

            // Detection 3: Timing anomalies (for SLEEP payloads)
            if (payload.name === "Time Delay (Safe)" && responseTime > 3000) {
              findings.push({
                id: `sql-injection-time-${route.path}-${field}`,
                checkId: "sql-injection",
                category: "backend",
                name: "SQL Injection - Time-Based Blind",
                endpoint: `${route.method} ${route.path}`,
                risk: "critical",
                description: `Field '${field}' caused ${responseTime}ms delay with time-based payload, indicating SQL execution.`,
                assumption: "Backend properly sanitizes all user input.",
                reproduction: `Time-based payloads detected. Manual verification recommended.`,
                fix: "Use parameterized queries. Disable dangerous SQL functions like SLEEP in database permissions if possible.",
              });
              break;
            }
          } catch (e: any) {
            // Network errors might also indicate injection impact
            if (e.message && e.message.toLowerCase().includes("sql")) {
              findings.push({
                id: `sql-injection-exception-${route.path}-${field}`,
                checkId: "sql-injection",
                category: "backend",
                name: "SQL Injection - Exception-Based",
                endpoint: `${route.method} ${route.path}`,
                risk: "critical",
                description: `Field '${field}' caused SQL-related exception: ${e.message.substring(0, 200)}`,
                assumption: "Error handling prevents information leakage.",
                reproduction: `Exception triggered with field: ${field}`,
                fix: "Implement proper error handling and use parameterized queries.",
              });
            }
          }
        }
      }
    }

    return findings;
  },
};
