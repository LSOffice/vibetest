import { Check, Finding } from "../core/types.js";

const DANGEROUS_FIELDS = {
  isAdmin: true,
  role: "admin",
  isVerified: true,
  premium: true,
  tier: "platinum",
  wallet_balance: 999999,
};

export const massAssignmentCheck: Check = {
  id: "mass-assignment",
  name: "Mass Assignment / Over-Posting",
  description: "Checks if sensitive fields can be injected into updates",
  async run({ axios, apiAxios, discoveredRoutes }) {
    const findings: Finding[] = [];

    // Heuristic: Try to find Update endpoints.
    // If we found GET /api/profile or /api/user, we guess PUT/PATCH might exist.

    const candidates = discoveredRoutes.filter((r) =>
      ["user", "profile", "account", "settings"].some((k) =>
        r.path.includes(k),
      ),
    );

    for (const route of candidates) {
      // Only try this if we think it's an object we can modify
      // We will try PATCH and PUT
      const methods = ["PUT", "PATCH"];

      for (const method of methods) {
        try {
          // First, check if method is allowed
          const client = route.path.startsWith("/api") ? apiAxios : axios;
          const preCheck = await client.request({
            method,
            url: route.path,
            validateStatus: () => true,
          });

          if (preCheck.status === 405 || preCheck.status === 404) continue;

          // Attempt Mass Assignment
          // We send a JSON body with dangerous fields
          const res = await client.request({
            method,
            url: route.path,
            data: DANGEROUS_FIELDS,
            validateStatus: () => true,
          });

          if (res.status >= 200 && res.status < 300) {
            // Need to verification if it stuck.
            // The prompt suggested: "Observe response fields".
            // If response returns the object with "isAdmin": true, we are likely pwned.

            if (
              res.data &&
              (res.data.isAdmin === true ||
                res.data.role === "admin" ||
                res.data.tier === "platinum")
            ) {
              findings.push({
                id: `mass-assignment-${route.path}`,
                checkId: "mass-assignment",
                category: "backend",
                name: "Mass Assignment Vulnerability",
                endpoint: `${method} ${route.path}`,
                risk: "high",
                description: `The endpoint accepted an update with 'isAdmin: true' or similar, and echoed it back.`,
                assumption:
                  "Developer passed `req.body` directly to `db.update()` without filtering.",
                reproduction: `curl -X ${method} ${axios.defaults.baseURL}${route.path} -d '{"isAdmin": true}' -H "Content-Type: application/json"`,
                fix: "Use DTOs (Data Transfer Objects) or explicitly select fields allowed for update.",
              });
            }
          }
        } catch (e) {
          // Ignore
        }
      }
    }

    return findings;
  },
};
