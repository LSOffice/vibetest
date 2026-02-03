import { Check, Finding } from "../core/types.js";

export const idorCheck: Check = {
  id: "idor-check",
  name: "Insecure Direct Object References (IDOR)",
  description:
    "Checks if changing ID parameters allows access to other objects",
  async run({ axios, apiAxios, discoveredRoutes, config }) {
    const findings: Finding[] = [];

    // Look for routes with /{id} pattern (heuristic: ends in number or looks like UUID in discovery?
    // Actually discovery just returns paths provided by crawler. Crawler finds static paths.
    // Pure crawler won't find /user/123 unless it was linked.
    // We need to rely on what we found.

    const idRoutes = discoveredRoutes.filter(
      (r) => /\/\d+$/.test(r.path) || /\/[a-f0-9-]{36}$/.test(r.path),
    );

    for (const route of idRoutes) {
      // Simple numeric IDOR test
      const numericMatch = route.path.match(/\/(\d+)$/);
      if (numericMatch) {
        const originalId = parseInt(numericMatch[1]);
        const fuzzIds = [originalId - 1, originalId + 1].filter((x) => x > 0);

        for (const testId of fuzzIds) {
          const testPath = route.path.replace(/\/\d+$/, `/${testId}`);
          try {
            // Try to access neighbor ID
            const client = route.path.startsWith('/api') ? apiAxios : axios;
            const headers = config.auth?.token
              ? { Authorization: `Bearer ${config.auth.token}` }
              : {};
            const res = await client.get(testPath, { headers });

            if (res.status === 200) {
              // We found another valid object. This is only IDOR if usage is improper,
              // but for a dev tool, finding an accessible neighbor /1 vs /2 is a strong warning signal
              // if the user didn't explicitly say "I want to be able to see everyone".

              findings.push({
                id: `idor-numeric-${route.path}`,
                checkId: "idor-check",
                category: "backend",
                name: "Possible IDOR / Enumeration",
                endpoint: testPath,
                risk: "high",
                description: `Accessed object ID ${testId} simply by guessing the number (neighbor of valid ID ${originalId}).`,
                assumption:
                  "Developer assumed sequential IDs are obscure or ownership is implicitly checked.",
                reproduction: `curl ${axios.defaults.baseURL}${testPath} -H "Authorization: ... "`,
                fix: "Verify ownership (e.g. `WHERE user_id = current`) or use UUIDs.",
              });
              break; // Log once per route
            }
          } catch {
            // 403/404 is good
          }
        }
      }
    }

    return findings;
  },
};
