import { Check, Finding } from "../core/types.js";

// Safe command injection test payloads (non-destructive)
const CMD_PAYLOADS = [
  { name: "Semicolon", value: "test;echo", markers: ["command", "syntax"] },
  { name: "Pipe", value: "test|whoami", markers: ["pipe", "command"] },
  { name: "Backticks", value: "test`id`", markers: ["command", "execution"] },
  {
    name: "Command Substitution",
    value: "test$(whoami)",
    markers: ["command", "substitution"],
  },
  { name: "Newline", value: "test\nwhoami", markers: ["newline", "command"] },
  {
    name: "Ampersand",
    value: "test&whoami",
    markers: ["background", "command"],
  },
];

const CMD_FIELD_PATTERNS = [
  "filename",
  "file",
  "path",
  "export",
  "format",
  "output",
  "document",
  "report",
  "download",
  "generate",
  "url",
  "command",
];

const CMD_ENDPOINT_PATTERNS = [
  "export",
  "download",
  "generate",
  "report",
  "convert",
  "file",
  "document",
  "pdf",
  "backup",
  "archive",
];

export const commandInjectionCheck: Check = {
  id: "command-injection",
  name: "Command Injection (CWE-77)",
  description:
    "Detects command injection via utility fields that trigger shell execution",
  async run({ axios, apiAxios, discoveredRoutes }) {
    const findings: Finding[] = [];

    // Target endpoints that likely trigger server-side command execution
    const candidates = discoveredRoutes.filter(
      (r) =>
        CMD_ENDPOINT_PATTERNS.some((pattern) =>
          r.path.toLowerCase().includes(pattern),
        ) ||
        (r.inputs &&
          Object.keys(r.inputs).some((k) =>
            CMD_FIELD_PATTERNS.some((pattern) =>
              k.toLowerCase().includes(pattern),
            ),
          )),
    );

    for (const route of candidates) {
      const client = route.path.startsWith("/api") ? apiAxios : axios;

      // Determine fields to test
      let testFields: string[] = [];
      if (route.inputs) {
        testFields = Object.keys(route.inputs).filter((k) =>
          CMD_FIELD_PATTERNS.some((pattern) =>
            k.toLowerCase().includes(pattern),
          ),
        );
      }
      if (testFields.length === 0) {
        testFields = ["filename", "file", "format", "output", "path"];
      }

      for (const field of testFields) {
        // Establish baseline
        let baselineRes;
        let baselineTime = 0;
        try {
          const start = Date.now();
          baselineRes = await client.request({
            method: route.method,
            url: route.path,
            data:
              route.method !== "GET" ? { [field]: "normal.txt" } : undefined,
            params:
              route.method === "GET" ? { [field]: "normal.txt" } : undefined,
            validateStatus: () => true,
            timeout: 10000,
          });
          baselineTime = Date.now() - start;
        } catch (e) {
          continue;
        }

        for (const payload of CMD_PAYLOADS) {
          try {
            const start = Date.now();

            const res = await client.request({
              method: route.method,
              url: route.path,
              data:
                route.method !== "GET" ? { [field]: payload.value } : undefined,
              params:
                route.method === "GET" ? { [field]: payload.value } : undefined,
              validateStatus: () => true,
              timeout: 10000,
            });

            const responseTime = Date.now() - start;
            const bodyStr = JSON.stringify(res.data).toLowerCase();
            const headersStr = JSON.stringify(res.headers).toLowerCase();

            // Detection 1: Error messages indicating command execution
            if (res.status >= 400) {
              const hasCommandError =
                payload.markers.some(
                  (marker) =>
                    bodyStr.includes(marker) || headersStr.includes(marker),
                ) ||
                bodyStr.includes("exec") ||
                bodyStr.includes("spawn") ||
                bodyStr.includes("shell") ||
                bodyStr.includes("sh:") ||
                bodyStr.includes("bash:") ||
                bodyStr.includes("/bin/") ||
                bodyStr.includes("cannot execute");

              if (hasCommandError) {
                findings.push({
                  id: `cmd-injection-error-${route.path}-${field}`,
                  checkId: "command-injection",
                  category: "backend",
                  name: "Command Injection - Error-Based Detection",
                  endpoint: `${route.method} ${route.path}`,
                  risk: "critical",
                  description: `Field '${field}' with payload "${payload.value}" triggered shell command error patterns. The server appears to be executing shell commands with user input.`,
                  assumption:
                    "User input is sanitized before any shell operations, or exec() is never used with user data.",
                  reproduction: `curl -X ${route.method} "${client.defaults.baseURL}${route.path}" ${route.method !== "GET" ? `-d '{"${field}":"${payload.value}"}' -H "Content-Type: application/json"` : `?${field}=${encodeURIComponent(payload.value)}`}`,
                  fix: "NEVER use exec(), execSync(), spawn() with shell:true, or system() with user input. Use child_process.execFile() with array arguments, or better yet, use libraries that don't invoke shell. Whitelist allowed values.",
                });
                break;
              }
            }

            // Detection 2: Unusual response time (potential command execution delay)
            const timeDiff = responseTime - baselineTime;
            if (timeDiff > 2000 && responseTime > 3000) {
              findings.push({
                id: `cmd-injection-timing-${route.path}-${field}`,
                checkId: "command-injection",
                category: "backend",
                name: "Command Injection - Time-Based Detection",
                endpoint: `${route.method} ${route.path}`,
                risk: "high",
                description: `Field '${field}' with command injection characters caused ${responseTime}ms response (baseline: ${baselineTime}ms). This delay suggests command execution.`,
                assumption:
                  "Backend operations don't involve shell command execution.",
                reproduction: `Time anomaly detected with payload: ${payload.value}`,
                fix: "Avoid shell command execution entirely. Use native language libraries for file operations, format conversions, etc. If shell is unavoidable, use strict whitelisting and execFile() with array arguments.",
              });
              break;
            }

            // Detection 3: Status code changes indicating injection impact
            if (
              baselineRes.status !== res.status &&
              Math.abs(baselineRes.status - res.status) > 100
            ) {
              findings.push({
                id: `cmd-injection-behavior-${route.path}-${field}`,
                checkId: "command-injection",
                category: "backend",
                name: "Command Injection - Behavior Change",
                endpoint: `${route.method} ${route.path}`,
                risk: "high",
                description: `Field '${field}' with special characters changed response from ${baselineRes.status} to ${res.status}, indicating potential command injection impact.`,
                assumption:
                  "Input is properly escaped before any system operations.",
                reproduction: `Status change with: ${field}=${payload.value}`,
                fix: "Sanitize all user input. Never concatenate user input into shell commands. Use parameterized alternatives or native APIs.",
              });
              break;
            }

            // Detection 4: Command output in response (whoami, id, etc.)
            if (res.status === 200 && bodyStr) {
              const hasCommandOutput =
                /uid=\d+/.test(bodyStr) || // id command
                /gid=\d+/.test(bodyStr) ||
                bodyStr.includes("root@") ||
                bodyStr.includes("/home/") ||
                bodyStr.includes("/usr/bin") ||
                (payload.value.includes("whoami") &&
                  bodyStr.match(/\b(root|admin|user|www-data|ubuntu|node)\b/));

              if (hasCommandOutput) {
                findings.push({
                  id: `cmd-injection-output-${route.path}-${field}`,
                  checkId: "command-injection",
                  category: "backend",
                  name: "Command Injection - Output Detected",
                  endpoint: `${route.method} ${route.path}`,
                  risk: "critical",
                  description: `Field '${field}' returned command execution output in response. CONFIRMED COMMAND INJECTION.`,
                  assumption:
                    "Server never executes shell commands with user input.",
                  reproduction: `Command output detected. Manual verification required.`,
                  fix: "IMMEDIATE FIX REQUIRED: Remove all exec()/system() calls that use user input. Rewrite using safe APIs.",
                });
                break;
              }
            }
          } catch (e: any) {
            // Timeout might indicate hung command
            if (e.code === "ECONNABORTED" || e.message?.includes("timeout")) {
              findings.push({
                id: `cmd-injection-timeout-${route.path}-${field}`,
                checkId: "command-injection",
                category: "backend",
                name: "Command Injection - Timeout",
                endpoint: `${route.method} ${route.path}`,
                risk: "high",
                description: `Field '${field}' with payload "${payload.value}" caused request timeout, possibly due to hung command execution.`,
                assumption: "Backend operations complete in reasonable time.",
                reproduction: `Timeout with: ${field}=${payload.value}`,
                fix: "Review any system command execution in this endpoint. Implement proper timeouts and avoid shell altogether.",
              });
              break;
            }
          }
        }
      }
    }

    return findings;
  },
};
