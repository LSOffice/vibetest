import chalk from "chalk";
import ora from "ora";
import axios from "axios";
import { VibeConfig, Route, Finding } from "./types.js";
import { discoverRoutes } from "./crawler.js";
import { checks } from "../checks/index.js";
import inquirer from "inquirer";
import {
  discoverAuth,
  generateConfigExample,
  captureAuthFromBrowser,
} from "./auth-discovery.js";
import { logTestAttempt } from "./logger.js";

export async function runVibeTest(config: VibeConfig) {
  const spinner = ora("Connecting to target...").start();

  // 1. Connectivity Check
  try {
    await axios.get(config.baseUrl);
    spinner.succeed(`Connected to ${config.baseUrl}`);
  } catch (e: any) {
    spinner.fail(`Could not connect to ${config.baseUrl}: ${e.message}`);
    await logTestAttempt({
      status: "connectivity_failed",
      error: e?.message,
      config: {
        baseUrl: config.baseUrl,
        apiUrl: config.apiUrl,
      },
      timestamp: new Date().toISOString(),
    });
    return;
  }

  // Automatic auth discovery
  if (!config.auth?.token) {
    const discoveredAuth = await discoverAuth(config.baseUrl);
    if (discoveredAuth) {
      config.auth = {
        token: discoveredAuth.token,
        cookies: discoveredAuth.cookies,
        headers: discoveredAuth.headers,
      };
    }
  }

  // Interactive Login Check (fallback if auto-discovery failed)
  if (!config.auth?.token && !config.auth?.cookies && process.stdout.isTTY) {
    console.log(""); // spacer
    const { wantAuth } = await inquirer.prompt([
      {
        type: "confirm",
        name: "wantAuth",
        message: "No auth credentials found. Do you want to authenticate now?",
        default: false,
      },
    ]);

    if (wantAuth) {
      const { authMethod } = await inquirer.prompt([
        {
          type: "list",
          name: "authMethod",
          message: "How would you like to authenticate?",
          choices: [
            {
              name: "🌐 Automatic (Open Browser & Login)",
              value: "browser",
            },
            { name: "🔑 Enter Bearer Token (JWT)", value: "token" },
            {
              name: "💾 Save config for future (.vibetest.json)",
              value: "config",
            },
            { name: "⏭️  Skip for now", value: "skip" },
          ],
        },
      ]);

      if (authMethod === "browser") {
        const capturedAuth = await captureAuthFromBrowser(config.baseUrl);
        if (capturedAuth) {
          config.auth = capturedAuth;
          console.log(
            chalk.green("  ✓ Authentication configured from browser."),
          );

          // Ask if they want to save it
          const { shouldSave } = await inquirer.prompt([
            {
              type: "confirm",
              name: "shouldSave",
              message:
                "Save these credentials to .vibetest.json for future use?",
              default: true,
            },
          ]);

          if (shouldSave) {
            const fs = await import("fs");
            fs.writeFileSync(
              ".vibetest.json",
              JSON.stringify(capturedAuth, null, 2),
            );
            console.log(chalk.green("  ✓ Saved to .vibetest.json"));
          }
        } else {
          console.log(
            chalk.yellow(
              "  ⚠ Could not capture authentication. Continuing without auth...",
            ),
          );
        }
      } else if (authMethod === "token") {
        const { token } = await inquirer.prompt([
          {
            type: "input",
            name: "token",
            message: "Enter Bearer Token (JWT):",
          },
        ]);
        if (token) {
          config.auth = { token };
          console.log(chalk.green("  ✓ Token configured."));
        }
      } else if (authMethod === "config") {
        console.log(
          chalk.cyan(
            "\n  📝 Create a .vibetest.json file in your project root:",
          ),
        );
        console.log(chalk.gray("\n" + generateConfigExample()));
        console.log(
          chalk.yellow(
            "\n  💡 Run vibetest again after creating the config file.\n",
          ),
        );
        await logTestAttempt({
          status: "config_instructions_shown",
          config: { baseUrl: config.baseUrl, apiUrl: config.apiUrl },
          timestamp: new Date().toISOString(),
        });
        process.exit(0);
      }
    }
    console.log(""); // spacer
  }

  // 2. Discovery
  spinner.start("Mapping application topology...");
  const routes = await discoverRoutes(config.baseUrl);
  spinner.succeed(`Discovered ${routes.length} potential endpoints`);

  if (routes.length === 0) {
    console.log(chalk.yellow("  No routes found. Is the app running?"));
  } else {
    routes
      .slice(0, 5)
      .forEach((r) => console.log(chalk.gray(`  - ${r.method} ${r.path}`)));
    if (routes.length > 5)
      console.log(chalk.gray(`  ...and ${routes.length - 5} more`));
  }

  // 3. Execution
  console.log(chalk.bold.blue("\n🧪 Starting Vulnerability Analysis\n"));

  const findings: Finding[] = [];

  // Create axios instance with rate limit detection
  const createAxiosInstance = (baseURL: string) => {
    const instance = axios.create({
      baseURL,
      validateStatus: () => true, // Don't throw on 4xx/5xx
    });

    // Rate limit detection patterns
    const RATE_LIMIT_INDICATORS = [
      "/blocked",
      "/rate-limit",
      "/too-many-requests",
      "rate limit exceeded",
      "too many requests",
    ];

    let rateLimitHits = 0;
    const BASE_WAIT_TIME = 3000; // Start with 3 seconds
    const MAX_RATE_LIMIT_BEFORE_PROMPT = 5;

    // Intercept responses to detect rate limiting
    instance.interceptors.response.use(async (response) => {
      // Check for 429 or rate limit indicators
      const isRateLimited =
        response.status === 429 ||
        RATE_LIMIT_INDICATORS.some(
          (indicator) =>
            response.request.path?.includes(indicator) ||
            JSON.stringify(response.data)?.toLowerCase().includes(indicator),
        );

      if (isRateLimited) {
        rateLimitHits++;

        // Get the endpoint/path that was rate limited
        const endpoint =
          response.request?.path || response.config?.url || "unknown";

        if (rateLimitHits <= MAX_RATE_LIMIT_BEFORE_PROMPT) {
          // Cap at 9s: 3s, 6s, 9s, 9s, 9s
          const waitTime = Math.min(
            BASE_WAIT_TIME * rateLimitHits,
            BASE_WAIT_TIME * 3,
          );
          const limitDisplay = config.autoContinue
            ? "∞"
            : MAX_RATE_LIMIT_BEFORE_PROMPT;
          console.log(
            chalk.yellow(
              `\n  ⏸️  Rate limit hit: ${endpoint}\n     Pausing for ${waitTime / 1000}s... (${rateLimitHits}/${limitDisplay})`,
            ),
          );
          await new Promise((resolve) => setTimeout(resolve, waitTime));
        }

        if (rateLimitHits === MAX_RATE_LIMIT_BEFORE_PROMPT) {
          // After 5 rate limits, ask user if they want to continue (unless auto-continue is enabled)
          console.log(
            chalk.red(
              `\n  🚨 Hit ${MAX_RATE_LIMIT_BEFORE_PROMPT} rate limits. The target application is heavily rate-limiting requests.`,
            ),
          );

          if (config.autoContinue) {
            // Auto-continue without prompting
            console.log(
              chalk.green(
                "\n  ▶️  Auto-continuing with 9s delays (--auto-continue enabled)...\n",
              ),
            );
          } else if (process.stdout.isTTY) {
            const { shouldContinue } = await inquirer.prompt([
              {
                type: "confirm",
                name: "shouldContinue",
                message:
                  "Continue testing? (This may take significantly longer)",
                default: false,
              },
            ]);

            if (!shouldContinue) {
              console.log(chalk.yellow("\n  ⏹️  Testing aborted by user.\n"));
              await logTestAttempt({
                status: "aborted_by_user_rate_limit",
                config: { baseUrl: config.baseUrl, apiUrl: config.apiUrl },
                discoveredRoutesCount: routes.length,
                timestamp: new Date().toISOString(),
              });
              process.exit(0);
            } else {
              console.log(
                chalk.green("\n  ▶️  Continuing with increased delays...\n"),
              );
            }
          } else {
            // Non-interactive mode, continue but with longer delays
            console.log(
              chalk.yellow("\n  ⚠️  Continuing with increased delays...\n"),
            );
          }
        } else if (rateLimitHits > MAX_RATE_LIMIT_BEFORE_PROMPT) {
          // After user confirms, stay at 9s
          const endpoint =
            response.request?.path || response.config?.url || "unknown";
          const waitTime = BASE_WAIT_TIME * 3; // Stay at 9 seconds
          console.log(
            chalk.yellow(
              `\n  ⏸️  Rate limit hit: ${endpoint}\n     Pausing for ${waitTime / 1000}s... (hit #${rateLimitHits})`,
            ),
          );
          await new Promise((resolve) => setTimeout(resolve, waitTime));
        }
      }
      return response;
    });

    return instance;
  };

  const axiosInstance = createAxiosInstance(config.baseUrl);
  const apiAxiosInstance = config.apiUrl
    ? createAxiosInstance(config.apiUrl)
    : axiosInstance;

  if (config.apiUrl) {
    console.log(chalk.gray(`  Frontend: ${config.baseUrl}`));
    console.log(chalk.gray(`  Backend API: ${config.apiUrl}`));
  }

  const context = {
    config,
    axios: axiosInstance,
    apiAxios: apiAxiosInstance,
    discoveredRoutes: routes,
  };

  for (const check of checks) {
    const checkSpinner = ora(`Running: ${check.name}`).start();
    try {
      const checkFindings = await check.run(context);
      if (checkFindings.length > 0) {
        checkSpinner.fail(chalk.red(`${check.name} found issues`));
        findings.push(...checkFindings);
      } else {
        checkSpinner.succeed(check.name);
      }
    } catch (e: any) {
      checkSpinner.warn(`Check ${check.name} failed to complete: ${e.message}`);
    }
  }

  // 4. Report
  printReport(findings);

  // 5. Export Reports
  if (findings.length > 0) {
    try {
      const reportsDir = path.join(process.cwd(), "vibetest-reports");
      if (!fs.existsSync(reportsDir)) {
        fs.mkdirSync(reportsDir, { recursive: true });
      }

      const timestamp = new Date().toISOString().replace(/:/g, "-").split(".")[0];
      const metadata = {
        target: config.baseUrl,
        scanDate: new Date().toISOString(),
        routesTested: routes.length,
        checksRun: checks.length,
      };

      console.log(chalk.bold.cyan("\n📤 Exporting Reports...\n"));

      exportToJSON(
        findings,
        metadata,
        path.join(reportsDir, `vibetest-report-${timestamp}.json`),
      );
      exportToMarkdown(
        findings,
        metadata,
        path.join(reportsDir, `vibetest-report-${timestamp}.md`),
      );
      exportToHTML(
        findings,
        metadata,
        path.join(reportsDir, `vibetest-report-${timestamp}.html`),
      );

      console.log(
        chalk.green(`\n✅ All reports exported to: ${reportsDir}\n`),
      );
    } catch (error: any) {
      console.log(
        chalk.yellow(`  ⚠ Could not export reports: ${error.message}`),
      );
    }
  }

  await logTestAttempt({
    status: "completed",
    config: {
      baseUrl: config.baseUrl,
      apiUrl: config.apiUrl,
      // avoid writing large or non-serializable items
      auth: config.auth,
      options: (config as any).options || null,
    },
    discoveredRoutesCount: routes.length,
    findings,
    timestamp: new Date().toISOString(),
  });
}

import * as fs from "fs";
import * as path from "path";

// Helper: Calculate overall risk level
function calculateOverallRisk(findings: Finding[]): string {
  if (findings.some((f) => f.risk === "critical")) return "Critical";
  if (findings.some((f) => f.risk === "high")) return "High";
  if (findings.some((f) => f.risk === "medium")) return "Medium";
  return "Low";
}

// Helper: Group findings by severity
function groupBySeverity(findings: Finding[]) {
  return {
    critical: findings.filter((f) => f.risk === "critical"),
    high: findings.filter((f) => f.risk === "high"),
    medium: findings.filter((f) => f.risk === "medium"),
    low: findings.filter((f) => f.risk === "low"),
  };
}

// Helper: Group findings by check ID
function groupByCheckId(findings: Finding[]): Record<string, Finding[]> {
  const groups: Record<string, Finding[]> = {};
  findings.forEach((f) => {
    if (!groups[f.checkId]) groups[f.checkId] = [];
    groups[f.checkId].push(f);
  });
  return groups;
}

// Helper: Calculate remediation priority
function calculateRemediationPriority(findings: Finding[]) {
  const scored = findings.map((f) => {
    let score = 0;
    if (f.risk === "critical") score += 100;
    else if (f.risk === "high") score += 75;
    else if (f.risk === "medium") score += 50;
    else score += 25;

    // Boost injection types
    if (
      f.checkId.includes("injection") ||
      f.checkId.includes("xss") ||
      f.checkId.includes("sql")
    ) {
      score += 10;
    }

    return { finding: f, score };
  });

  return scored.sort((a, b) => b.score - a.score).map((s) => s.finding);
}

// Export to JSON
function exportToJSON(
  findings: Finding[],
  metadata: any,
  outputPath: string,
): void {
  const report = {
    metadata,
    summary: {
      totalIssues: findings.length,
      overallRisk: calculateOverallRisk(findings),
      bySeverity: {
        critical: findings.filter((f) => f.risk === "critical").length,
        high: findings.filter((f) => f.risk === "high").length,
        medium: findings.filter((f) => f.risk === "medium").length,
        low: findings.filter((f) => f.risk === "low").length,
      },
      byCategory: {
        backend: findings.filter((f) => f.category === "backend").length,
        frontend: findings.filter((f) => f.category === "frontend").length,
        config: findings.filter((f) => f.category === "config").length,
        logic: findings.filter((f) => f.category === "logic").length,
      },
    },
    findings,
  };

  fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
  console.log(chalk.green(`  ✓ JSON report saved: ${outputPath}`));
}

// Export to Markdown
function exportToMarkdown(
  findings: Finding[],
  metadata: any,
  outputPath: string,
): void {
  let md = `# VIBETEST Security Scan Report\n\n`;
  md += `**Target:** ${metadata.target}\n`;
  md += `**Scan Date:** ${metadata.scanDate}\n`;
  md += `**Routes Tested:** ${metadata.routesTested}\n`;
  md += `**Checks Run:** ${metadata.checksRun}\n\n`;

  md += `---\n\n`;
  md += `## Executive Summary\n\n`;
  md += `**Overall Risk Level:** ${calculateOverallRisk(findings)}\n`;
  md += `**Total Issues Found:** ${findings.length}\n\n`;

  const bySeverity = groupBySeverity(findings);
  if (bySeverity.critical.length > 0)
    md += `- ⛔ **${bySeverity.critical.length} CRITICAL** issues require immediate attention\n`;
  if (bySeverity.high.length > 0)
    md += `- 🔴 **${bySeverity.high.length} HIGH** severity issues found\n`;
  if (bySeverity.medium.length > 0)
    md += `- 🟡 **${bySeverity.medium.length} MEDIUM** severity issues found\n`;
  if (bySeverity.low.length > 0)
    md += `- 🔵 **${bySeverity.low.length} LOW** severity issues found\n`;

  md += `\n### Top Vulnerability Types\n\n`;
  const byCheckId = groupByCheckId(findings);
  const topChecks = Object.entries(byCheckId)
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 5);

  topChecks.forEach(([checkId, items]) => {
    md += `- **${checkId}**: ${items.length} issue(s)\n`;
  });

  md += `\n---\n\n`;
  md += `## Findings by Severity\n\n`;

  const printFindingsMD = (severity: string, items: Finding[]) => {
    if (items.length === 0) return;
    md += `### ${severity.toUpperCase()} (${items.length})\n\n`;

    items.forEach((f, idx) => {
      md += `#### ${idx + 1}. ${f.name}\n\n`;
      md += `**Endpoint:** \`${f.endpoint}\`\n\n`;
      md += `**Description:** ${f.description}\n\n`;
      md += `**Fix:** ${f.fix}\n\n`;
      md += `**Reproduction:**\n\`\`\`\n${f.reproduction}\n\`\`\`\n\n`;
      md += `---\n\n`;
    });
  };

  printFindingsMD("Critical", bySeverity.critical);
  printFindingsMD("High", bySeverity.high);
  printFindingsMD("Medium", bySeverity.medium);
  printFindingsMD("Low", bySeverity.low);

  md += `\n## Remediation Priority (Top 10)\n\n`;
  const prioritized = calculateRemediationPriority(findings).slice(0, 10);
  prioritized.forEach((f, idx) => {
    md += `${idx + 1}. **[${f.risk.toUpperCase()}]** ${f.name} - \`${f.endpoint}\`\n`;
  });

  md += `\n\n---\n\n`;
  md += `*Report generated by [Vibetest](https://github.com/vibetest/vibetest)*\n`;

  fs.writeFileSync(outputPath, md);
  console.log(chalk.green(`  ✓ Markdown report saved: ${outputPath}`));
}

// Export to HTML
function exportToHTML(
  findings: Finding[],
  metadata: any,
  outputPath: string,
): void {
  const bySeverity = groupBySeverity(findings);
  const overallRisk = calculateOverallRisk(findings);

  let html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vibetest Security Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #d32f2f; border-bottom: 3px solid #d32f2f; padding-bottom: 10px; }
        h2 { color: #333; margin-top: 30px; }
        .metadata { background: #f9f9f9; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .metadata p { margin: 5px 0; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .summary-card { background: #fff; padding: 20px; border-radius: 8px; border-left: 4px solid #2196f3; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .summary-card.critical { border-left-color: #d32f2f; }
        .summary-card.high { border-left-color: #f57c00; }
        .summary-card.medium { border-left-color: #fbc02d; }
        .summary-card.low { border-left-color: #0288d1; }
        .summary-card h3 { margin: 0 0 10px 0; font-size: 14px; color: #666; }
        .summary-card .count { font-size: 32px; font-weight: bold; color: #333; }
        .finding { background: #fff; margin: 20px 0; padding: 20px; border-radius: 8px; border-left: 4px solid #ccc; }
        .finding.critical { border-left-color: #d32f2f; }
        .finding.high { border-left-color: #f57c00; }
        .finding.medium { border-left-color: #fbc02d; }
        .finding.low { border-left-color: #0288d1; }
        .finding h3 { margin: 0 0 10px 0; color: #333; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; color: white; }
        .badge.critical { background: #d32f2f; }
        .badge.high { background: #f57c00; }
        .badge.medium { background: #fbc02d; color: #333; }
        .badge.low { background: #0288d1; }
        .endpoint { font-family: monospace; background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }
        .fix { background: #e8f5e9; padding: 15px; border-radius: 4px; margin-top: 10px; border-left: 3px solid #4caf50; }
        pre { background: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ VIBETEST Security Scan Report</h1>

        <div class="metadata">
            <p><strong>Target:</strong> ${metadata.target}</p>
            <p><strong>Scan Date:</strong> ${metadata.scanDate}</p>
            <p><strong>Routes Tested:</strong> ${metadata.routesTested}</p>
            <p><strong>Checks Run:</strong> ${metadata.checksRun}</p>
        </div>

        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="summary-card ${overallRisk.toLowerCase()}">
                <h3>Overall Risk</h3>
                <div class="count">${overallRisk}</div>
            </div>
            <div class="summary-card">
                <h3>Total Issues</h3>
                <div class="count">${findings.length}</div>
            </div>
            <div class="summary-card critical">
                <h3>Critical</h3>
                <div class="count">${bySeverity.critical.length}</div>
            </div>
            <div class="summary-card high">
                <h3>High</h3>
                <div class="count">${bySeverity.high.length}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium</h3>
                <div class="count">${bySeverity.medium.length}</div>
            </div>
            <div class="summary-card low">
                <h3>Low</h3>
                <div class="count">${bySeverity.low.length}</div>
            </div>
        </div>

        <h2>Findings by Severity</h2>`;

  const printFindingsHTML = (severity: string, items: Finding[]) => {
    if (items.length === 0) return;
    html += `<h3>${severity.toUpperCase()} (${items.length})</h3>`;

    items.forEach((f) => {
      html += `
        <div class="finding ${f.risk}">
            <span class="badge ${f.risk}">${f.risk.toUpperCase()}</span>
            <h3>${f.name}</h3>
            <p><strong>Endpoint:</strong> <span class="endpoint">${f.endpoint}</span></p>
            <p>${f.description}</p>
            <div class="fix">
                <strong>Fix:</strong> ${f.fix}
            </div>
            <details>
                <summary><strong>Reproduction Steps</strong></summary>
                <pre>${f.reproduction}</pre>
            </details>
        </div>`;
    });
  };

  printFindingsHTML("Critical", bySeverity.critical);
  printFindingsHTML("High", bySeverity.high);
  printFindingsHTML("Medium", bySeverity.medium);
  printFindingsHTML("Low", bySeverity.low);

  html += `
        <h2>Remediation Priority (Top 10)</h2>
        <ol>`;

  const prioritized = calculateRemediationPriority(findings).slice(0, 10);
  prioritized.forEach((f) => {
    html += `<li><span class="badge ${f.risk}">${f.risk.toUpperCase()}</span> ${f.name} - <span class="endpoint">${f.endpoint}</span></li>`;
  });

  html += `
        </ol>

        <hr style="margin: 40px 0;">
        <p style="text-align: center; color: #666;">
            Report generated by <a href="https://github.com/vibetest/vibetest">Vibetest</a>
        </p>
    </div>
</body>
</html>`;

  fs.writeFileSync(outputPath, html);
  console.log(chalk.green(`  ✓ HTML report saved: ${outputPath}`));
}

function printReport(findings: Finding[]) {
  if (findings.length === 0) {
    console.log(
      chalk.green(
        "\n✨ No obvious vulnerabilities found. Good vibes only! ✨\n",
      ),
    );
    return;
  }

  // Report Header
  console.log(chalk.bold.white("\n" + "=".repeat(80)));
  console.log(chalk.bold.white("  VIBETEST SECURITY SCAN REPORT"));
  console.log(chalk.bold.white("=".repeat(80)));

  // Executive Summary
  const overallRisk = calculateOverallRisk(findings);
  const bySeverity = groupBySeverity(findings);

  console.log(chalk.bold.cyan("\n📊 EXECUTIVE SUMMARY\n"));
  console.log(
    chalk.bold(`Overall Risk Level: ${overallRisk === "Critical" ? chalk.bgRed.white(` ${overallRisk} `) : overallRisk === "High" ? chalk.red(overallRisk) : overallRisk === "Medium" ? chalk.yellow(overallRisk) : chalk.blue(overallRisk)}`),
  );
  console.log(chalk.bold(`Total Issues Found: ${findings.length}\n`));

  if (bySeverity.critical.length > 0)
    console.log(
      chalk.bgRed.white(
        ` ${bySeverity.critical.length} CRITICAL `,
      ) + chalk.red(` issues require immediate attention`),
    );
  if (bySeverity.high.length > 0)
    console.log(
      chalk.red(`${bySeverity.high.length} HIGH`) + ` severity issues found`,
    );
  if (bySeverity.medium.length > 0)
    console.log(
      chalk.yellow(`${bySeverity.medium.length} MEDIUM`) +
        ` severity issues found`,
    );
  if (bySeverity.low.length > 0)
    console.log(
      chalk.blue(`${bySeverity.low.length} LOW`) + ` severity issues found`,
    );

  // Top vulnerability types
  console.log(chalk.bold.cyan("\nTop Vulnerability Types:"));
  const byCheckId = groupByCheckId(findings);
  const topChecks = Object.entries(byCheckId)
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 5);

  topChecks.forEach(([checkId, items]) => {
    console.log(chalk.gray(`  - ${checkId}: ${items.length} issue(s)`));
  });

  // Group by category and risk (risk-first ordering)
  const categories = {
    backend: [] as Finding[],
    frontend: [] as Finding[],
    config: [] as Finding[],
    logic: [] as Finding[],
    uncategorized: [] as Finding[],
  };

  findings.forEach((f) => {
    const cat = f.category || "uncategorized";
    if (categories[cat]) {
      categories[cat].push(f);
    } else {
      categories.uncategorized.push(f);
    }
  });

  // Sort each category by risk
  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  Object.keys(categories).forEach((cat) => {
    categories[cat as keyof typeof categories].sort(
      (a, b) => riskOrder[a.risk] - riskOrder[b.risk],
    );
  });

  console.log(chalk.bold.cyan("\n📁 FINDINGS BY CATEGORY & RISK\n"));

  const printCategory = (title: string, items: Finding[]) => {
    if (items.length === 0) return;
    console.log(chalk.bold.magenta(`\n${title} (${items.length})`));
    console.log(chalk.gray("─".repeat(title.length + 5)));

    items.forEach((f) => {
      const riskColor =
        f.risk === "critical"
          ? chalk.bgRed.white
          : f.risk === "high"
            ? chalk.red
            : f.risk === "medium"
              ? chalk.yellow
              : chalk.blue;

      console.log(
        `\n${riskColor(`[${f.risk.toUpperCase()}]`)} ${chalk.bold(f.name)}`,
      );
      console.log(chalk.gray(`   Endpoint: ${f.endpoint}`));
      console.log(`   ${chalk.white(f.description)}`);
      console.log(`   ${chalk.green.dim("Fix:")} ${f.fix}`);
    });
  };

  printCategory("Backend API & Auth", categories.backend);
  printCategory("Frontend & Client Assets", categories.frontend);
  printCategory("Business Logic", categories.logic);
  printCategory("Configuration & Headers", categories.config);
  printCategory("General / Uncategorized", categories.uncategorized);

  // Remediation Priority
  console.log(chalk.bold.cyan("\n🎯 REMEDIATION PRIORITY (Top 10)\n"));
  const prioritized = calculateRemediationPriority(findings).slice(0, 10);
  prioritized.forEach((f, idx) => {
    const riskColor =
      f.risk === "critical"
        ? chalk.bgRed.white
        : f.risk === "high"
          ? chalk.red
          : f.risk === "medium"
            ? chalk.yellow
            : chalk.blue;
    console.log(
      `  ${idx + 1}. ${riskColor(`[${f.risk.toUpperCase()}]`)} ${f.name} - ${chalk.gray(f.endpoint)}`,
    );
  });

  console.log(chalk.bold.white("\n" + "=".repeat(80) + "\n"));
}
