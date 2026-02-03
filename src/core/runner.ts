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

function printReport(findings: Finding[]) {
  if (findings.length === 0) {
    console.log(
      chalk.green(
        "\n✨ No obvious vulnerabilities found. Good vibes only! ✨\n",
      ),
    );
    return;
  }

  console.log(
    chalk.bold.underline.red(`\n🚫 Found ${findings.length} Issues\n`),
  );

  // Group by category
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

  const printCategory = (title: string, items: Finding[]) => {
    if (items.length === 0) return;
    console.log(chalk.bold.magenta(`\n📂 ${title} (${items.length})`));
    console.log(chalk.gray("=".repeat(title.length + 5)));

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
        `${riskColor(`[${f.risk.toUpperCase()}]`)} ${chalk.bold(f.name)}`,
      );
      console.log(chalk.gray(`   Endpoint: ${f.endpoint}`));
      console.log(`   ${chalk.white(f.description)}`);
      console.log(`   ${chalk.green.dim("Fix:")} ${f.fix}`);
      console.log("");
    });
  };

  printCategory("Backend API & Auth", categories.backend);
  printCategory("Frontend & Client Assets", categories.frontend);
  printCategory("Business Logic", categories.logic);
  printCategory("Configuration & Headers", categories.config);
  printCategory("General / Uncategorized", categories.uncategorized);
}
