import chalk from "chalk";
import ora from "ora";
import axios from "axios";
import { VibeConfig, Route, Finding } from "./types.js";
import { discoverRoutes } from "./crawler.js";
import { checks } from "../checks/index.js";
import inquirer from "inquirer";

export async function runVibeTest(config: VibeConfig) {
  const spinner = ora("Connecting to target...").start();

  // 1. Connectivity Check
  try {
    await axios.get(config.baseUrl);
    spinner.succeed(`Connected to ${config.baseUrl}`);
  } catch (e: any) {
    spinner.fail(`Could not connect to ${config.baseUrl}: ${e.message}`);
    return;
  }

  // Interactive Login Check
  if (!config.auth?.token && process.stdout.isTTY) {
    console.log(""); // spacer
    const { wantAuth } = await inquirer.prompt([
      {
        type: "confirm",
        name: "wantAuth",
        message: "No auth token provided. Do you want to authenticate now?",
        default: false,
      },
    ]);

    if (wantAuth) {
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
    const MAX_RATE_LIMIT_HITS = 3;

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
        if (rateLimitHits <= MAX_RATE_LIMIT_HITS) {
          const waitTime = 3000; // 3 seconds
          console.log(
            chalk.yellow(
              `\n  ⏸️  Rate limit detected. Pausing for ${waitTime / 1000}s... (${rateLimitHits}/${MAX_RATE_LIMIT_HITS})`,
            ),
          );
          await new Promise((resolve) => setTimeout(resolve, waitTime));
        } else if (rateLimitHits === MAX_RATE_LIMIT_HITS + 1) {
          console.log(
            chalk.yellow(
              `\n  ⚠️  Multiple rate limits hit. Continuing with caution...`,
            ),
          );
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
