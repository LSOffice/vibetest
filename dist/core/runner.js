"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runVibeTest = runVibeTest;
const chalk_1 = __importDefault(require("chalk"));
const ora_1 = __importDefault(require("ora"));
const axios_1 = __importDefault(require("axios"));
const crawler_js_1 = require("./crawler.js");
const index_js_1 = require("../checks/index.js");
const inquirer_1 = __importDefault(require("inquirer"));
const auth_discovery_js_1 = require("./auth-discovery.js");
const logger_js_1 = require("./logger.js");
async function runVibeTest(config) {
    const spinner = (0, ora_1.default)("Connecting to target...").start();
    // 1. Connectivity Check
    try {
        await axios_1.default.get(config.baseUrl);
        spinner.succeed(`Connected to ${config.baseUrl}`);
    }
    catch (e) {
        spinner.fail(`Could not connect to ${config.baseUrl}: ${e.message}`);
        await (0, logger_js_1.logTestAttempt)({
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
        const discoveredAuth = await (0, auth_discovery_js_1.discoverAuth)(config.baseUrl);
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
        const { wantAuth } = await inquirer_1.default.prompt([
            {
                type: "confirm",
                name: "wantAuth",
                message: "No auth credentials found. Do you want to authenticate now?",
                default: false,
            },
        ]);
        if (wantAuth) {
            const { authMethod } = await inquirer_1.default.prompt([
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
                const capturedAuth = await (0, auth_discovery_js_1.captureAuthFromBrowser)(config.baseUrl);
                if (capturedAuth) {
                    config.auth = capturedAuth;
                    console.log(chalk_1.default.green("  ✓ Authentication configured from browser."));
                    // Ask if they want to save it
                    const { shouldSave } = await inquirer_1.default.prompt([
                        {
                            type: "confirm",
                            name: "shouldSave",
                            message: "Save these credentials to .vibetest.json for future use?",
                            default: true,
                        },
                    ]);
                    if (shouldSave) {
                        const fs = await import("fs");
                        fs.writeFileSync(".vibetest.json", JSON.stringify(capturedAuth, null, 2));
                        console.log(chalk_1.default.green("  ✓ Saved to .vibetest.json"));
                    }
                }
                else {
                    console.log(chalk_1.default.yellow("  ⚠ Could not capture authentication. Continuing without auth..."));
                }
            }
            else if (authMethod === "token") {
                const { token } = await inquirer_1.default.prompt([
                    {
                        type: "input",
                        name: "token",
                        message: "Enter Bearer Token (JWT):",
                    },
                ]);
                if (token) {
                    config.auth = { token };
                    console.log(chalk_1.default.green("  ✓ Token configured."));
                }
            }
            else if (authMethod === "config") {
                console.log(chalk_1.default.cyan("\n  📝 Create a .vibetest.json file in your project root:"));
                console.log(chalk_1.default.gray("\n" + (0, auth_discovery_js_1.generateConfigExample)()));
                console.log(chalk_1.default.yellow("\n  💡 Run vibetest again after creating the config file.\n"));
                await (0, logger_js_1.logTestAttempt)({
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
    const routes = await (0, crawler_js_1.discoverRoutes)(config.baseUrl);
    spinner.succeed(`Discovered ${routes.length} potential endpoints`);
    if (routes.length === 0) {
        console.log(chalk_1.default.yellow("  No routes found. Is the app running?"));
    }
    else {
        routes
            .slice(0, 5)
            .forEach((r) => console.log(chalk_1.default.gray(`  - ${r.method} ${r.path}`)));
        if (routes.length > 5)
            console.log(chalk_1.default.gray(`  ...and ${routes.length - 5} more`));
    }
    // 3. Execution
    console.log(chalk_1.default.bold.blue("\n🧪 Starting Vulnerability Analysis\n"));
    const findings = [];
    // Create axios instance with rate limit detection
    const createAxiosInstance = (baseURL) => {
        const instance = axios_1.default.create({
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
            const isRateLimited = response.status === 429 ||
                RATE_LIMIT_INDICATORS.some((indicator) => response.request.path?.includes(indicator) ||
                    JSON.stringify(response.data)?.toLowerCase().includes(indicator));
            if (isRateLimited) {
                rateLimitHits++;
                if (rateLimitHits <= MAX_RATE_LIMIT_BEFORE_PROMPT) {
                    // Exponentially increase wait time: 3s, 6s, 9s, 12s, 15s
                    const waitTime = BASE_WAIT_TIME * rateLimitHits;
                    console.log(chalk_1.default.yellow(`\n  ⏸️  Rate limit detected. Pausing for ${waitTime / 1000}s... (${rateLimitHits}/${MAX_RATE_LIMIT_BEFORE_PROMPT})`));
                    await new Promise((resolve) => setTimeout(resolve, waitTime));
                }
                if (rateLimitHits === MAX_RATE_LIMIT_BEFORE_PROMPT) {
                    // After 5 rate limits, ask user if they want to continue
                    console.log(chalk_1.default.red(`\n  🚨 Hit ${MAX_RATE_LIMIT_BEFORE_PROMPT} rate limits. The target application is heavily rate-limiting requests.`));
                    if (process.stdout.isTTY) {
                        const { shouldContinue } = await inquirer_1.default.prompt([
                            {
                                type: "confirm",
                                name: "shouldContinue",
                                message: "Continue testing? (This may take significantly longer)",
                                default: false,
                            },
                        ]);
                        if (!shouldContinue) {
                            console.log(chalk_1.default.yellow("\n  ⏹️  Testing aborted by user.\n"));
                            await (0, logger_js_1.logTestAttempt)({
                                status: "aborted_by_user_rate_limit",
                                config: { baseUrl: config.baseUrl, apiUrl: config.apiUrl },
                                discoveredRoutesCount: routes.length,
                                timestamp: new Date().toISOString(),
                            });
                            process.exit(0);
                        }
                        else {
                            console.log(chalk_1.default.green("\n  ▶️  Continuing with increased delays...\n"));
                        }
                    }
                    else {
                        // Non-interactive mode, continue but with longer delays
                        console.log(chalk_1.default.yellow("\n  ⚠️  Continuing with increased delays...\n"));
                    }
                }
                else if (rateLimitHits > MAX_RATE_LIMIT_BEFORE_PROMPT) {
                    // After user confirms, use even longer waits
                    const waitTime = BASE_WAIT_TIME * 5; // 15 seconds
                    console.log(chalk_1.default.yellow(`\n  ⏸️  Rate limit detected. Pausing for ${waitTime / 1000}s... (hit #${rateLimitHits})`));
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
        console.log(chalk_1.default.gray(`  Frontend: ${config.baseUrl}`));
        console.log(chalk_1.default.gray(`  Backend API: ${config.apiUrl}`));
    }
    const context = {
        config,
        axios: axiosInstance,
        apiAxios: apiAxiosInstance,
        discoveredRoutes: routes,
    };
    for (const check of index_js_1.checks) {
        const checkSpinner = (0, ora_1.default)(`Running: ${check.name}`).start();
        try {
            const checkFindings = await check.run(context);
            if (checkFindings.length > 0) {
                checkSpinner.fail(chalk_1.default.red(`${check.name} found issues`));
                findings.push(...checkFindings);
            }
            else {
                checkSpinner.succeed(check.name);
            }
        }
        catch (e) {
            checkSpinner.warn(`Check ${check.name} failed to complete: ${e.message}`);
        }
    }
    // 4. Report
    printReport(findings);
    await (0, logger_js_1.logTestAttempt)({
        status: "completed",
        config: {
            baseUrl: config.baseUrl,
            apiUrl: config.apiUrl,
            // avoid writing large or non-serializable items
            auth: config.auth,
            options: config.options || null,
        },
        discoveredRoutesCount: routes.length,
        findings,
        timestamp: new Date().toISOString(),
    });
}
function printReport(findings) {
    if (findings.length === 0) {
        console.log(chalk_1.default.green("\n✨ No obvious vulnerabilities found. Good vibes only! ✨\n"));
        return;
    }
    console.log(chalk_1.default.bold.underline.red(`\n🚫 Found ${findings.length} Issues\n`));
    // Group by category
    const categories = {
        backend: [],
        frontend: [],
        config: [],
        logic: [],
        uncategorized: [],
    };
    findings.forEach((f) => {
        const cat = f.category || "uncategorized";
        if (categories[cat]) {
            categories[cat].push(f);
        }
        else {
            categories.uncategorized.push(f);
        }
    });
    const printCategory = (title, items) => {
        if (items.length === 0)
            return;
        console.log(chalk_1.default.bold.magenta(`\n📂 ${title} (${items.length})`));
        console.log(chalk_1.default.gray("=".repeat(title.length + 5)));
        items.forEach((f) => {
            const riskColor = f.risk === "critical"
                ? chalk_1.default.bgRed.white
                : f.risk === "high"
                    ? chalk_1.default.red
                    : f.risk === "medium"
                        ? chalk_1.default.yellow
                        : chalk_1.default.blue;
            console.log(`${riskColor(`[${f.risk.toUpperCase()}]`)} ${chalk_1.default.bold(f.name)}`);
            console.log(chalk_1.default.gray(`   Endpoint: ${f.endpoint}`));
            console.log(`   ${chalk_1.default.white(f.description)}`);
            console.log(`   ${chalk_1.default.green.dim("Fix:")} ${f.fix}`);
            console.log("");
        });
    };
    printCategory("Backend API & Auth", categories.backend);
    printCategory("Frontend & Client Assets", categories.frontend);
    printCategory("Business Logic", categories.logic);
    printCategory("Configuration & Headers", categories.config);
    printCategory("General / Uncategorized", categories.uncategorized);
}
