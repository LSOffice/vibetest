#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const commander_1 = require("commander");
const chalk_1 = __importDefault(require("chalk"));
const runner_js_1 = require("./core/runner.js");
const program = new commander_1.Command();
program
    .name("vibetest")
    .description("Localhost-only pentesting CLI for modern web apps")
    .version("0.0.1")
    .requiredOption("-p, --port <number>", "Port to attach to (e.g. 3000)")
    .option("--api-port <number>", "Separate port for backend API (if different from frontend)")
    .option("--host <string>", "Host to bind to", "localhost")
    .option("--token <string>", "Bearer token for authentication")
    .option("--safe", "Run only safe checks", true)
    .action(async (options) => {
    console.log(chalk_1.default.bold.magenta("\n🔮 Vibetest initialized...\n"));
    if (options.host !== "localhost" && options.host !== "127.0.0.1") {
        console.warn(chalk_1.default.yellow("⚠️  Warning: Testing non-localhost targets is discouraged used Vibetest."));
    }
    try {
        const frontendUrl = `http://${options.host}:${options.port}`;
        const apiUrl = options.apiPort
            ? `http://${options.host}:${options.apiPort}`
            : frontendUrl;
        await (0, runner_js_1.runVibeTest)({
            port: parseInt(options.port),
            apiPort: options.apiPort ? parseInt(options.apiPort) : undefined,
            baseUrl: frontendUrl,
            apiUrl: apiUrl !== frontendUrl ? apiUrl : undefined,
            auth: options.token ? { token: options.token } : undefined,
            safeMode: options.safe,
        });
    }
    catch (error) {
        console.error(chalk_1.default.red("Fatal Error:"), error.message);
        process.exit(1);
    }
});
program.parse();
