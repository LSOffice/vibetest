#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import { runVibeTest } from "./core/runner.js";

const program = new Command();

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
    console.log(chalk.bold.magenta("\n🔮 Vibetest initialized...\n"));

    if (options.host !== "localhost" && options.host !== "127.0.0.1") {
      console.warn(
        chalk.yellow(
          "⚠️  Warning: Testing non-localhost targets is discouraged used Vibetest.",
        ),
      );
    }

    try {
      const frontendUrl = `http://${options.host}:${options.port}`;
      const apiUrl = options.apiPort 
        ? `http://${options.host}:${options.apiPort}` 
        : frontendUrl;

      await runVibeTest({
        port: parseInt(options.port),
        apiPort: options.apiPort ? parseInt(options.apiPort) : undefined,
        baseUrl: frontendUrl,
        apiUrl: apiUrl !== frontendUrl ? apiUrl : undefined,
        auth: options.token ? { token: options.token } : undefined,
        safeMode: options.safe,
      });
    } catch (error: any) {
      console.error(chalk.red("Fatal Error:"), error.message);
      process.exit(1);
    }
  });

program.parse();
