#!/usr/bin/env node
const chalk = require("chalk");
const boxen = require("boxen");

const lines = [
  chalk.green("✅ vibetest command installed globally!"),
  "",
  chalk.cyan("📝 Usage:") + " " + chalk.bold("vibetest -p <port> [options]"),
  "",
  chalk.yellow("💡 Examples:"),
  "   " + chalk.white("vibetest -p 3000"),
  "   " + chalk.white("vibetest -p 3000 --api-port 8080"),
  "   " + chalk.white("vibetest --help"),
];

const message = lines.join("\n");

console.log(
  boxen(message, {
    padding: 1,
    margin: 1,
    borderStyle: "round",
    float: "center",
  }),
);
