import { existsSync, readFileSync } from "fs";
import { homedir } from "os";
import { join } from "path";
import chalk from "chalk";
import puppeteer from "puppeteer";

export interface AuthCredentials {
  token?: string;
  cookies?: Record<string, string>;
  headers?: Record<string, string>;
}

/**
 * Attempts to automatically discover authentication credentials from multiple sources
 */
export async function discoverAuth(
  baseUrl: string,
): Promise<AuthCredentials | null> {
  console.log(chalk.gray("  🔍 Looking for authentication credentials...\n"));

  // 1. Check for .vibetest.json in current directory
  const localConfig = await loadLocalConfig();
  if (localConfig) {
    console.log(chalk.green("  ✓ Found credentials in .vibetest.json"));
    return localConfig;
  }

  // 2. Check environment variables
  const envAuth = loadFromEnv();
  if (envAuth) {
    console.log(chalk.green("  ✓ Found token in environment variable"));
    return envAuth;
  }

  // 3. Try to extract cookies from Chrome
  const browserCookies = await extractBrowserCookies(baseUrl);
  if (browserCookies) {
    console.log(chalk.green("  ✓ Found session cookies in browser"));
    return browserCookies;
  }

  console.log(chalk.gray("  ℹ No automatic authentication found\n"));
  return null;
}

/**
 * Load credentials from .vibetest.json config file
 */
async function loadLocalConfig(): Promise<AuthCredentials | null> {
  const configPath = join(process.cwd(), ".vibetest.json");

  if (!existsSync(configPath)) {
    return null;
  }

  try {
    const config = JSON.parse(readFileSync(configPath, "utf-8"));

    if (config.token || config.cookies || config.headers) {
      return {
        token: config.token,
        cookies: config.cookies,
        headers: config.headers,
      };
    }
  } catch (e) {
    console.log(chalk.yellow("  ⚠ Failed to parse .vibetest.json"));
  }

  return null;
}

/**
 * Load token from environment variables
 */
function loadFromEnv(): AuthCredentials | null {
  const token =
    process.env.VIBETEST_TOKEN ||
    process.env.JWT_TOKEN ||
    process.env.AUTH_TOKEN;

  if (token) {
    return { token };
  }

  return null;
}

/**
 * Extract cookies from Chrome browser for the target URL
 */
async function extractBrowserCookies(
  baseUrl: string,
): Promise<AuthCredentials | null> {
  try {
    const url = new URL(baseUrl);
    const domain = url.hostname;

    // Chrome cookie database locations
    const chromePaths = [
      join(
        homedir(),
        "Library/Application Support/Google/Chrome/Default/Cookies",
      ), // macOS
      join(homedir(), ".config/google-chrome/Default/Cookies"), // Linux
      join(homedir(), "AppData/Local/Google/Chrome/User Data/Default/Cookies"), // Windows
    ];

    for (const cookiePath of chromePaths) {
      if (existsSync(cookiePath)) {
        // We can't easily read Chrome's encrypted SQLite cookies without native modules
        // Instead, let's check for a cookies.txt export or similar
        // For now, skip this and return null
        // TODO: Implement proper Chrome cookie extraction with better-sqlite3
        break;
      }
    }
  } catch (e) {
    // Silent fail
  }

  return null;
}

/**
 * Generate a sample .vibetest.json config file
 */
export function generateConfigExample(): string {
  return `{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "cookies": {
    "session": "your-session-cookie-here",
    "auth_token": "your-auth-token-here"
  },
  "headers": {
    "X-API-Key": "your-api-key-here"
  }
}`;
}

/**
 * Automatically capture authentication by opening browser and monitoring traffic
 */
export async function captureAuthFromBrowser(
  baseUrl: string,
): Promise<AuthCredentials | null> {
  console.log(
    chalk.cyan("\n🌐 Opening browser to capture authentication...\n"),
  );
  console.log(chalk.gray("  1. Browser will open to your app"));
  console.log(chalk.gray("  2. Login normally"));
  console.log(
    chalk.gray("  3. Auth credentials will be captured automatically\n"),
  );

  const browser = await puppeteer.launch({
    headless: false,
    defaultViewport: { width: 1280, height: 800 },
    args: ["--no-sandbox"],
  });

  try {
    const page = await browser.newPage();
    const capturedAuth: AuthCredentials = {};
    let authCaptured = false;

    // Common token patterns in headers, localStorage, cookies
    const TOKEN_PATTERNS = [
      /bearer\s+([a-zA-Z0-9_\-\.]+)/i,
      /jwt[:\s]+([a-zA-Z0-9_\-\.]+)/i,
      /token[:\s]+([a-zA-Z0-9_\-\.]+)/i,
      /^eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\./i, // JWT format
    ];

    // Intercept network requests to capture authorization headers
    await page.setRequestInterception(true);
    page.on("request", (request) => {
      const headers = request.headers();

      // Check Authorization header
      if (headers["authorization"]) {
        const authHeader = headers["authorization"];
        const match = authHeader.match(/bearer\s+(.+)/i);
        if (match && match[1]) {
          capturedAuth.token = match[1];
          authCaptured = true;
          console.log(
            chalk.green("  ✓ Captured Bearer token from request header"),
          );
        }
      }

      // Check for custom auth headers
      Object.keys(headers).forEach((key) => {
        if (
          key.toLowerCase().includes("token") ||
          key.toLowerCase().includes("auth")
        ) {
          if (!capturedAuth.headers) {
            capturedAuth.headers = {};
          }
          capturedAuth.headers[key] = headers[key];
        }
      });

      request.continue();
    });

    // Monitor responses for tokens in body
    page.on("response", async (response) => {
      try {
        if (response.status() === 200 && !authCaptured) {
          const contentType = response.headers()["content-type"];
          if (contentType?.includes("application/json")) {
            const body = await response.text();

            // Look for JWT tokens in response body
            for (const pattern of TOKEN_PATTERNS) {
              const match = body.match(pattern);
              if (match) {
                const token = match[1] || match[0];
                if (token.length > 20) {
                  capturedAuth.token = token;
                  authCaptured = true;
                  console.log(
                    chalk.green("  ✓ Captured token from API response"),
                  );
                  break;
                }
              }
            }
          }
        }
      } catch (e) {
        // Ignore errors in response processing
      }
    });

    // Determine login page
    const loginPaths = ["/login", "/signin", "/auth/login", "/api/auth/signin"];
    let loginUrl = baseUrl;

    // Try to find login page
    for (const path of loginPaths) {
      try {
        const testUrl = new URL(path, baseUrl).toString();
        const response = await page.goto(testUrl, {
          waitUntil: "networkidle0",
          timeout: 5000,
        });
        if (response && response.status() === 200) {
          loginUrl = testUrl;
          break;
        }
      } catch (e) {
        // Try next path
      }
    }

    // Navigate to login page (or home if not found)
    await page.goto(loginUrl, { waitUntil: "networkidle0" });

    console.log(
      chalk.yellow("  👤 Waiting for login... (will auto-detect when done)"),
    );

    // Wait for authentication to be captured or timeout
    const timeout = 120000; // 2 minutes
    const startTime = Date.now();

    while (!authCaptured && Date.now() - startTime < timeout) {
      // Check localStorage for tokens
      const localStorageTokens = await page.evaluate(() => {
        const tokens: Record<string, string> = {};
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          if (
            key &&
            (key.includes("token") ||
              key.includes("auth") ||
              key.includes("jwt"))
          ) {
            const value = localStorage.getItem(key);
            if (value) tokens[key] = value;
          }
        }
        return tokens;
      });

      if (Object.keys(localStorageTokens).length > 0) {
        // Extract token from localStorage
        for (const [key, value] of Object.entries(localStorageTokens)) {
          if (value.startsWith("eyJ")) {
            // JWT token
            capturedAuth.token = value;
            authCaptured = true;
            console.log(
              chalk.green(`  ✓ Captured token from localStorage (${key})`),
            );
            break;
          }
        }
      }

      // Check cookies
      const cookies = await page.cookies();
      const authCookies: Record<string, string> = {};

      for (const cookie of cookies) {
        const name = cookie.name.toLowerCase();

        // Ignore CSRF tokens and callback URLs
        if (
          name.includes("csrf") ||
          name.includes("callback") ||
          name.includes("state") ||
          name.includes("nonce")
        ) {
          continue;
        }

        // Look for actual session/auth tokens
        if (
          name.includes("session") ||
          (name.includes("auth") && !name.includes("csrf")) ||
          name.includes("token")
        ) {
          // Only add if the cookie has a substantial value (not just a short ID)
          if (cookie.value.length > 20) {
            authCookies[cookie.name] = cookie.value;

            // Check if cookie value is a JWT
            if (cookie.value.startsWith("eyJ") && !capturedAuth.token) {
              capturedAuth.token = cookie.value;
              authCaptured = true;
              console.log(
                chalk.green(`  ✓ Captured JWT from cookie (${cookie.name})`),
              );
            }
          }
        }
      }

      // Only consider authenticated if we have real session cookies (not just CSRF)
      if (Object.keys(authCookies).length > 0 && !capturedAuth.cookies) {
        capturedAuth.cookies = authCookies;
        authCaptured = true;
        console.log(
          chalk.green(
            `  ✓ Captured ${Object.keys(authCookies).length} auth cookie(s)`,
          ),
        );
      }

      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    await browser.close();

    if (authCaptured) {
      console.log(
        chalk.green("\n  ✅ Authentication captured successfully!\n"),
      );
      return capturedAuth;
    } else {
      console.log(
        chalk.yellow("\n  ⏱️  Timeout: No authentication captured\n"),
      );
      return null;
    }
  } catch (error: any) {
    console.log(chalk.red(`\n  ❌ Error: ${error.message}\n`));
    await browser.close();
    return null;
  }
}
