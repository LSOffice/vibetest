import puppeteer from "puppeteer";
import chalk from "chalk";
import { VibeConfig, Route, Finding } from "../core/types.js";
import { logTestAttempt } from "../core/logger.js";

/**
 * Unsafe Rendering Patterns Check (XSS)
 *
 * Detects potentially unsafe rendering without being a full XSS scanner:
 * - dangerouslySetInnerHTML in React
 * - v-html in Vue
 * - Markdown renderers without sanitization
 * - innerHTML usage patterns
 */
export async function checkUnsafeRendering(
  config: VibeConfig,
  routes: Route[],
): Promise<Finding[]> {
  const findings: Finding[] = [];

  console.log(chalk.blue("\n⚠️  Testing Unsafe Rendering Patterns..."));

  try {
    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();

    await page
      .goto(config.baseUrl, {
        waitUntil: "networkidle0",
        timeout: 10000,
      })
      .catch(() => {});

    // Scan JavaScript for unsafe patterns
    const scripts = await page.evaluate(() => {
      return Array.from(document.querySelectorAll("script"))
        .map((s) => s.textContent || "")
        .join("\n");
    });

    // Detect unsafe rendering patterns
    const unsafePatterns = [
      {
        pattern: /dangerouslySetInnerHTML/g,
        name: "React dangerouslySetInnerHTML",
        severity: "high" as const,
      },
      {
        pattern: /v-html=/g,
        name: "Vue v-html directive",
        severity: "high" as const,
      },
      {
        pattern: /\.innerHTML\s*=/g,
        name: "Direct innerHTML assignment",
        severity: "high" as const,
      },
      {
        pattern: /document\.write\(/g,
        name: "document.write() usage",
        severity: "medium" as const,
      },
      {
        pattern: /eval\(/g,
        name: "eval() usage",
        severity: "critical" as const,
      },
      {
        pattern: /new Function\(/g,
        name: "new Function() constructor",
        severity: "high" as const,
      },
    ];

    for (const { pattern, name, severity } of unsafePatterns) {
      const matches = scripts.match(pattern);
      if (matches && matches.length > 0) {
        findings.push({
          id: `unsafe-render-${name}`,
          checkId: "unsafe-rendering",
          category: "frontend",
          name: `${name} Detected`,
          description: `Found ${matches.length} instance(s) of ${name} in client code. This can lead to XSS if user input is rendered.`,
          endpoint: config.baseUrl,
          risk: severity as "low" | "medium" | "high" | "critical",
          assumption: "User input is properly escaped before rendering",
          reproduction: `Search client JavaScript for: ${pattern.source}`,
          fix: "Avoid unsafe rendering methods. Use proper sanitization with DOMPurify if HTML rendering is required. Prefer text rendering or safe templating.",
        });

        logTestAttempt({
          check: "unsafe-rendering",
          endpoint: config.baseUrl,
          status: "SUSPICIOUS",
          details: `Found ${matches.length}x ${name}`,
        });
      }
    }

    // Check for markdown renderers
    const markdownPatterns = [
      /marked\(/g,
      /markdown-it/g,
      /showdown/g,
      /ReactMarkdown/g,
    ];

    let hasMarkdownRenderer = false;
    let hasSanitizer = false;

    for (const pattern of markdownPatterns) {
      if (pattern.test(scripts)) {
        hasMarkdownRenderer = true;
        break;
      }
    }

    // Check for sanitization libraries
    const sanitizerPatterns = [/DOMPurify/g, /sanitize-html/g, /xss\(/g];

    for (const pattern of sanitizerPatterns) {
      if (pattern.test(scripts)) {
        hasSanitizer = true;
        break;
      }
    }

    if (hasMarkdownRenderer && !hasSanitizer) {
      findings.push({
        id: `unsafe-render-markdown`,
        checkId: "unsafe-rendering",
        category: "frontend",
        name: "Markdown Renderer Without Sanitization",
        description:
          "Application uses markdown rendering but no sanitization library was detected. User-generated markdown could contain XSS.",
        endpoint: config.baseUrl,
        risk: "high",
        assumption: "Markdown is always sanitized before rendering",
        reproduction:
          "Find markdown renderer in client code and test with XSS payload",
        fix: "Always sanitize markdown output with DOMPurify or similar. Configure markdown renderer with safe options (disable raw HTML).",
      });

      logTestAttempt({
        check: "unsafe-rendering",
        endpoint: config.baseUrl,
        status: "VULNERABLE",
        details: "Markdown without sanitization",
      });
    }

    // Check for URL/query param rendering
    const urlRenderingCheck = await page.evaluate(() => {
      const results: string[] = [];
      const elements = document.querySelectorAll("[data-*], [id], [class]");

      elements.forEach((el) => {
        const html = el.innerHTML;
        // Check if innerHTML contains URL patterns (might be reflected)
        if (
          html.includes("http://") ||
          html.includes("https://") ||
          html.includes("://")
        ) {
          results.push(
            `${el.tagName}.${el.className || el.id}: ${html.substring(0, 50)}`,
          );
        }
      });

      return results;
    });

    if (urlRenderingCheck.length > 0) {
      findings.push({
        id: `unsafe-render-url`,
        checkId: "unsafe-rendering",
        category: "frontend",
        name: "Potential URL/Query Param Rendering",
        description: `Found ${urlRenderingCheck.length} elements that may be rendering URL data. Check if query params or URL fragments are reflected unsafely.`,
        endpoint: config.baseUrl,
        risk: "medium",
        assumption:
          "URL parameters and fragments are sanitized before rendering",
        reproduction:
          "Search for elements containing http:// or https:// patterns",
        fix: "Sanitize all URL parameters, query strings, and hash fragments before rendering. Use textContent instead of innerHTML.",
      });
    }

    await browser.close();
  } catch (error) {
    console.log(chalk.yellow("  ⚠ Could not complete unsafe rendering check"));
  }

  return findings;
}
