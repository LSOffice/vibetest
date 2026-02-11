import puppeteer from "puppeteer";
import { Check, Finding, CheckContext } from "../core/types.js";
import { logTestAttempt } from "../core/logger.js";

/**
 * Active XSS Injection Testing
 *
 * Unlike pattern-based detection, this actively injects payloads and detects execution.
 * Tests for:
 * - Reflected XSS (GET and POST)
 * - Stored XSS (inject + revisit pattern)
 * - DOM-based XSS
 * - Multiple contexts: HTML, attribute, script, URL, CSS
 */

// Safe detection token for XSS confirmation
function generateDetectionToken(): string {
  return `vibetest_xss_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// XSS payload library with context-aware payloads
interface XSSPayload {
  name: string;
  context: string;
  generatePayload: (token: string) => string;
  description: string;
}

const XSS_PAYLOADS: XSSPayload[] = [
  // HTML Context
  {
    name: "Script Tag",
    context: "html",
    generatePayload: (token) => `<script>window.${token}=1</script>`,
    description: "Basic script tag injection",
  },
  {
    name: "IMG onerror",
    context: "html",
    generatePayload: (token) =>
      `<img src=x onerror="window.${token}=1" alt="test">`,
    description: "Image tag with onerror handler",
  },
  {
    name: "SVG onload",
    context: "html",
    generatePayload: (token) => `<svg onload="window.${token}=1"></svg>`,
    description: "SVG with onload handler",
  },
  {
    name: "Body onload",
    context: "html",
    generatePayload: (token) => `<body onload="window.${token}=1">`,
    description: "Body tag with onload",
  },
  {
    name: "IFrame srcdoc",
    context: "html",
    generatePayload: (token) =>
      `<iframe srcdoc="<script>parent.${token}=1</script>">`,
    description: "IFrame with srcdoc XSS",
  },

  // Attribute Context
  {
    name: "Attribute Break Double Quote",
    context: "attribute",
    generatePayload: (token) => `" onmouseover="window.${token}=1`,
    description: "Break out of double-quoted attribute",
  },
  {
    name: "Attribute Break Single Quote",
    context: "attribute",
    generatePayload: (token) => `' onmouseover="window.${token}=1`,
    description: "Break out of single-quoted attribute",
  },
  {
    name: "Attribute Without Quotes",
    context: "attribute",
    generatePayload: (token) => `onmouseover=window.${token}=1`,
    description: "Attribute injection without quotes",
  },

  // JavaScript Context
  {
    name: "Script Context Break",
    context: "javascript",
    generatePayload: (token) => `</script><script>window.${token}=1</script>`,
    description: "Break out of script context",
  },
  {
    name: "Template Literal",
    context: "javascript",
    generatePayload: (token) => `\${window.${token}=1}`,
    description: "Template literal injection",
  },
  {
    name: "String Break Single",
    context: "javascript",
    generatePayload: (token) => `';window.${token}=1;'`,
    description: "Break out of single-quoted string",
  },
  {
    name: "String Break Double",
    context: "javascript",
    generatePayload: (token) => `";window.${token}=1;"`,
    description: "Break out of double-quoted string",
  },

  // URL Context
  {
    name: "JavaScript Protocol",
    context: "url",
    generatePayload: (token) => `javascript:window.${token}=1`,
    description: "JavaScript protocol in URL",
  },
  {
    name: "Data URL",
    context: "url",
    generatePayload: (token) =>
      `data:text/html,<script>window.${token}=1</script>`,
    description: "Data URL with script",
  },

  // CSS Context
  {
    name: "CSS Expression (IE)",
    context: "css",
    generatePayload: (token) => `expression(window.${token}=1)`,
    description: "CSS expression (legacy IE)",
  },
  {
    name: "CSS Import",
    context: "css",
    generatePayload: (token) =>
      `@import 'data:text/css,*{background:url(javascript:window.${token}=1)}'`,
    description: "CSS import with JS",
  },

  // Advanced/Mutation XSS
  {
    name: "Mutation XSS",
    context: "html",
    generatePayload: (token) =>
      `<noscript><p title="</noscript><img src=x onerror=window.${token}=1>">`,
    description: "Mutation XSS via noscript",
  },
  {
    name: "SVG Use",
    context: "html",
    generatePayload: (token) =>
      `<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>window.${token}=1</script></svg>#x" />`,
    description: "SVG use element XSS",
  },

  // Encoding Bypasses
  {
    name: "HTML Entity",
    context: "html",
    generatePayload: (token) =>
      `<img src=x onerror="window.&#118;&#105;&#98;&#101;&#116;&#101;&#115;&#116;=1">`,
    description: "HTML entity encoded",
  },
  {
    name: "Unicode Escape",
    context: "javascript",
    generatePayload: (token) => `\\u003cscript\\u003ewindow.${token}=1\\u003c/script\\u003e`,
    description: "Unicode escaped XSS",
  },
];

/**
 * Test for reflected XSS in GET parameters
 */
async function testReflectedXSS(
  context: CheckContext,
  browser: any,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const { axios, apiAxios, discoveredRoutes, config } = context;

  // Target GET routes that might reflect input
  const getRoutes = discoveredRoutes.filter(
    (r) =>
      r.method === "GET" &&
      (r.path.includes("search") ||
        r.path.includes("query") ||
        r.path.includes("q") ||
        r.path.includes("filter") ||
        r.inputs),
  );

  for (const route of getRoutes.slice(0, 10)) {
    // Limit to 10 routes for performance
    const testParams = route.inputs
      ? Object.keys(route.inputs).slice(0, 3)
      : ["search", "q", "query"];

    for (const param of testParams) {
      // Test a selection of payloads (not all, to save time)
      const selectedPayloads = [
        XSS_PAYLOADS[0], // Script tag
        XSS_PAYLOADS[1], // IMG onerror
        XSS_PAYLOADS[5], // Attribute break
        XSS_PAYLOADS[13], // JavaScript protocol
      ];

      for (const payloadDef of selectedPayloads) {
        const token = generateDetectionToken();
        const payload = payloadDef.generatePayload(token);

        try {
          logTestAttempt({
            check: "xss-injection",
            endpoint: `GET ${route.path}?${param}=${payload.substring(0, 30)}`,
            status: "TESTING",
            details: `Reflected XSS (${payloadDef.name})`,
          });

          const page = await browser.newPage();
          await page.setDefaultTimeout(5000);

          // Navigate with payload
          const url = `${config.baseUrl}${route.path}?${param}=${encodeURIComponent(payload)}`;
          await page.goto(url, { waitUntil: "domcontentloaded" }).catch(() => {});

          // Check if our detection token exists in window
          const executed = await page
            .evaluate((t: string) => {
              return (window as any)[t] === 1;
            }, token)
            .catch(() => false);

          if (executed) {
            findings.push({
              id: `xss-reflected-${route.path}-${param}-${payloadDef.context}`,
              checkId: "xss-injection",
              category: "backend",
              name: `Reflected XSS - ${payloadDef.name}`,
              endpoint: `GET ${route.path}?${param}=...`,
              risk: "critical",
              description: `Parameter '${param}' is vulnerable to reflected XSS. Payload executed: ${payloadDef.description}. Context: ${payloadDef.context}. An attacker can craft malicious links to execute arbitrary JavaScript in victims' browsers.`,
              assumption: "User input is sanitized before being reflected in HTML.",
              reproduction: `Visit: ${url}`,
              fix: "Sanitize all user input before rendering. Use DOMPurify for HTML content. Prefer textContent over innerHTML. Set Content-Security-Policy header to block inline scripts.",
            });

            logTestAttempt({
              check: "xss-injection",
              endpoint: `GET ${route.path}`,
              status: "VULNERABLE",
              details: `XSS confirmed: ${payloadDef.name}`,
            });

            await page.close();
            break; // One payload execution per param is enough
          }

          await page.close();
        } catch (error: any) {
          // Errors during XSS testing are expected
        }
      }
    }
  }

  return findings;
}

/**
 * Test for stored XSS (inject + revisit pattern)
 */
async function testStoredXSS(
  context: CheckContext,
  browser: any,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const { axios, apiAxios, discoveredRoutes, config } = context;

  // Find POST routes that might store data
  const postRoutes = discoveredRoutes.filter(
    (r) =>
      r.method === "POST" &&
      (r.path.includes("comment") ||
        r.path.includes("post") ||
        r.path.includes("message") ||
        r.path.includes("review") ||
        r.path.includes("feedback") ||
        r.path.includes("note")),
  );

  for (const route of postRoutes.slice(0, 5)) {
    // Limit to 5 routes
    const testFields = route.inputs
      ? Object.keys(route.inputs).filter(
          (k) =>
            k.includes("content") ||
            k.includes("text") ||
            k.includes("body") ||
            k.includes("message") ||
            k.includes("comment"),
        )
      : ["content", "text", "body", "message"];

    for (const field of testFields.slice(0, 2)) {
      const token = generateDetectionToken();
      const payload = XSS_PAYLOADS[1].generatePayload(token); // IMG onerror

      try {
        logTestAttempt({
          check: "xss-injection",
          endpoint: `POST ${route.path}`,
          status: "TESTING",
          details: `Stored XSS (${field})`,
        });

        const client = route.path.startsWith("/api") ? apiAxios : axios;

        // Step 1: Inject the payload
        await client
          .post(route.path, {
            [field]: payload,
          })
          .catch(() => {});

        // Step 2: Revisit a likely viewing route
        const viewRoutes = [
          route.path.replace("/create", ""),
          route.path.replace("/add", ""),
          route.path.replace("s", ""), // e.g., /comments -> /comment
          "/",
        ];

        for (const viewRoute of viewRoutes) {
          try {
            const page = await browser.newPage();
            await page.setDefaultTimeout(5000);

            await page
              .goto(`${config.baseUrl}${viewRoute}`, {
                waitUntil: "domcontentloaded",
              })
              .catch(() => {});

            // Check if our detection token exists
            const executed = await page
              .evaluate((t: string) => {
                return (window as any)[t] === 1;
              }, token)
              .catch(() => false);

            if (executed) {
              findings.push({
                id: `xss-stored-${route.path}-${field}`,
                checkId: "xss-injection",
                category: "backend",
                name: "Stored XSS (Persistent)",
                endpoint: `POST ${route.path} → GET ${viewRoute}`,
                risk: "critical",
                description: `Field '${field}' in POST ${route.path} stores unsanitized content that executes when viewed at ${viewRoute}. This is STORED XSS - affects all users viewing the content. Highly dangerous.`,
                assumption:
                  "User-generated content is sanitized before storage and rendering.",
                reproduction: `1. POST to ${route.path} with XSS payload in ${field}\n2. Visit ${viewRoute}\n3. Payload executes for all viewers`,
                fix: "Sanitize input before storage AND before rendering. Use DOMPurify. Store content as plain text when possible. Implement Content-Security-Policy.",
              });

              logTestAttempt({
                check: "xss-injection",
                endpoint: `POST ${route.path}`,
                status: "VULNERABLE",
                details: `Stored XSS confirmed: ${field}`,
              });

              await page.close();
              return findings; // Found stored XSS, stop testing
            }

            await page.close();
          } catch (error: any) {
            // Continue to next view route
          }
        }
      } catch (error: any) {
        // Error during injection is fine
      }
    }
  }

  return findings;
}

/**
 * Test for DOM-based XSS (client-side sources to sinks)
 */
async function testDomXSS(config: any, browser: any): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const page = await browser.newPage();
    await page.setDefaultTimeout(8000);

    // Navigate to base URL
    await page
      .goto(config.baseUrl, { waitUntil: "domcontentloaded" })
      .catch(() => {});

    // Analyze client-side code for DOM XSS patterns
    const domAnalysis = await page.evaluate(() => {
      const scripts = Array.from(document.querySelectorAll("script"))
        .map((s) => s.textContent || "")
        .join("\n");

      const analysis: {
        dangerousSources: string[];
        dangerousSinks: string[];
        suspiciousPatterns: string[];
      } = {
        dangerousSources: [],
        dangerousSinks: [],
        suspiciousPatterns: [],
      };

      // Check for dangerous sources (user-controllable)
      const sources = [
        /location\.hash/g,
        /location\.search/g,
        /document\.URL/g,
        /document\.documentURI/g,
        /document\.referrer/g,
        /window\.name/g,
      ];

      sources.forEach((pattern) => {
        if (pattern.test(scripts)) {
          analysis.dangerousSources.push(pattern.source);
        }
      });

      // Check for dangerous sinks (execution points)
      const sinks = [
        /\.innerHTML\s*=/g,
        /\.outerHTML\s*=/g,
        /document\.write\(/g,
        /eval\(/g,
        /setTimeout\(/g,
        /setInterval\(/g,
        /\.html\(/g, // jQuery
        /\$\(.*\)\.append\(/g, // jQuery
      ];

      sinks.forEach((pattern) => {
        if (pattern.test(scripts)) {
          analysis.dangerousSinks.push(pattern.source);
        }
      });

      // Check for direct source-to-sink patterns
      const suspiciousPatterns = [
        /innerHTML\s*=\s*location\.hash/g,
        /innerHTML\s*=\s*location\.search/g,
        /document\.write\(.*location\./g,
        /eval\(.*location\./g,
      ];

      suspiciousPatterns.forEach((pattern) => {
        if (pattern.test(scripts)) {
          analysis.suspiciousPatterns.push(pattern.source);
        }
      });

      return analysis;
    });

    // Report DOM XSS risks
    if (
      domAnalysis.dangerousSources.length > 0 &&
      domAnalysis.dangerousSinks.length > 0
    ) {
      findings.push({
        id: "xss-dom-sources-sinks",
        checkId: "xss-injection",
        category: "frontend",
        name: "DOM XSS Risk - Sources and Sinks Present",
        endpoint: config.baseUrl,
        risk: "high",
        description: `Found ${domAnalysis.dangerousSources.length} dangerous sources (location.hash, location.search, etc.) and ${domAnalysis.dangerousSinks.length} dangerous sinks (innerHTML, eval, document.write). This indicates potential DOM-based XSS.`,
        assumption:
          "Client-side code sanitizes URL parameters before using them.",
        reproduction: `Sources: ${domAnalysis.dangerousSources.slice(0, 3).join(", ")}\nSinks: ${domAnalysis.dangerousSinks.slice(0, 3).join(", ")}`,
        fix: "Sanitize all data from URL/hash before using in sinks. Use textContent instead of innerHTML. Avoid eval() and document.write(). Use DOMPurify for any HTML rendering.",
      });
    }

    if (domAnalysis.suspiciousPatterns.length > 0) {
      findings.push({
        id: "xss-dom-direct-flow",
        checkId: "xss-injection",
        category: "frontend",
        name: "DOM XSS - Direct Source-to-Sink Flow",
        endpoint: config.baseUrl,
        risk: "critical",
        description: `Found direct data flow from dangerous sources to sinks: ${domAnalysis.suspiciousPatterns.join(", ")}. This is a confirmed DOM XSS vulnerability.`,
        assumption: "URL parameters are not used directly in dangerous sinks.",
        reproduction: `Detected patterns: ${domAnalysis.suspiciousPatterns.join("; ")}`,
        fix: "URGENT: Remove direct source-to-sink flows. Always sanitize data from location.hash, location.search, etc. before using in innerHTML, eval, or document.write.",
      });
    }

    // Active DOM XSS test with hash fragment
    const token = generateDetectionToken();
    const hashPayload = `<img src=x onerror="window.${token}=1">`;

    await page.goto(`${config.baseUrl}#${encodeURIComponent(hashPayload)}`, {
      waitUntil: "domcontentloaded",
    });

    const hashExecuted = await page
      .evaluate((t: string) => {
        return (window as any)[t] === 1;
      }, token)
      .catch(() => false);

    if (hashExecuted) {
      findings.push({
        id: "xss-dom-hash-confirmed",
        checkId: "xss-injection",
        category: "frontend",
        name: "DOM XSS - Hash Fragment Execution Confirmed",
        endpoint: `${config.baseUrl}#...`,
        risk: "critical",
        description: `XSS payload in URL hash fragment executed successfully. Application reads location.hash and renders it unsafely.`,
        assumption: "Hash fragments are safe and not executed.",
        reproduction: `Visit: ${config.baseUrl}#${hashPayload}`,
        fix: "Sanitize location.hash before rendering. Use DOMPurify or similar. Prefer textContent over innerHTML.",
      });
    }

    await page.close();
  } catch (error: any) {
    // DOM XSS testing errors are fine
  }

  return findings;
}

/**
 * Main XSS Injection Check
 */
export const xssInjectionCheck: Check = {
  id: "xss-injection",
  name: "XSS Injection Testing (Active)",
  description:
    "Active XSS payload injection with script execution detection for reflected, stored, and DOM-based XSS",
  async run(context: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const browser = await puppeteer.launch({
        headless: true,
        args: ["--no-sandbox", "--disable-setuid-sandbox"],
      });

      // Test 1: Reflected XSS in query params
      const reflectedFindings = await testReflectedXSS(context, browser);
      findings.push(...reflectedFindings);

      // Test 2: Stored XSS (inject + revisit)
      const storedFindings = await testStoredXSS(context, browser);
      findings.push(...storedFindings);

      // Test 3: DOM-based XSS
      const domFindings = await testDomXSS(context.config, browser);
      findings.push(...domFindings);

      await browser.close();
    } catch (error: any) {
      console.log(`  ⚠ XSS injection testing incomplete: ${error.message}`);
    }

    return findings;
  },
};
