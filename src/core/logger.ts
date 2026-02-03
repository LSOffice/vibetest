import fs from "fs/promises";
import path from "path";

export async function logTestAttempt(details: any) {
  try {
    const dir = path.join(process.cwd(), "log");
    await fs.mkdir(dir, { recursive: true });

    const safeTimestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const filename = `${safeTimestamp}.txt`;
    const filepath = path.join(dir, filename);

    const header = `Timestamp: ${new Date().toISOString()}\n`;
    let body: string;
    if (typeof details === "string") {
      body = details;
    } else {
      try {
        body = JSON.stringify(details, null, 2);
      } catch (e) {
        body = String(details);
      }
    }

    const content = `${header}\n${body}\n`;
    await fs.writeFile(filepath, content, "utf8");
    return filepath;
  } catch (err) {
    // Fail silently; logging should not break execution
    return undefined;
  }
}
