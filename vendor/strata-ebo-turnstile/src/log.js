import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { appendFile } from "node:fs/promises";
import { dirname } from "node:path";
import { canonicalize } from "./canonicalize.js";

export class JsonlReceiptLog {
  constructor(filePath) {
    this.filePath = filePath;
    mkdirSync(dirname(filePath), { recursive: true });
  }

  async append(receipt) {
    await appendFile(this.filePath, `${canonicalize(receipt)}\n`, { encoding: "utf8" });
    return receipt;
  }

  writeAll(receipts) {
    mkdirSync(dirname(this.filePath), { recursive: true });
    writeFileSync(this.filePath, receipts.map((receipt) => canonicalize(receipt)).join("\n") + "\n", "utf8");
  }

  readAll() {
    let raw;
    try {
      raw = readFileSync(this.filePath, "utf8");
    } catch (error) {
      if (error.code === "ENOENT") {
        return [];
      }
      throw error;
    }

    return raw
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .map((line, index) => {
        try {
          return JSON.parse(line);
        } catch (error) {
          throw new Error(`Invalid JSONL receipt at line ${index + 1}: ${error.message}`);
        }
      });
  }

  reset() {
    rmSync(this.filePath, { force: true });
  }
}
