import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(webRoot, "../data/snapshot.json");
const targetDir = resolve(webRoot, "public/data");
mkdirSync(targetDir, { recursive: true });
copyFileSync(source, resolve(targetDir, "snapshot.json"));
