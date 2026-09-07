// cf.js must stay small: at most 4 KB minified and gzipped (issue #73).
import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { minify } from "terser";

const LIMIT = 4096;
const source = readFileSync(new URL("../../crates/ui/assets/cf.js", import.meta.url), "utf8");
const { code } = await minify(source, { module: true, compress: true, mangle: true });
const gz = gzipSync(code, { level: 9 }).length;
console.log(`cf.js: ${source.length} B source, ${code.length} B minified, ${gz} B gzipped (limit ${LIMIT})`);
if (gz > LIMIT) {
  console.error(`cf.js exceeds the ${LIMIT} B gzipped limit by ${gz - LIMIT} B`);
  process.exit(1);
}
