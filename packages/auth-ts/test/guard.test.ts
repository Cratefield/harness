// A source-level guard: the package promises a Workers/browser entry point,
// and the Node suite cannot catch a `node:` import or a `Buffer` that only
// fails once the bundle reaches workerd. Static scan, in the Node project.
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const srcDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

describe('source guard', () => {
  it('uses no Node-only APIs in src/', () => {
    const files = readdirSync(srcDir).filter((file) => file.endsWith('.ts'));
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const source = readFileSync(join(srcDir, file), 'utf8');
      expect(source, `${file} imports a node: module`).not.toMatch(/['"]node:/);
      expect(source, `${file} uses require()`).not.toMatch(/\brequire\s*\(/);
      expect(source, `${file} uses Buffer`).not.toMatch(/\bBuffer\s*[.(]|\bnew\s+Buffer\b/);
      expect(source, `${file} uses process`).not.toMatch(/(?:^|[^.\w])process\s*\./);
    }
  });
});
