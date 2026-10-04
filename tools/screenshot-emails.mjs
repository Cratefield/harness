#!/usr/bin/env node
// Screenshots every rendered email in headless Chrome: 600px and 360px wide,
// light and dark (`prefers-color-scheme`), full height, at 2x.
//
//     node tools/screenshot-emails.mjs <dir of .html> <out dir> [--logo logo-64.png]
//
// `--logo` serves that file for every `*/assets/email/*` URL, so previews
// show a venture's logo before its website hosts it. Chrome: $CHROME, else
// the usual install paths. No dependencies: it speaks the DevTools protocol
// over Node's WebSocket. (Adapted from Owlpost's tools/screenshot-emails.mjs.)

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const args = process.argv.slice(2);
const logoAt = args.indexOf('--logo');
const logo = logoAt >= 0 ? fs.readFileSync(args.splice(logoAt, 2)[1]) : null;
const [inDir, outDir] = args;
if (!inDir || !outDir) {
  console.error('usage: screenshot-emails.mjs <dir of .html> <out dir> [--logo file.png]');
  process.exit(2);
}
fs.mkdirSync(outDir, { recursive: true });

const chrome = [
  process.env.CHROME,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
].find((p) => p && fs.existsSync(p));
if (!chrome) {
  console.error('no Chrome found; set CHROME');
  process.exit(2);
}

const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'cratefield-shots-'));
const proc = spawn(chrome, [
  '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
  '--no-first-run', '--no-default-browser-check', '--hide-scrollbars', 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] });

const wsUrl = await new Promise((resolve, reject) => {
  let buf = '';
  proc.stderr.on('data', (d) => {
    buf += d;
    const m = buf.match(/DevTools listening on (ws:\/\/\S+)/);
    if (m) resolve(m[1]);
  });
  proc.on('exit', () => reject(new Error(`Chrome exited:\n${buf}`)));
});

const ws = new WebSocket(wsUrl);
await new Promise((r) => ws.addEventListener('open', r, { once: true }));
let nextId = 0;
const pending = new Map();
const listeners = [];
ws.addEventListener('message', (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
  } else if (msg.method) {
    for (const l of listeners) l(msg);
  }
});
const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
  const id = ++nextId;
  pending.set(id, { resolve, reject });
  ws.send(JSON.stringify({ id, method, params, sessionId }));
});

const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
const s = (m, p) => send(m, p, sessionId);
await s('Page.enable');
if (logo) {
  await s('Fetch.enable', { patterns: [{ urlPattern: '*/assets/email/*' }] });
  listeners.push((msg) => {
    if (msg.method === 'Fetch.requestPaused' && msg.sessionId === sessionId) {
      s('Fetch.fulfillRequest', {
        requestId: msg.params.requestId, responseCode: 200,
        responseHeaders: [{ name: 'Content-Type', value: 'image/png' }],
        body: logo.toString('base64'),
      });
    }
  });
}
const loaded = () => new Promise((resolve) => {
  const l = (msg) => {
    if (msg.method === 'Page.loadEventFired' && msg.sessionId === sessionId) {
      listeners.splice(listeners.indexOf(l), 1);
      resolve();
    }
  };
  listeners.push(l);
});

const files = fs.readdirSync(inDir).filter((f) => f.endsWith('.html') && f !== 'index.html').sort();
for (const file of files) {
  const url = `file://${path.resolve(inDir, file)}`;
  for (const width of [600, 360]) {
    for (const scheme of ['light', 'dark']) {
      await s('Emulation.setDeviceMetricsOverride', { width, height: 800, deviceScaleFactor: 2, mobile: width < 500 });
      await s('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: scheme }] });
      const done = loaded();
      await s('Page.navigate', { url });
      await done;
      const { result } = await s('Runtime.evaluate', {
        expression: 'Math.ceil(Math.max(document.documentElement.scrollHeight, document.body.scrollHeight))',
        returnByValue: true,
      });
      const { result: overflow } = await s('Runtime.evaluate', {
        expression: 'document.documentElement.scrollWidth > window.innerWidth',
        returnByValue: true,
      });
      const { data } = await s('Page.captureScreenshot', {
        format: 'png', captureBeyondViewport: true,
        clip: { x: 0, y: 0, width, height: result.value, scale: 1 },
      });
      const out = path.join(outDir, `${file.replace(/\.html$/, '')}-${width}-${scheme}.png`);
      fs.writeFileSync(out, Buffer.from(data, 'base64'));
      console.log(`${out}${overflow.value ? '  (horizontal overflow!)' : ''}`);
    }
  }
}

ws.close();
await new Promise((r) => { proc.once('exit', r); proc.kill(); });
fs.rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
