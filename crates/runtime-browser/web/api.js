// The request bridge: turns a call into the wasm venture's `handle` and back
// into a Response-shaped object. The Service Worker (service-worker.js) and the
// demo page both use this identical contract — the SW is the production
// ingress; the page can also call it directly.
//
// `handle` returns the envelope `{ status, headers: [[k,v]], body: <base64> }`.

const b64ToBytes = (b64) => {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) { bytes[i] = bin.charCodeAt(i); }
  return bytes;
};

export async function callHandle(wasm, method, url, headers, bodyBytes) {
  const envelopeJson = await wasm.handle(
    method,
    url,
    JSON.stringify(headers ?? []),
    bodyBytes ?? new Uint8Array(),
  );
  const env = JSON.parse(envelopeJson);
  return {
    status: env.status,
    headers: new Headers(env.headers),
    bytes: b64ToBytes(env.body),
    text() { return new TextDecoder().decode(this.bytes); },
  };
}
