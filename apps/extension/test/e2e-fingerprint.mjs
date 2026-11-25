/**
 * End-to-end check of fingerprint noise in Chromium with the real extension:
 * values change once noise is on, stay the same for a site within the session,
 * differ between sites, look native, and return to the real ones on a site the
 * person turned it off for.
 *
 *   SENTINEL_TEST_BUILD=1 SENTINEL_SERVER=http://localhost:8787 npm run build
 *   node test/e2e-fingerprint.mjs
 */
import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { startMockServer } from "./mock-server.mjs";

const { chromium } = createRequire(import.meta.url)("playwright");
const extensionPath = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "chrome");
const step = (text) => console.log(`✓ ${text}`);

const { server } = await startMockServer(8787);
const context = await chromium.launchPersistentContext(await mkdtemp(join(tmpdir(), "qalaa-fp-")), {
  channel: "chromium",
  headless: true,
  args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`],
});

// A page that reads the usual fingerprint sources as soon as it runs.
const PAGE = `<!doctype html><title>fp</title><script>
function draw(doc) {
  const c = doc.createElement("canvas"); c.width = 220; c.height = 40;
  const x = c.getContext("2d");
  x.textBaseline = "top"; x.font = "16px Arial"; x.fillStyle = "#f60"; x.fillRect(10, 1, 62, 20);
  x.fillStyle = "#069"; x.fillText("Qalaa fingerprint test", 2, 15);
  x.fillStyle = "rgba(102,204,0,0.7)"; x.fillText("Qalaa fingerprint test", 4, 17);
  return c;
}
// Worker: an OffscreenCanvas drawing and the worker's processor count.
const WORKER = \`onmessage = async () => {
  const c = new OffscreenCanvas(220, 40); const x = c.getContext("2d");
  x.fillStyle = "#f60"; x.fillRect(10, 1, 62, 20); x.fillStyle = "#069"; x.font = "16px Arial"; x.fillText("Qalaa fingerprint test", 2, 15);
  const bytes = new Uint8Array(await (await c.convertToBlob()).arrayBuffer());
  const pixels = Array.from(x.getImageData(0, 0, 220, 40).data).join(",");
  postMessage({ blob: Array.from(bytes).join(","), pixels, cores: navigator.hardwareConcurrency });
};\`;
async function fromWorker() {
  const w = new Worker(URL.createObjectURL(new Blob([WORKER], { type: "text/javascript" })));
  const answer = await new Promise((resolve) => { w.onmessage = (e) => resolve(e.data); w.postMessage(0); });
  w.terminate();
  return answer;
}
async function localAddresses() {
  if (typeof RTCPeerConnection !== "function") return [];
  const pc = new RTCPeerConnection({ iceServers: [] });
  pc.createDataChannel("x");
  const found = [];
  pc.onicecandidate = (e) => { if (e.candidate) found.push(e.candidate.candidate); };
  await pc.setLocalDescription(await pc.createOffer());
  await new Promise((r) => setTimeout(r, 1500));
  pc.close();
  return found.filter((c) => /\\b(10\\.|192\\.168\\.|172\\.(1[6-9]|2\\d|3[01])\\.)/.test(c));
}
async function fingerprint() {
  const c = draw(document);
  const x = c.getContext("2d");
  const digest = async (s) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
  const pixels = (d) => Array.from(d.data).join(",");
  const img1 = pixels(x.getImageData(0, 0, c.width, c.height));
  const img2 = pixels(x.getImageData(0, 0, c.width, c.height));
  let renderer = null;
  const gl = document.createElement("canvas").getContext("webgl");
  if (gl) renderer = gl.getParameter(0x9246);
  const ctx = new OfflineAudioContext(1, 5000, 44100);
  const osc = ctx.createOscillator(); osc.type = "triangle"; osc.frequency.value = 1000;
  const comp = ctx.createDynamicsCompressor(); osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
  const buffer = await ctx.startRendering();
  const samples = buffer.getChannelData(0); const again = buffer.getChannelData(0);
  let sum = 0; for (let i = 0; i < samples.length; i++) sum += Math.abs(samples[i]);
  // copyFromChannel on a fresh buffer, before getChannelData has been called on it.
  const ctx2 = new OfflineAudioContext(1, 5000, 44100);
  const osc2 = ctx2.createOscillator(); osc2.type = "triangle"; osc2.frequency.value = 1000; osc2.connect(ctx2.destination); osc2.start(0);
  const copy = new Float32Array(5000); (await ctx2.startRendering()).copyFromChannel(copy, 0);
  let copySum = 0; for (const v of copy) copySum += Math.abs(v);
  // A frame the script makes itself, reached two ways: contentWindow, and window[i] right after insertion.
  const frame = document.createElement("iframe"); document.body.appendChild(frame);
  const viaContent = await digest(draw(frame.contentWindow.document).toDataURL());
  const frame2 = document.createElement("iframe"); document.body.appendChild(frame2);
  const viaIndex = await digest(window[window.length - 1].HTMLCanvasElement.prototype.toDataURL.call(draw(frame2.contentDocument)));
  const worker = await fromWorker();
  return {
    canvas: await digest(c.toDataURL()),
    canvasAgain: await digest(c.toDataURL()),
    imageStable: img1 === img2,
    image: await digest(img1),
    renderer,
    audio: sum.toFixed(10),
    audioCopy: copySum.toFixed(10),
    frameContent: viaContent,
    frameIndex: viaIndex,
    workerBlob: await digest(worker.blob),
    workerPixels: await digest(worker.pixels),
    workerCores: worker.cores,
    leaks: await localAddresses(),
    audioSame: samples === again,
    cores: navigator.hardwareConcurrency,
    memory: navigator.deviceMemory,
    native: Function.prototype.toString.call(HTMLCanvasElement.prototype.toDataURL),
    early: window.__early,
  };
}
// Read before anything else on the page has run.
window.__early = navigator.hardwareConcurrency;
</script><body>fp</body>`;
await context.route(/^https:\/\/(site-a|site-b)\.example\//, (route) => route.fulfill({ contentType: "text/html", body: PAGE }));

let [worker] = context.serviceWorkers();
worker ??= await context.waitForEvent("serviceworker");
const extensionId = new URL(worker.url()).host;

const page = await context.newPage();
const read = async (url) => {
  await page.goto(url);
  return page.evaluate(() => fingerprint());
};
const settings = async (changes) => {
  const options = await context.newPage();
  await options.goto(`chrome-extension://${extensionId}/options.html`);
  await options.evaluate((c) => chrome.runtime.sendMessage({ type: "settings", changes: c }), changes);
  await options.close();
};

const real = await read("https://site-a.example/");
assert.ok(real.imageStable && real.canvas === real.canvasAgain, "the page reads stable values without noise");
step(`baseline read (cores ${real.cores}, memory ${real.memory}, WebGL ${real.renderer ? "on" : "off"})`);

await settings({ fingerprintNoise: true, warnOnSuspicious: false });
const a1 = await read("https://site-a.example/");
assert.notEqual(a1.canvas, real.canvas, "canvas export changes");
assert.notEqual(a1.image, real.image, "getImageData changes");
assert.notEqual(a1.audio, real.audio, "audio samples change");
assert.notEqual(a1.audioCopy, real.audioCopy, "copyFromChannel changes too");
assert.equal(real.frameContent, real.canvas, "a same-origin frame draws the same as the page without noise");
assert.notEqual(a1.frameContent, real.frameContent, "a frame reached through contentWindow is covered");
assert.notEqual(a1.frameIndex, real.frameIndex, "a frame reached through window[i] is covered");
assert.notEqual(a1.workerBlob, real.workerBlob, "OffscreenCanvas.convertToBlob in a worker is covered");
assert.notEqual(a1.workerPixels, real.workerPixels, "OffscreenCanvas getImageData in a worker is covered");
assert.equal(a1.workerCores, a1.cores, "the worker reports the same processor count as the page");
assert.deepEqual(a1.leaks, [], "WebRTC shows no local network address");
const policy = await worker.evaluate(() => chrome.privacy.network.webRTCIPHandlingPolicy.get({}));
assert.equal(policy.value, "default_public_interface_only");
assert.ok([4, 8, 12].includes(a1.cores), `cores from the common set (${a1.cores})`);
if (real.memory !== undefined) assert.ok([4, 8].includes(a1.memory), `memory from the common set (${a1.memory})`);
if (real.renderer) assert.match(a1.renderer, /^ANGLE \(/);
assert.ok(a1.imageStable && a1.canvas === a1.canvasAgain && a1.audioSame, "repeated reads agree, so the noise can't be spotted by reading twice");
assert.equal(a1.native, "function toDataURL() { [native code] }");
step("noise on: canvas, image data, audio, cores and memory differ from the real values; repeated reads agree; functions look native");
step("covered in script-made frames (contentWindow and window[i]), workers (OffscreenCanvas), copyFromChannel; WebRTC limited to the public interface");

const a2 = await read("https://site-a.example/");
assert.deepEqual({ ...a2, early: null }, { ...a1, early: null }, "same site, same session: same values");
// How often the noise is in place before the page's first inline script runs.
let early = 0;
const RUNS = 10;
for (let i = 0; i < RUNS; i++) if ((await read("https://site-a.example/")).early === a1.cores) early += 1;
step(`noise in place before the first inline script on ${early} of ${RUNS} loads`);
const b = await read("https://site-b.example/");
assert.notEqual(b.canvas, a1.canvas, "another site sees another canvas");
step("stable for a site within the session; different on another site");

await settings({ fingerprintBypass: ["site-a.example"] });
const bypassed = await read("https://site-a.example/");
assert.equal(bypassed.canvas, real.canvas);
assert.equal(bypassed.cores, real.cores);
assert.equal(bypassed.audio, real.audio);
assert.equal(bypassed.frameContent, real.frameContent);
assert.equal(bypassed.workerBlob, real.workerBlob);
const stillB = await read("https://site-b.example/");
assert.equal(stillB.canvas, b.canvas);
step("a site the person turned it off for gets the real values; other sites keep their noise");

await context.close();
server.close();
console.log("All fingerprint noise checks passed.");
