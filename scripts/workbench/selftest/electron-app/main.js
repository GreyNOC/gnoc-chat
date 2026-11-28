const { app, BrowserWindow, net } = require("electron");
const base = process.env.SB_SELFTEST_URL || "http://127.0.0.1:9";
app.whenReady().then(async () => {
  const w = new BrowserWindow({ show: false });
  await w.loadURL(base + "/page-renderer");
  try { const r = await net.fetch(base + "/electron-ping?from=main"); console.log("main fetch", r.status); }
  catch (e) { console.log("main fetch error", e.message); }
});
