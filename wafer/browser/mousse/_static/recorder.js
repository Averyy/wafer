/* Mousse — mouse movement recorder */

// ── State ──────────────────────────────────────────────────────────────
let mode = "idle"; // idle | path | hold | drag | browse
let state = "ready"; // ready | countdown | recording | preview
let points = []; // raw captured points [{t, x, y}]
let startTime = 0;
let holdStartPos = null;
let countdownTimer = null;
let recordingTimer = null;
let animFrameId = null;

// ── DOM refs ───────────────────────────────────────────────────────────
const canvas = document.getElementById("canvas");
const ctx = canvas.getContext("2d");
const tabs = document.querySelectorAll(".tab");
const viewportSelect = document.getElementById("viewport-select");
const directionSelect = document.getElementById("direction-select");
const directionInfo = document.getElementById("direction-info");
const btnStart = document.getElementById("btn-start");
const btnAccept = document.getElementById("btn-accept");
const btnDiscard = document.getElementById("btn-discard");
const countdownEl = document.getElementById("countdown");
const countdownNum = document.getElementById("countdown-num");
const recordingsGrid = document.getElementById("recordings-grid");
const modal = document.getElementById("modal");
const modalCanvas = document.getElementById("modal-canvas");
const modalCtx = modalCanvas.getContext("2d");
const modalTitle = document.getElementById("modal-title");
const modalClose = document.getElementById("modal-close");

// ── Viewport ───────────────────────────────────────────────────────────
function getViewport() {
  const v = viewportSelect.value.split("x");
  return { w: parseInt(v[0]), h: parseInt(v[1]) };
}

function resizeCanvas() {
  const vp = getViewport();
  canvas.width = vp.w;
  canvas.height = vp.h;
  drawGuides();
}

viewportSelect.addEventListener("change", () => {
  if (state === "ready") resizeCanvas();
});

// ── Coordinate mapping ─────────────────────────────────────────────────
function canvasCoords(e) {
  // offsetX/offsetY are relative to the element's padding edge (content area),
  // clientWidth/clientHeight are the CSS content size (excluding border).
  // This correctly maps CSS pixels → logical canvas pixels regardless of
  // CSS scaling, borders, or devicePixelRatio.
  return {
    x: e.offsetX / canvas.clientWidth * canvas.width,
    y: e.offsetY / canvas.clientHeight * canvas.height,
  };
}

// ── Zone positions ─────────────────────────────────────────────────────
const ZONE_R = 40;
const HOLD_R = 50;

function getZones(direction) {
  const W = canvas.width, H = canvas.height;
  const zones = {
    to_center_from_ul: { start: { x: W * 0.05, y: H * 0.05 }, end: { x: W * 0.5, y: H * 0.55 } },
    to_center_from_ur: { start: { x: W * 0.95, y: H * 0.05 }, end: { x: W * 0.5, y: H * 0.55 } },
    to_center_from_l:  { start: { x: W * 0.05, y: H * 0.5  }, end: { x: W * 0.5, y: H * 0.55 } },
    to_center_from_bl: { start: { x: W * 0.05, y: H * 0.95 }, end: { x: W * 0.5, y: H * 0.55 } },
    to_center_from_br: { start: { x: W * 0.95, y: H * 0.95 }, end: { x: W * 0.5, y: H * 0.55 } },
    to_lower_from_ul:  { start: { x: W * 0.05, y: H * 0.05 }, end: { x: W * 0.5, y: H * 0.80 } },
  };
  return zones[direction];
}

function getDragZone() {
  const W = canvas.width, H = canvas.height;
  return {
    start: { x: W * 0.08, y: H * 0.5 },
    end: { x: W * 0.92, y: H * 0.5 },
  };
}

function getHoldTarget() {
  return { x: canvas.width * 0.5, y: canvas.height * 0.5 };
}

// ── Drawing helpers ────────────────────────────────────────────────────
function clear() {
  ctx.fillStyle = "#0d0d1a";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
}

function drawCircle(x, y, r, color, label) {
  ctx.beginPath();
  ctx.arc(x, y, r, 0, Math.PI * 2);
  ctx.fillStyle = color + "30";
  ctx.fill();
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.stroke();
  if (label) {
    ctx.fillStyle = color;
    ctx.font = "12px monospace";
    ctx.textAlign = "center";
    ctx.fillText(label, x, y + r + 16);
  }
}

function drawCrosshair(x, y, size, color) {
  ctx.strokeStyle = color;
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(x - size, y); ctx.lineTo(x + size, y);
  ctx.moveTo(x, y - size); ctx.lineTo(x, y + size);
  ctx.stroke();
}

function drawPath(pts, color, lineWidth) {
  if (pts.length < 2) return;
  ctx.strokeStyle = color;
  ctx.lineWidth = lineWidth || 2;
  ctx.lineCap = "round";
  ctx.lineJoin = "round";
  ctx.beginPath();
  ctx.moveTo(pts[0].x, pts[0].y);
  for (let i = 1; i < pts.length; i++) {
    ctx.lineTo(pts[i].x, pts[i].y);
  }
  ctx.stroke();
}

function drawGuides() {
  clear();

  if (mode === "idle") {
    ctx.fillStyle = "#808090";
    ctx.font = "16px monospace";
    ctx.textAlign = "center";
    ctx.fillText("Move your mouse around naturally", canvas.width / 2, canvas.height / 2 - 10);
    ctx.font = "12px monospace";
    ctx.fillText("Press Space or click Start to begin (1-4s recording)", canvas.width / 2, canvas.height / 2 + 16);
  } else if (mode === "path") {
    const dir = directionSelect.value;
    const z = getZones(dir);
    if (z) {
      drawCircle(z.start.x, z.start.y, ZONE_R, "#4ecca3", "START");
      drawCircle(z.end.x, z.end.y, ZONE_R, "#e94560", "END");
      ctx.strokeStyle = "#2a2a4a";
      ctx.lineWidth = 1;
      ctx.setLineDash([8, 8]);
      ctx.beginPath();
      ctx.moveTo(z.start.x, z.start.y);
      ctx.lineTo(z.end.x, z.end.y);
      ctx.stroke();
      ctx.setLineDash([]);
    }
    // State-aware instruction text (prevents overlap)
    ctx.font = "14px monospace";
    ctx.textAlign = "center";
    if (state === "recording" && pathStarted && pathReady) {
      ctx.fillStyle = "#e94560";
      ctx.fillText("Go \u2014 move to the red zone!", canvas.width / 2, canvas.height - 20);
    } else if (state === "recording" && pathStarted) {
      ctx.fillStyle = "#4ecca3";
      ctx.fillText("Hold still...", canvas.width / 2, canvas.height - 20);
    } else if (state === "recording") {
      ctx.fillStyle = "#4ecca3";
      ctx.fillText("Move cursor into the green zone", canvas.width / 2, canvas.height - 20);
    } else {
      ctx.fillStyle = "#808090";
      ctx.fillText("Press Space to begin", canvas.width / 2, canvas.height - 20);
    }
  } else if (mode === "hold") {
    const t = getHoldTarget();
    drawCircle(t.x, t.y, HOLD_R, "#e94560", "HOLD");
    drawCrosshair(t.x, t.y, 20, "#e94560");
    ctx.fillStyle = "#808090";
    ctx.font = "14px monospace";
    ctx.textAlign = "center";
    if (state === "recording") {
      ctx.fillStyle = "#4ecca3";
      ctx.fillText("Click and hold inside the red circle", canvas.width / 2, canvas.height - 20);
    } else {
      ctx.fillText("Press Space, then click and hold the red circle (12s)", canvas.width / 2, canvas.height - 20);
    }
  } else if (mode === "drag") {
    const z = getDragZone();
    drawCircle(z.start.x, z.start.y, ZONE_R, "#4ecca3", "START");
    drawCircle(z.end.x, z.end.y, ZONE_R, "#e94560", "END");
    ctx.strokeStyle = "#2a2a4a";
    ctx.lineWidth = 2;
    ctx.setLineDash([8, 8]);
    ctx.beginPath();
    ctx.moveTo(z.start.x, z.start.y);
    ctx.lineTo(z.end.x, z.end.y);
    ctx.stroke();
    ctx.setLineDash([]);
    // State-aware instruction text (prevents overlap)
    ctx.font = "14px monospace";
    ctx.textAlign = "center";
    if (state === "recording" && dragStarted && dragReady) {
      ctx.fillStyle = "#e94560";
      ctx.fillText("Go \u2014 drag to the red zone!", canvas.width / 2, canvas.height - 20);
    } else if (state === "recording" && dragStarted) {
      ctx.fillStyle = "#4ecca3";
      ctx.fillText("Hold still...", canvas.width / 2, canvas.height - 20);
    } else if (state === "recording") {
      ctx.fillStyle = "#4ecca3";
      ctx.fillText("Move cursor into the green zone", canvas.width / 2, canvas.height - 20);
    } else {
      ctx.fillStyle = "#808090";
      ctx.fillText("Press Space to begin", canvas.width / 2, canvas.height - 20);
    }
  } else if (mode === "browse") {
    drawBrowsePage();
  }
}

// ── Browse page rendering ──────────────────────────────────────────────
const _LOREM = [
  "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor.",
  "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi.",
  "Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore.",
  "Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia.",
  "Curabitur pretium tincidunt lacus. Nulla gravida orci a odio dignissim.",
  "Sed vel lectus. Donec odio urna tempus molestie porttitor ut nulla.",
  "Pellentesque habitant morbi tristique senectus et netus et malesuada fames.",
  "Vestibulum tortor quam, feugiat vitae, ultricies eget tempor sit amet ante.",
  "Mauris placerat eleifend leo. Quisque sit amet est et sapien ullamcorper.",
  "Proin quam nisl, tincidunt et, mattis eget vehicula vitae nunc facilisis.",
  "Aenean imperdiet. Etiam ultricies nisi vel augue. Curabitur ullamcorper.",
  "Maecenas tempus tellus eget condimentum rhoncus sem quam semper libero.",
];

function drawBrowsePage() {
  const W = canvas.width, H = canvas.height;
  clear();

  // Total content height based on section count
  const sectionH = 140;
  const headerH = 60;
  const totalContentH = headerH + browsePageSections * sectionH + 40;
  const maxScroll = Math.max(0, totalContentH - H);
  const scrollY = Math.max(0, Math.min(browseScrollOffset, maxScroll));

  ctx.save();
  ctx.beginPath();
  ctx.rect(0, 0, W, H);
  ctx.clip();

  // Fake header bar (fixed at top)
  ctx.fillStyle = "#1a1a2e";
  ctx.fillRect(0, 0, W, headerH);
  ctx.fillStyle = "#4a4a6a";
  ctx.fillRect(40, 18, 200, 24);
  ctx.fillRect(W - 180, 18, 40, 24);
  ctx.fillRect(W - 120, 18, 40, 24);
  ctx.fillRect(W - 60, 18, 40, 24);
  ctx.fillStyle = "#606080";
  ctx.font = "13px sans-serif";
  ctx.textAlign = "left";
  ctx.fillText("Example Page", 50, 35);

  // Content sections (scrollable)
  for (let i = 0; i < browsePageSections; i++) {
    const baseY = headerH + i * sectionH - scrollY;
    if (baseY > H || baseY + sectionH < 0) continue; // off-screen

    // Section card
    ctx.fillStyle = "#16162a";
    ctx.fillRect(60, baseY + 10, W - 120, sectionH - 20);
    ctx.strokeStyle = "#2a2a4a";
    ctx.lineWidth = 1;
    ctx.strokeRect(60, baseY + 10, W - 120, sectionH - 20);

    // Section header
    ctx.fillStyle = "#5a5a8a";
    ctx.font = "bold 14px sans-serif";
    ctx.textAlign = "left";
    ctx.fillText(`Section ${i + 1}`, 80, baseY + 35);

    // Lorem text lines
    ctx.fillStyle = "#3a3a5a";
    ctx.font = "12px sans-serif";
    const line1 = _LOREM[i % _LOREM.length];
    const line2 = _LOREM[(i + 3) % _LOREM.length];
    const line3 = _LOREM[(i + 7) % _LOREM.length];
    ctx.fillText(line1.slice(0, Math.floor((W - 160) / 7)), 80, baseY + 58);
    ctx.fillText(line2.slice(0, Math.floor((W - 160) / 7)), 80, baseY + 78);
    ctx.fillText(line3.slice(0, Math.floor((W - 160) / 7)), 80, baseY + 98);
  }

  // Scrollbar
  if (maxScroll > 0) {
    ctx.fillStyle = "#1a1a2e";
    ctx.fillRect(W - 12, headerH, 12, H - headerH);
    const thumbH = Math.max(30, (H - headerH) * (H / totalContentH));
    const thumbY = headerH + (scrollY / maxScroll) * ((H - headerH) - thumbH);
    ctx.fillStyle = "#4a4a6a";
    ctx.fillRect(W - 10, thumbY, 8, thumbH);
  }

  ctx.restore();

  // Instructions (centered overlay, only when not recording)
  if (state !== "recording") {
    // Semi-transparent backdrop
    ctx.fillStyle = "rgba(13, 13, 26, 0.7)";
    ctx.fillRect(W / 2 - 260, H / 2 - 40, 520, 90);
    ctx.fillStyle = "#808090";
    ctx.font = "16px monospace";
    ctx.textAlign = "center";
    ctx.fillText("Browse naturally \u2014 move mouse & scroll", W / 2, H / 2 - 10);
    ctx.font = "12px monospace";
    ctx.fillText(`Press Space to begin (8s) \u2014 ${browsePageSections} sections`, W / 2, H / 2 + 12);
    ctx.fillText("\u2191\u2193 Scroll up and down as you explore", W / 2, H / 2 + 32);
  }
}

// ── Mode tabs ──────────────────────────────────────────────────────────
function switchMode(newMode) {
  if (state !== "ready") return;
  mode = newMode;
  tabs.forEach(t => t.classList.toggle("active", t.dataset.mode === mode));
  directionSelect.classList.toggle("hidden", mode !== "path");
  directionInfo.classList.toggle("hidden", mode !== "path");
  if (mode === "path") updateDirectionInfo();
  syncActiveTab();
  resizeCanvas();
}

tabs.forEach(tab => {
  tab.addEventListener("click", () => switchMode(tab.dataset.mode));
});

// Clicking a stat badge also switches to that mode
document.querySelectorAll(".stat[data-mode]").forEach(stat => {
  stat.style.cursor = "pointer";
  stat.addEventListener("click", () => switchMode(stat.dataset.mode));
});

// Also track drag recording state
let dragStarted = false;

// Browse mode: scroll events captured separately
let browseScrollEvents = [];
// Browse mode: randomized content length (sections) per recording
let browsePageSections = 6; // default, randomized on each start
let browseScrollOffset = 0; // current scroll position in the fake page

// Dwell: true once the 500ms start-zone dwell is complete
let pathReady = false;
let dragReady = false;

// Settle timer: keep recording 500ms after entering end zone
let settleTimer = null;

// ── Direction info ─────────────────────────────────────────────────────
let pathBreakdown = { counts: {}, targets: {} };

function updateDirectionInfo() {
  const dir = directionSelect.value;
  const have = pathBreakdown.counts[dir] || 0;
  const need = pathBreakdown.targets[dir] || 0;
  const cls = have >= need ? "done" : "needed";
  directionInfo.innerHTML = `<span class="${cls}">${have}/${need} recorded</span>`;
}

directionSelect.addEventListener("change", () => {
  updateDirectionInfo();
  if (state === "ready") drawGuides();
});

// ── Stats ──────────────────────────────────────────────────────────────
function updateStats(data) {
  for (const cat of ["idles", "paths", "holds", "drags", "browses"]) {
    const el = document.getElementById(`stat-${cat}`);
    const info = data[cat];
    const valueEl = el.querySelector(".stat-value");
    if (valueEl) valueEl.textContent = `${info.count}/${info.target}`;
    const iconEl = el.querySelector(".stat-icon");
    const done = info.count >= info.target;
    if (iconEl) iconEl.textContent = done ? "\u2705" : "\u26A0\uFE0F";
    const isActive = el.classList.contains("active-tab");
    el.className = "stat " + (done ? "complete" : "incomplete") + (isActive ? " active-tab" : "");
  }
  if (data.path_breakdown) {
    pathBreakdown = data.path_breakdown;
    if (mode === "path") updateDirectionInfo();
  }
}

function syncActiveTab() {
  const modeToStat = { idle: "stat-idles", path: "stat-paths", hold: "stat-holds", drag: "stat-drags", browse: "stat-browses" };
  for (const [m, id] of Object.entries(modeToStat)) {
    document.getElementById(id).classList.toggle("active-tab", m === mode);
  }
}

// ── Recordings list ────────────────────────────────────────────────────
let allRecordings = {};

async function refreshRecordings() {
  const resp = await fetch("/api/recordings");
  const data = await resp.json();
  allRecordings = data;
  updateStats(data);
  renderRecordings(data);
}

function renderRecordings(data) {
  recordingsGrid.innerHTML = "";
  const emptyEl = document.getElementById("recordings-empty");
  let total = 0;
  for (const cat of ["idles", "paths", "holds", "drags", "browses"]) total += data[cat].files.length;
  if (emptyEl) emptyEl.classList.toggle("hidden", total > 0);
  for (const cat of ["idles", "paths", "holds", "drags", "browses"]) {
    for (const file of data[cat].files) {
      const thumb = document.createElement("div");
      thumb.className = "recording-thumb";
      thumb.title = file;

      const tc = document.createElement("canvas");
      tc.width = 80;
      tc.height = 50;
      thumb.appendChild(tc);

      const label = document.createElement("div");
      label.className = "label";
      label.textContent = file.replace(".csv", "");
      thumb.appendChild(label);

      const del = document.createElement("div");
      del.className = "delete-btn";
      del.textContent = "×";
      del.addEventListener("click", async (e) => {
        e.stopPropagation();
        await fetch(`/api/recordings/${cat}/${file}`, { method: "DELETE" });
        showStatus("Deleted " + file, "success");
        refreshRecordings();
      });
      thumb.appendChild(del);

      thumb.addEventListener("click", () => openPreview(cat, file));
      recordingsGrid.appendChild(thumb);

      // Load thumbnail
      loadThumbnail(tc, cat, file);
    }
  }
}

async function loadThumbnail(tc, category, filename) {
  const resp = await fetch(`/api/preview/${category}/${filename}`);
  const data = await resp.json();
  const tctx = tc.getContext("2d");
  tctx.fillStyle = "#0d0d1a";
  tctx.fillRect(0, 0, 80, 50);

  if (!data.rows || data.rows.length < 2) return;

  const cols = data.columns;
  const isNormalized = cols[1] === "rx"; // paths use rx,ry

  tctx.strokeStyle = "#4ecca3";
  tctx.lineWidth = 1;
  tctx.beginPath();

  if (isNormalized) {
    // Path: rx,ry normalized 0-1
    tctx.moveTo(data.rows[0][1] * 70 + 5, data.rows[0][2] * 40 + 5);
    for (let i = 1; i < data.rows.length; i++) {
      tctx.lineTo(data.rows[i][1] * 70 + 5, data.rows[i][2] * 40 + 5);
    }
  } else {
    // Idle/Hold: dx,dy deltas — find bounds and scale
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    for (const row of data.rows) {
      minX = Math.min(minX, row[1]);
      maxX = Math.max(maxX, row[1]);
      minY = Math.min(minY, row[2]);
      maxY = Math.max(maxY, row[2]);
    }
    const rangeX = maxX - minX || 1;
    const rangeY = maxY - minY || 1;
    const scX = 70 / rangeX, scY = 40 / rangeY;
    const sc = Math.min(scX, scY);
    tctx.moveTo((data.rows[0][1] - minX) * sc + 5, (data.rows[0][2] - minY) * sc + 5);
    for (let i = 1; i < data.rows.length; i++) {
      tctx.lineTo((data.rows[i][1] - minX) * sc + 5, (data.rows[i][2] - minY) * sc + 5);
    }
  }
  tctx.stroke();
}

// ── Preview modal ──────────────────────────────────────────────────────
let previewAnimId = null;

async function openPreview(category, filename) {
  const resp = await fetch(`/api/preview/${category}/${filename}`);
  const data = await resp.json();
  if (!data.rows || data.rows.length < 2) return;

  modalTitle.textContent = filename;
  modal.classList.remove("hidden");

  // Animate playback
  const cols = data.columns;
  const isNormalized = cols[1] === "rx";
  const rows = data.rows;
  const duration = rows[rows.length - 1][0]; // total time in seconds
  const startT = performance.now();

  if (previewAnimId) cancelAnimationFrame(previewAnimId);

  function animate() {
    const elapsed = (performance.now() - startT) / 1000;
    const progress = Math.min(elapsed / duration, 1);

    modalCtx.fillStyle = "#0d0d1a";
    modalCtx.fillRect(0, 0, 600, 400);

    // Find how many points to draw
    let drawCount = 0;
    for (let i = 0; i < rows.length; i++) {
      if (rows[i][0] <= elapsed) drawCount = i + 1;
      else break;
    }

    if (drawCount >= 2) {
      if (isNormalized) {
        modalCtx.strokeStyle = "#4ecca3";
        modalCtx.lineWidth = 2;
        modalCtx.lineCap = "round";
        modalCtx.beginPath();
        modalCtx.moveTo(rows[0][1] * 560 + 20, rows[0][2] * 360 + 20);
        for (let i = 1; i < drawCount; i++) {
          modalCtx.lineTo(rows[i][1] * 560 + 20, rows[i][2] * 360 + 20);
        }
        modalCtx.stroke();

        // Current dot
        const last = rows[drawCount - 1];
        modalCtx.beginPath();
        modalCtx.arc(last[1] * 560 + 20, last[2] * 360 + 20, 4, 0, Math.PI * 2);
        modalCtx.fillStyle = "#e94560";
        modalCtx.fill();
      } else {
        // dx,dy — center-based scatter/trail
        const cx = 300, cy = 200;
        modalCtx.strokeStyle = "#4ecca340";
        modalCtx.lineWidth = 1;
        modalCtx.beginPath();
        modalCtx.moveTo(cx + rows[0][1], cy + rows[0][2]);
        for (let i = 1; i < drawCount; i++) {
          modalCtx.lineTo(cx + rows[i][1], cy + rows[i][2]);
        }
        modalCtx.stroke();

        // Dots for recent points
        const recentStart = Math.max(0, drawCount - 20);
        for (let i = recentStart; i < drawCount; i++) {
          const alpha = (i - recentStart) / 20;
          modalCtx.beginPath();
          modalCtx.arc(cx + rows[i][1], cy + rows[i][2], 2 + alpha * 2, 0, Math.PI * 2);
          modalCtx.fillStyle = `rgba(78, 204, 163, ${0.3 + alpha * 0.7})`;
          modalCtx.fill();
        }
      }
    }

    // Progress text
    modalCtx.fillStyle = "#808090";
    modalCtx.font = "12px monospace";
    modalCtx.textAlign = "right";
    modalCtx.fillText(`${elapsed.toFixed(1)}s / ${duration.toFixed(1)}s`, 590, 390);

    if (progress < 1) {
      previewAnimId = requestAnimationFrame(animate);
    }
  }

  previewAnimId = requestAnimationFrame(animate);
}

function closePreview() {
  modal.classList.add("hidden");
  if (previewAnimId) {
    cancelAnimationFrame(previewAnimId);
    previewAnimId = null;
  }
}

modalClose.addEventListener("click", closePreview);
modal.addEventListener("click", (e) => {
  if (e.target === modal) closePreview();
});

// ── Status toast ───────────────────────────────────────────────────────
function showStatus(msg, type) {
  const el = document.createElement("div");
  el.className = `status-msg ${type}`;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 2200);
}

// ── Recording logic ────────────────────────────────────────────────────

function startRecording() {
  if (state !== "ready") return;
  points = [];
  holdStartPos = null;

  if (mode === "idle") {
    startCountdown(() => {
      beginCapture();
      const idleDuration = 1000 + Math.random() * 3000; // 1-4s
      recordingTimer = setTimeout(() => finishRecording(), idleDuration);
    });
  } else if (mode === "path") {
    // Path: wait for cursor to enter start zone
    state = "recording";
    updateButtons();
    drawGuides();
  } else if (mode === "hold") {
    state = "recording";
    updateButtons();
    drawGuides();
  } else if (mode === "drag") {
    // Drag: wait for cursor to enter start zone (like path)
    state = "recording";
    dragStarted = false;
    updateButtons();
    drawGuides();
  } else if (mode === "browse") {
    // Randomize page length: 6-24 sections (always scrollable)
    browsePageSections = 6 + Math.floor(Math.random() * 19);
    browseScrollOffset = 0;
    drawGuides();
    startCountdown(() => {
      browseScrollEvents = [];
      beginCapture();
      recordingTimer = setTimeout(() => finishRecording(), 8000);
    });
  }
}

function startCountdown(callback) {
  state = "countdown";
  updateButtons();
  let count = 3;
  countdownEl.classList.remove("hidden");
  countdownNum.textContent = count;

  countdownTimer = setInterval(() => {
    count--;
    if (count <= 0) {
      clearInterval(countdownTimer);
      countdownEl.classList.add("hidden");
      callback();
    } else {
      countdownNum.textContent = count;
    }
  }, 1000);
}

function beginCapture() {
  state = "recording";
  startTime = performance.now();
  points = [];
  updateButtons();
}

// ── Mouse handlers ─────────────────────────────────────────────────────
let pathStarted = false;
let holdActive = false;

canvas.addEventListener("mousemove", (e) => {
  if (state !== "recording") return;
  const p = canvasCoords(e);
  const t = (performance.now() - startTime) / 1000;

  if (mode === "idle" || mode === "browse") {
    points.push({ t, x: p.x, y: p.y });
    // Draw trail
    if (points.length >= 2) {
      const prev = points[points.length - 2];
      ctx.strokeStyle = mode === "browse" ? "#7b68ee" : "#4ecca3";
      ctx.lineWidth = 2;
      ctx.lineCap = "round";
      ctx.beginPath();
      ctx.moveTo(prev.x, prev.y);
      ctx.lineTo(p.x, p.y);
      ctx.stroke();
    }
  } else if (mode === "path") {
    if (!pathStarted) {
      // Check if cursor entered start zone
      const z = getZones(directionSelect.value);
      const dx = p.x - z.start.x, dy = p.y - z.start.y;
      if (Math.sqrt(dx * dx + dy * dy) < ZONE_R) {
        pathStarted = true;
        pathReady = false;
        startTime = performance.now();
        points = [{ t: 0, x: p.x, y: p.y }];
        drawGuides();
        // After 500ms dwell, allow end-zone detection
        setTimeout(() => {
          if (!pathStarted) return;
          pathReady = true;
          drawGuides();
        }, 500);
        // Timeout after 10s
        recordingTimer = setTimeout(() => {
          showStatus("Path recording timed out (10s)", "error");
          discardRecording();
        }, 10000);
      }
    } else {
      points.push({ t: (performance.now() - startTime) / 1000, x: p.x, y: p.y });
      // Draw trail
      if (points.length >= 2) {
        const prev = points[points.length - 2];
        ctx.strokeStyle = "#e94560";
        ctx.lineWidth = 2;
        ctx.lineCap = "round";
        ctx.beginPath();
        ctx.moveTo(prev.x, prev.y);
        ctx.lineTo(p.x, p.y);
        ctx.stroke();
      }
      // Check if reached end zone — keep recording 500ms to capture settle
      const z = getZones(directionSelect.value);
      const dx = p.x - z.end.x, dy = p.y - z.end.y;
      if (pathReady && Math.sqrt(dx * dx + dy * dy) < ZONE_R && !settleTimer) {
        settleTimer = setTimeout(() => {
          clearTimeout(recordingTimer);
          finishRecording();
        }, 500);
      }
    }
  } else if (mode === "drag") {
    if (!dragStarted) {
      // Check if cursor entered start zone
      const z = getDragZone();
      const dx = p.x - z.start.x, dy = p.y - z.start.y;
      if (Math.sqrt(dx * dx + dy * dy) < ZONE_R) {
        dragStarted = true;
        dragReady = false;
        startTime = performance.now();
        points = [{ t: 0, x: p.x, y: p.y }];
        drawGuides();
        // After 500ms dwell, allow end-zone detection
        setTimeout(() => {
          if (!dragStarted) return;
          dragReady = true;
          drawGuides();
        }, 500);
        // Timeout after 5s
        recordingTimer = setTimeout(() => {
          showStatus("Drag recording timed out (5s)", "error");
          discardRecording();
        }, 5000);
      }
    } else {
      points.push({ t: (performance.now() - startTime) / 1000, x: p.x, y: p.y });
      // Draw trail
      if (points.length >= 2) {
        const prev = points[points.length - 2];
        ctx.strokeStyle = "#e94560";
        ctx.lineWidth = 2;
        ctx.lineCap = "round";
        ctx.beginPath();
        ctx.moveTo(prev.x, prev.y);
        ctx.lineTo(p.x, p.y);
        ctx.stroke();
      }
      // Check if reached end zone — keep recording 500ms to capture settle
      const z = getDragZone();
      const dx = p.x - z.end.x, dy = p.y - z.end.y;
      if (dragReady && Math.sqrt(dx * dx + dy * dy) < ZONE_R && !settleTimer) {
        settleTimer = setTimeout(() => {
          clearTimeout(recordingTimer);
          finishRecording();
        }, 500);
      }
    }
  } else if (mode === "hold" && holdActive) {
    points.push({ t: (performance.now() - startTime) / 1000, x: p.x, y: p.y });
    // Draw jitter dot
    const dx = p.x - holdStartPos.x, dy = p.y - holdStartPos.y;
    ctx.beginPath();
    ctx.arc(p.x, p.y, 2, 0, Math.PI * 2);
    ctx.fillStyle = "#4ecca380";
    ctx.fill();
  }
});

canvas.addEventListener("mousedown", (e) => {
  if (state !== "recording" || mode !== "hold") return;
  const p = canvasCoords(e);
  const t = getHoldTarget();
  const dx = p.x - t.x, dy = p.y - t.y;
  if (Math.sqrt(dx * dx + dy * dy) > HOLD_R) return;

  holdActive = true;
  holdStartPos = { x: p.x, y: p.y };
  startTime = performance.now();
  points = [{ t: 0, x: p.x, y: p.y }];

  // Draw progress bar
  const progressWrap = document.createElement("div");
  progressWrap.className = "progress-bar";
  progressWrap.id = "hold-progress";
  const fill = document.createElement("div");
  fill.className = "fill";
  progressWrap.appendChild(fill);
  canvas.parentElement.appendChild(progressWrap);

  // Progress update loop
  const holdDuration = 12000; // 12 seconds
  function updateProgress() {
    if (!holdActive) return;
    const elapsed = performance.now() - startTime;
    const pct = Math.min(elapsed / holdDuration * 100, 100);
    fill.style.width = pct + "%";

    // Time display on canvas
    ctx.fillStyle = "#0d0d1a";
    ctx.fillRect(canvas.width / 2 - 40, canvas.height - 35, 80, 20);
    ctx.fillStyle = "#4ecca3";
    ctx.font = "14px monospace";
    ctx.textAlign = "center";
    ctx.fillText((elapsed / 1000).toFixed(1) + "s", canvas.width / 2, canvas.height - 20);

    if (elapsed >= holdDuration) {
      endHold();
    } else {
      animFrameId = requestAnimationFrame(updateProgress);
    }
  }
  animFrameId = requestAnimationFrame(updateProgress);
});

canvas.addEventListener("mouseup", () => {
  if (holdActive) endHold();
});

canvas.addEventListener("mouseleave", () => {
  if (holdActive) endHold();
});

canvas.addEventListener("wheel", (e) => {
  if (state !== "recording" || mode !== "browse") return;
  e.preventDefault();

  // Don't record scroll events if the page isn't scrollable
  const sectionH = 140, headerH = 60;
  const totalContentH = headerH + browsePageSections * sectionH + 40;
  const maxScroll = Math.max(0, totalContentH - canvas.height);
  if (maxScroll <= 0) return;

  const t = (performance.now() - startTime) / 1000;
  browseScrollEvents.push({ t, deltaY: e.deltaY });

  // Scroll the fake page content
  browseScrollOffset += e.deltaY * 0.5;
  browseScrollOffset = Math.max(0, Math.min(browseScrollOffset, maxScroll));

  // Redraw the page at new scroll position, then overlay the mouse trail
  drawBrowsePage();
  // Redraw mouse trail on top of the scrolled content
  if (points.length >= 2) {
    ctx.strokeStyle = "#7b68ee";
    ctx.lineWidth = 2;
    ctx.lineCap = "round";
    ctx.lineJoin = "round";
    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 1; i < points.length; i++) {
      ctx.lineTo(points[i].x, points[i].y);
    }
    ctx.stroke();
  }
}, { passive: false });

function endHold() {
  if (!holdActive) return;
  holdActive = false;
  if (animFrameId) {
    cancelAnimationFrame(animFrameId);
    animFrameId = null;
  }
  const pb = document.getElementById("hold-progress");
  if (pb) pb.remove();

  if (points.length < 10) {
    showStatus("Hold too short (need 10+ events)", "error");
    discardRecording();
    return;
  }
  finishRecording();
}

// ── Finish & preview ───────────────────────────────────────────────────
function finishRecording() {
  state = "preview";
  pathStarted = false;
  updateButtons();

  // Draw the preview
  clear();
  if (mode === "idle") {
    drawPath(points, "#4ecca3", 2);
    ctx.fillStyle = "#808090";
    ctx.font = "14px monospace";
    ctx.textAlign = "center";
    ctx.fillText(`${points.length} events, ${points[points.length - 1].t.toFixed(1)}s`, canvas.width / 2, canvas.height - 20);
  } else if (mode === "browse") {
    drawPath(points, "#7b68ee", 2);
    // Draw scroll events as tick marks along bottom
    for (const se of browseScrollEvents) {
      const frac = se.t / points[points.length - 1].t;
      const tx = frac * canvas.width;
      ctx.strokeStyle = se.deltaY > 0 ? "#e94560" : "#4ecca3";
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(tx, canvas.height - 40);
      ctx.lineTo(tx, canvas.height - 30);
      ctx.stroke();
    }
    ctx.fillStyle = "#808090";
    ctx.font = "14px monospace";
    ctx.textAlign = "center";
    ctx.fillText(
      `${points.length} mouse + ${browseScrollEvents.length} scroll events, ${points[points.length - 1].t.toFixed(1)}s`,
      canvas.width / 2, canvas.height - 20
    );
  } else if (mode === "path") {
    const z = getZones(directionSelect.value);
    drawCircle(z.start.x, z.start.y, ZONE_R, "#4ecca3", "START");
    drawCircle(z.end.x, z.end.y, ZONE_R, "#e94560", "END");
    drawPath(points, "#e94560", 2);
    ctx.fillStyle = "#808090";
    ctx.font = "14px monospace";
    ctx.textAlign = "center";
    ctx.fillText(`${points.length} events, ${points[points.length - 1].t.toFixed(1)}s`, canvas.width / 2, canvas.height - 20);
  } else if (mode === "drag") {
    const z = getDragZone();
    drawCircle(z.start.x, z.start.y, ZONE_R, "#4ecca3", "START");
    drawCircle(z.end.x, z.end.y, ZONE_R, "#e94560", "END");
    drawPath(points, "#e94560", 2);
    ctx.fillStyle = "#808090";
    ctx.font = "14px monospace";
    ctx.textAlign = "center";
    ctx.fillText(`${points.length} events, ${points[points.length - 1].t.toFixed(1)}s`, canvas.width / 2, canvas.height - 20);
  } else if (mode === "hold") {
    // Scatter plot of jitter
    const cx = canvas.width / 2, cy = canvas.height / 2;
    drawCrosshair(cx, cy, 40, "#2a2a4a");
    for (const pt of points) {
      const dx = pt.x - holdStartPos.x;
      const dy = pt.y - holdStartPos.y;
      ctx.beginPath();
      ctx.arc(cx + dx * 5, cy + dy * 5, 2, 0, Math.PI * 2); // 5x amplification for visibility
      ctx.fillStyle = "#4ecca380";
      ctx.fill();
    }
    ctx.fillStyle = "#808090";
    ctx.font = "14px monospace";
    ctx.textAlign = "center";
    ctx.fillText(`${points.length} events, ${points[points.length - 1].t.toFixed(1)}s (jitter 5× amplified)`, canvas.width / 2, canvas.height - 20);
  }
}

// ── Accept / Discard ───────────────────────────────────────────────────
async function acceptRecording() {
  if (state !== "preview") return;

  const vp = getViewport();
  const vpStr = `${vp.w}x${vp.h}`;

  let payload;

  if (mode === "idle") {
    // dx,dy deltas from start
    const sx = points[0].x, sy = points[0].y;
    const rows = points.map(p => [
      parseFloat(p.t.toFixed(3)),
      parseFloat((p.x - sx).toFixed(1)),
      parseFloat((p.y - sy).toFixed(1)),
    ]);
    payload = {
      type: "idles",
      columns: ["t", "dx", "dy"],
      metadata: { viewport: vpStr },
      rows,
    };
  } else if (mode === "browse") {
    // Merge mouse + scroll events into a single timeline
    // dx,dy deltas from start + scroll_y column (0 for mouse-only events)
    const sx = points[0].x, sy = points[0].y;

    // Build combined timeline: mouse events with scroll_y=0
    const mouseRows = points.map(p => ({
      t: p.t,
      dx: p.x - sx,
      dy: p.y - sy,
      scroll_y: 0,
    }));

    // Insert scroll events at their timestamps
    const scrollRows = browseScrollEvents.map(se => ({
      t: se.t,
      dx: null, // interpolated below
      dy: null,
      scroll_y: se.deltaY,
    }));

    // Merge and sort by time
    const all = [...mouseRows, ...scrollRows].sort((a, b) => a.t - b.t);

    // Interpolate dx/dy for scroll-only events from surrounding mouse events
    for (let i = 0; i < all.length; i++) {
      if (all[i].dx === null) {
        // Find nearest mouse event before and after
        let prev = null, next = null;
        for (let j = i - 1; j >= 0; j--) { if (all[j].dx !== null) { prev = all[j]; break; } }
        for (let j = i + 1; j < all.length; j++) { if (all[j].dx !== null) { next = all[j]; break; } }
        if (prev && next) {
          const frac = (all[i].t - prev.t) / (next.t - prev.t);
          all[i].dx = prev.dx + (next.dx - prev.dx) * frac;
          all[i].dy = prev.dy + (next.dy - prev.dy) * frac;
        } else if (prev) {
          all[i].dx = prev.dx;
          all[i].dy = prev.dy;
        } else if (next) {
          all[i].dx = next.dx;
          all[i].dy = next.dy;
        } else {
          all[i].dx = 0;
          all[i].dy = 0;
        }
      }
    }

    const rows = all.map(e => [
      parseFloat(e.t.toFixed(3)),
      parseFloat(e.dx.toFixed(1)),
      parseFloat(e.dy.toFixed(1)),
      parseFloat(e.scroll_y.toFixed(0)),
    ]);
    const _sectionH = 140, _headerH = 60;
    const _totalH = _headerH + browsePageSections * _sectionH + 40;
    const _maxScroll = Math.max(0, _totalH - vp.h);
    payload = {
      type: "browses",
      columns: ["t", "dx", "dy", "scroll_y"],
      metadata: { viewport: vpStr, sections: String(browsePageSections), max_scroll: String(_maxScroll) },
      rows,
    };
  } else if (mode === "path") {
    const dir = directionSelect.value;
    const z = getZones(dir);
    const sx = points[0].x, sy = points[0].y;
    const ex = z.end.x, ey = z.end.y;
    const dxRange = ex - sx, dyRange = ey - sy;

    // Guard against near-zero displacement
    if (Math.abs(dxRange) < 1 || Math.abs(dyRange) < 1) {
      showStatus("Path too short — discarding", "error");
      discardRecording();
      return;
    }

    const rows = points.map(p => [
      parseFloat(p.t.toFixed(3)),
      parseFloat(((p.x - sx) / dxRange).toFixed(4)),
      parseFloat(((p.y - sy) / dyRange).toFixed(4)),
    ]);
    payload = {
      type: "paths",
      columns: ["t", "rx", "ry"],
      metadata: {
        viewport: vpStr,
        start: `${Math.round(sx)},${Math.round(sy)}`,
        end: `${Math.round(ex)},${Math.round(ey)}`,
      },
      direction: dir,
      rows,
    };
  } else if (mode === "drag") {
    const z = getDragZone();
    const sx = points[0].x, sy = points[0].y;
    const ex = z.end.x, ey = z.end.y;
    const dxRange = ex - sx;

    if (Math.abs(dxRange) < 1) {
      showStatus("Drag too short — discarding", "error");
      discardRecording();
      return;
    }

    // ry normalized relative to horizontal displacement (captures wobble)
    const rows = points.map(p => [
      parseFloat(p.t.toFixed(3)),
      parseFloat(((p.x - sx) / dxRange).toFixed(4)),
      parseFloat(((p.y - sy) / dxRange).toFixed(4)),
    ]);
    payload = {
      type: "drags",
      columns: ["t", "rx", "ry"],
      metadata: {
        viewport: vpStr,
        start: `${Math.round(sx)},${Math.round(sy)}`,
        end: `${Math.round(ex)},${Math.round(ey)}`,
      },
      rows,
    };
  } else if (mode === "hold") {
    const rows = points.map(p => [
      parseFloat(p.t.toFixed(3)),
      parseFloat((p.x - holdStartPos.x).toFixed(1)),
      parseFloat((p.y - holdStartPos.y).toFixed(1)),
    ]);
    payload = {
      type: "holds",
      columns: ["t", "dx", "dy"],
      metadata: { viewport: vpStr },
      rows,
    };
  }

  const resp = await fetch("/api/save", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const result = await resp.json();

  if (resp.ok) {
    showStatus(`Saved ${result.filename}`, "success");
    refreshRecordings();
  } else {
    showStatus(`Error: ${result.error}`, "error");
  }

  resetState();
}

function discardRecording() {
  if (recordingTimer) {
    clearTimeout(recordingTimer);
    recordingTimer = null;
  }
  if (countdownTimer) {
    clearInterval(countdownTimer);
    countdownTimer = null;
  }
  if (animFrameId) {
    cancelAnimationFrame(animFrameId);
    animFrameId = null;
  }
  holdActive = false;
  pathStarted = false;
  pathReady = false;
  dragStarted = false;
  dragReady = false;
  browseScrollEvents = [];
  if (settleTimer) { clearTimeout(settleTimer); settleTimer = null; }
  const pb = document.getElementById("hold-progress");
  if (pb) pb.remove();
  countdownEl.classList.add("hidden");
  resetState();
}

function resetState() {
  state = "ready";
  points = [];
  pathStarted = false;
  pathReady = false;
  dragStarted = false;
  dragReady = false;
  browseScrollEvents = [];
  if (settleTimer) { clearTimeout(settleTimer); settleTimer = null; }
  holdActive = false;
  holdStartPos = null;
  updateButtons();
  drawGuides();
}

// ── Button state ───────────────────────────────────────────────────────
function updateButtons() {
  const isReady = state === "ready";
  const isPreview = state === "preview";
  const isRecording = state === "recording" || state === "countdown";

  btnStart.classList.toggle("hidden", !isReady);
  btnAccept.classList.toggle("hidden", !isPreview);
  btnDiscard.classList.toggle("hidden", !isPreview && !isRecording);

  tabs.forEach(t => t.disabled = !isReady);
  viewportSelect.disabled = !isReady;
  directionSelect.disabled = !isReady;
}

btnStart.addEventListener("click", startRecording);
btnAccept.addEventListener("click", acceptRecording);
btnDiscard.addEventListener("click", discardRecording);

// ── Keyboard shortcuts ─────────────────────────────────────────────────
document.addEventListener("keydown", (e) => {
  // Don't handle if typing in an input
  if (e.target.tagName === "INPUT" || e.target.tagName === "SELECT") return;

  if (e.code === "Space") {
    e.preventDefault();
    if (state === "ready") startRecording();
  } else if (e.code === "Enter") {
    e.preventDefault();
    if (state === "preview") acceptRecording();
  } else if (e.code === "Escape") {
    e.preventDefault();
    if (!managePopover.classList.contains("hidden")) {
      managePopover.classList.add("hidden");
    } else if (!modal.classList.contains("hidden")) {
      closePreview();
    } else if (state === "preview" || state === "recording" || state === "countdown") {
      discardRecording();
    }
  }
});

// ── Manage popover ────────────────────────────────────────────────────
const btnManage = document.getElementById("btn-manage");
const managePopover = document.getElementById("manage-popover");
const manageRows = document.getElementById("manage-rows");
const btnDeleteAll = document.getElementById("btn-delete-all");

btnManage.addEventListener("click", (e) => {
  e.stopPropagation();
  managePopover.classList.toggle("hidden");
  if (!managePopover.classList.contains("hidden")) populateManage();
});

document.addEventListener("click", (e) => {
  if (!managePopover.contains(e.target) && e.target !== btnManage) {
    managePopover.classList.add("hidden");
  }
});

function populateManage() {
  manageRows.innerHTML = "";
  let totalFiles = 0;
  for (const cat of ["idles", "paths", "holds", "drags", "browses"]) {
    const info = allRecordings[cat] || { files: [], count: 0, target: 0 };
    totalFiles += info.count;
    const row = document.createElement("div");
    row.className = "manage-row";
    row.innerHTML = `
      <span><span class="manage-row-label">${cat}</span><span class="manage-row-count">${info.count}/${info.target}</span></span>
      <div class="manage-row-actions">
        <button class="manage-row-delete" data-cat="${cat}" ${info.count === 0 ? "disabled" : ""}>Delete all</button>
      </div>`;
    manageRows.appendChild(row);
  }
  btnDeleteAll.disabled = totalFiles === 0;

  manageRows.querySelectorAll(".manage-row-delete").forEach(btn => {
    btn.addEventListener("click", async () => {
      const cat = btn.dataset.cat;
      const info = allRecordings[cat];
      if (!info || info.count === 0) return;
      if (!confirm(`Delete all ${info.count} ${cat} recordings?`)) return;
      for (const file of info.files) {
        await fetch(`/api/recordings/${cat}/${file}`, { method: "DELETE" });
      }
      showStatus(`Deleted all ${cat}`, "success");
      await refreshRecordings();
      populateManage();
    });
  });
}

btnDeleteAll.addEventListener("click", async () => {
  let total = 0;
  for (const cat of ["idles", "paths", "holds", "drags", "browses"]) {
    total += (allRecordings[cat]?.count || 0);
  }
  if (total === 0) return;
  if (!confirm(`Delete ALL ${total} recordings?`)) return;
  for (const cat of ["idles", "paths", "holds", "drags", "browses"]) {
    for (const file of (allRecordings[cat]?.files || [])) {
      await fetch(`/api/recordings/${cat}/${file}`, { method: "DELETE" });
    }
  }
  showStatus("Deleted everything", "success");
  await refreshRecordings();
  populateManage();
});

// ── Init ───────────────────────────────────────────────────────────────
resizeCanvas();
refreshRecordings();
