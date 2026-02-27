/* Mousse — mouse movement recorder */

// ── State ──────────────────────────────────────────────────────────────
let mode = "idle"; // idle | path | hold | drag | slide_drag | grid | browse | det | cls
let state = "ready"; // ready | countdown | recording | preview
let points = []; // raw captured points [{t, x, y}]
let startTime = 0;
let holdStartPos = null;
let countdownTimer = null;
let recordingTimer = null;
let animFrameId = null;

// ── DET mode state (grid annotation) ──────────────────────────────────
let detEntries = [];          // all unannotated grid entries
let detIndex = 0;             // current entry index
let detImage = null;          // loaded Image object
let detGridSize = 0;          // 3 or 4
let detModelPicks = [];       // model's selected cells
let detUserPicks = new Set(); // user's clicked cells (togglable)
let detAnnotatedCount = 0;    // total annotated so far
let detTotalCount = 0;        // total failure entries (annotated + unannotated)
let detHasEntries = false;    // whether any failure entries exist at all

// ── CLS mode state (tile labeling) ───────────────────────────────────
let clsTiles = [];             // all tiles from metadata
let clsIndex = 0;             // current tile index (into filtered list)
let clsFiltered = [];         // filtered subset being reviewed
let clsImage = null;          // loaded Image object
let clsSelectedLabel = null;  // currently selected class label
let clsReviewedCount = 0;     // total reviewed
let clsTotalCount = 0;        // total tiles
let clsHasTiles = false;      // whether any tiles exist
let clsFilter = "unreviewed"; // "all" | "unreviewed" | "low_confidence"
let clsHistory = [];          // recent labels [{tile, label, imgSrc}]
const CLS_NAMES = [
  "Bicycle", "Bridge", "Bus", "Car", "Chimney", "Crosswalk",
  "Hydrant", "Motorcycle", "Mountain", "Other", "Palm",
  "Stair", "Tractor", "Traffic Light", "Boat", "Parking Meter", "None",
];
// No keyboard shortcuts for class buttons - click only

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

// ── Tool panel DOM refs (DET/CLS) ─────────────────────────────────────
const detPanel = document.getElementById("det-panel");
const detOutcomeEl = document.getElementById("det-outcome");
const detInstructionEl = document.getElementById("det-instruction");
const detGridEl = document.getElementById("det-grid");
const detProgressEl = document.getElementById("det-progress");
const clsPanel = document.getElementById("cls-panel");
const clsTileImg = document.getElementById("cls-tile-img");
const clsKeywordEl = document.getElementById("cls-keyword-text");
const clsConfWrap = document.getElementById("cls-confidence-wrap");
const clsButtonsWrap = document.getElementById("cls-buttons-wrap");
const clsProgressEl = document.getElementById("cls-progress");
const clsHistoryEl = document.getElementById("cls-history");
const controlsRight = document.querySelector(".controls-right");
const recordingsPanel = document.querySelector(".recordings-panel");

// ── Viewport ───────────────────────────────────────────────────────────
function getViewport() {
  const v = viewportSelect.value.split("x");
  return { w: parseInt(v[0]), h: parseInt(v[1]) };
}

// Track whether canvas is in HiDPI mode so coordinate mapping stays correct
let canvasDPR = 1;

function setCanvasSize(w, h, hidpi = false) {
  const dpr = hidpi ? (window.devicePixelRatio || 1) : 1;
  canvasDPR = dpr;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  canvas.style.width = w + "px";
  canvas.style.height = h + "px";
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}

function resizeCanvas() {
  const vp = getViewport();
  setCanvasSize(vp.w, vp.h, false);
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

// ── Drag puzzle state ───────────────────────────────────────────────────
// Randomized per recording: track width 200-400px, random notch position,
// random puzzle piece size. Simulates real slider CAPTCHAs so recordings
// capture the fast-approach + slow-placement behavior at realistic scale.
let dragPuzzle = null;

function randomizeDragPuzzle() {
  const W = canvas.width, H = canvas.height;
  const trackW = 200 + Math.floor(Math.random() * 201); // 200-400px
  const trackH = 40;
  const trackX = Math.floor((W - trackW) / 2); // centered
  const trackY = Math.floor(H * 0.55);

  // Puzzle piece: 40-80px wide
  const pieceW = 40 + Math.floor(Math.random() * 41);
  const pieceH = pieceW; // square

  // Notch position: 15-95% along the usable track (covers short to near-end drags)
  const usable = trackW - pieceW;
  const notchFrac = 0.15 + Math.random() * 0.8;
  const notchX = trackX + Math.floor(notchFrac * usable);
  const notchY = Math.floor(H * 0.25) + Math.floor(Math.random() * (trackY - Math.floor(H * 0.25) - pieceH - 20));

  // Background image area (above the track)
  const bgX = trackX;
  const bgY = notchY - 20;
  const bgW = trackW;
  const bgH = trackY - bgY - 10;

  // Random palette for visual variety
  const hue = Math.floor(Math.random() * 360);

  dragPuzzle = {
    trackX, trackY, trackW, trackH,
    pieceW, pieceH,
    notchX, notchY,
    bgX, bgY, bgW, bgH,
    hue,
    // Handle starts at left edge of track
    handleX: trackX,
    handleY: trackY,
    // Target: notch X is where the piece center should land
    targetX: notchX + pieceW / 2,
  };
}

function getDragZone() {
  if (!dragPuzzle) randomizeDragPuzzle();
  const p = dragPuzzle;
  const handleW = p.trackH + 6;
  return {
    start: { x: p.trackX + handleW / 2, y: p.trackY + p.trackH / 2 },
    end: { x: p.targetX, y: p.trackY + p.trackH / 2 },
  };
}

function getHoldTarget() {
  return { x: canvas.width * 0.5, y: canvas.height * 0.5 };
}

// ── Slide drag state (simple left→right, no puzzle) ──────────────────
let slideTrack = null;

function randomizeSlideTrack() {
  const W = canvas.width, H = canvas.height;
  const trackW = 300; // exact Baxia NoCaptcha width
  const trackH = 34;  // exact Baxia height
  const trackX = Math.floor((W - trackW) / 2);
  const trackY = Math.floor(H * 0.55);
  const handleW = 42; // exact Baxia handle width

  slideTrack = {
    trackX, trackY, trackW, trackH, handleW,
    handleX: trackX,
    handleY: trackY,
    maxSlide: trackW - handleW,
  };
}

function getSlideZone() {
  if (!slideTrack) randomizeSlideTrack();
  const s = slideTrack;
  return {
    start: { x: s.trackX + s.handleW / 2, y: s.trackY + s.trackH / 2 },
    end: { x: s.trackX + s.maxSlide + s.handleW / 2, y: s.trackY + s.trackH / 2 },
  };
}

function drawSlideTrack() {
  if (!slideTrack) randomizeSlideTrack();
  const s = slideTrack;
  const z = getSlideZone();

  // Track background
  ctx.fillStyle = "#333";
  ctx.beginPath();
  ctx.roundRect(s.trackX, s.trackY, s.trackW, s.trackH, 17);
  ctx.fill();

  // Fill bar (grows with drag)
  let fillW = 0;
  if (slideTrack._currentX !== undefined) {
    fillW = slideTrack._currentX - z.start.x + s.handleW / 2;
  }
  if (fillW > 0) {
    ctx.fillStyle = "#4caf50";
    ctx.beginPath();
    ctx.roundRect(s.trackX, s.trackY + 3, Math.min(fillW, s.trackW), s.trackH - 6, 14);
    ctx.fill();
  }

  // "Slide to verify" text
  ctx.fillStyle = "rgba(255,255,255,0.3)";
  ctx.font = "14px 'DM Sans', sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText("Slide to verify", s.trackX + s.trackW / 2, s.trackY + s.trackH / 2);

  // Handle
  let handleDrawX = s.trackX;
  if (slideTrack._currentX !== undefined) {
    handleDrawX = s.trackX + (slideTrack._currentX - z.start.x);
  }
  ctx.fillStyle = "#fff";
  ctx.beginPath();
  ctx.roundRect(handleDrawX, s.trackY + 2, s.handleW, s.trackH - 4, 15);
  ctx.fill();
  ctx.strokeStyle = "#999";
  ctx.lineWidth = 1;
  ctx.stroke();

  // ">>" arrows on handle
  ctx.fillStyle = "#999";
  ctx.font = "bold 16px sans-serif";
  ctx.textAlign = "center";
  ctx.fillText("»", handleDrawX + s.handleW / 2, s.trackY + s.trackH / 2);

  // "Sorry" text above
  ctx.fillStyle = "rgba(255,255,255,0.4)";
  ctx.font = "16px 'DM Sans', sans-serif";
  ctx.fillText("Sorry, we have detected unusual traffic", canvas.width / 2, s.trackY - 60);

  // Distance info
  ctx.fillStyle = "rgba(255,255,255,0.2)";
  ctx.font = "12px 'JetBrains Mono', monospace";
  const dragDist = Math.round(z.end.x - z.start.x);
  ctx.fillText(`${s.trackW}px track, ${dragDist}px slide`, s.trackX + s.trackW / 2, s.trackY + s.trackH + 20);
}

// Slide drag reuses drag state machine (approach -> hover -> drag)
// but always drags to the right edge of the track.

// ── Grid layout helpers ───────────────────────────────────────────────
const GRID_TILE_SIZE = 100;
const GRID_GAP = 4;
const GRID_COLS = 3;
const GRID_ROWS = 3;

function getGridOrigin() {
  const totalW = GRID_COLS * GRID_TILE_SIZE + (GRID_COLS - 1) * GRID_GAP;
  const totalH = GRID_ROWS * GRID_TILE_SIZE + (GRID_ROWS - 1) * GRID_GAP;
  return {
    x: Math.floor((canvas.width - totalW) / 2),
    y: Math.floor((canvas.height - totalH) / 2),
  };
}

function getTileBounds(tileIdx) {
  const origin = getGridOrigin();
  const col = tileIdx % GRID_COLS;
  const row = Math.floor(tileIdx / GRID_COLS);
  const x = origin.x + col * (GRID_TILE_SIZE + GRID_GAP);
  const y = origin.y + row * (GRID_TILE_SIZE + GRID_GAP);
  return { x, y, w: GRID_TILE_SIZE, h: GRID_TILE_SIZE };
}

function getTileCenter(tileIdx) {
  const b = getTileBounds(tileIdx);
  return { x: b.x + b.w / 2, y: b.y + b.h / 2 };
}

function hitTestTile(px, py) {
  for (let i = 0; i < 9; i++) {
    const b = getTileBounds(i);
    if (px >= b.x && px <= b.x + b.w && py >= b.y && py <= b.y + b.h) return i;
  }
  return -1;
}

function randomizeGrid() {
  // Pick 3 unique random tile indices, ensuring at least 2 different directions
  for (let attempt = 0; attempt < 50; attempt++) {
    const indices = [];
    while (indices.length < 3) {
      const idx = Math.floor(Math.random() * 9);
      if (!indices.includes(idx)) indices.push(idx);
    }
    // Check: not all 3 in the same row or same column
    const rows = indices.map(i => Math.floor(i / 3));
    const cols = indices.map(i => i % 3);
    const sameRow = rows[0] === rows[1] && rows[1] === rows[2];
    const sameCol = cols[0] === cols[1] && cols[1] === cols[2];
    if (!sameRow && !sameCol) {
      gridTargets = indices;
      return;
    }
  }
  // Fallback: just use any 3 distinct tiles
  gridTargets = [0, 4, 8];
}

function drawGrid() {
  const origin = getGridOrigin();
  const totalW = GRID_COLS * GRID_TILE_SIZE + (GRID_COLS - 1) * GRID_GAP;
  const totalH = GRID_ROWS * GRID_TILE_SIZE + (GRID_ROWS - 1) * GRID_GAP;

  // Background
  ctx.fillStyle = "#111122";
  ctx.fillRect(origin.x - 8, origin.y - 8, totalW + 16, totalH + 16);
  ctx.strokeStyle = "#2a2a4a";
  ctx.lineWidth = 1;
  ctx.strokeRect(origin.x - 8, origin.y - 8, totalW + 16, totalH + 16);

  for (let i = 0; i < 9; i++) {
    const b = getTileBounds(i);
    const targetIdx = gridTargets.indexOf(i);
    const isTarget = targetIdx !== -1;
    const isClicked = gridClicks.some(c => c.tile === i);
    const isCurrentTarget = isTarget && targetIdx === gridPhase - 1;

    // Tile fill
    if (isClicked) {
      ctx.fillStyle = "#1a3a2a";
    } else {
      ctx.fillStyle = "#1a1a2e";
    }
    ctx.fillRect(b.x, b.y, b.w, b.h);

    // Tile border
    if (isCurrentTarget) {
      ctx.strokeStyle = "#4ecca3";
      ctx.lineWidth = 3;
    } else if (isTarget && !isClicked) {
      ctx.strokeStyle = "#4ecca380";
      ctx.lineWidth = 2;
    } else {
      ctx.strokeStyle = "#2a2a4a";
      ctx.lineWidth = 1;
    }
    ctx.strokeRect(b.x, b.y, b.w, b.h);

    // Label for target tiles
    if (isTarget) {
      ctx.fillStyle = isClicked ? "#4ecca350" : (isCurrentTarget ? "#4ecca3" : "#4ecca380");
      ctx.font = "bold 24px 'JetBrains Mono', monospace";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(String(targetIdx + 1), b.x + b.w / 2, b.y + b.h / 2);
    }
  }

  // Instructions
  ctx.font = "14px monospace";
  ctx.textAlign = "center";
  ctx.textBaseline = "alphabetic";
  if (gridPhase === 4) {
    ctx.fillStyle = "#4ecca3";
    ctx.fillText("Settling...", canvas.width / 2, origin.y + totalH + 30);
  } else if (gridPhase >= 1 && gridPhase <= 3) {
    if (!gridStarted) {
      ctx.fillStyle = "#808090";
      ctx.fillText("Move cursor into tile 1", canvas.width / 2, origin.y + totalH + 30);
    } else if (!gridReady) {
      ctx.fillStyle = "#4ecca3";
      ctx.fillText("Hold still...", canvas.width / 2, origin.y + totalH + 30);
    } else {
      ctx.fillStyle = "#4ecca3";
      ctx.fillText(`Click tile ${gridPhase}`, canvas.width / 2, origin.y + totalH + 30);
    }
  }
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
    if (state === "ready") {
      // Don't show puzzle until recording starts
      ctx.fillStyle = "#808090";
      ctx.font = "16px monospace";
      ctx.textAlign = "center";
      ctx.fillText("Drag puzzle — approach, pause, then drag", canvas.width / 2, canvas.height / 2 - 10);
      ctx.font = "12px monospace";
      ctx.fillText("Press Space to begin (random puzzle each time)", canvas.width / 2, canvas.height / 2 + 16);
    } else {
      drawDragPuzzle();
      ctx.font = "14px monospace";
      ctx.textAlign = "center";
      if (dragStarted) {
        ctx.fillStyle = "#e94560";
        ctx.fillText("Drag to the notch \u2014 release when placed!", canvas.width / 2, canvas.height - 20);
      } else if (dragApproached) {
        ctx.fillStyle = "#4ecca3";
        ctx.fillText("Pause naturally (look at puzzle), then click and drag", canvas.width / 2, canvas.height - 20);
      } else {
        ctx.fillStyle = "#808090";
        ctx.fillText("Move cursor to the slider handle", canvas.width / 2, canvas.height - 20);
      }
    }
  } else if (mode === "slide_drag") {
    if (state === "ready") {
      ctx.fillStyle = "#808090";
      ctx.font = "16px monospace";
      ctx.textAlign = "center";
      ctx.fillText("Slide to verify — approach, pause, then slide right", canvas.width / 2, canvas.height / 2 - 10);
      ctx.font = "12px monospace";
      ctx.fillText("Press Space to begin (300px track, full-width drag)", canvas.width / 2, canvas.height / 2 + 16);
    } else {
      drawSlideTrack();
      ctx.font = "14px monospace";
      ctx.textAlign = "center";
      if (dragStarted) {
        ctx.fillStyle = "#e94560";
        ctx.fillText("Slide all the way right \u2014 release at the end!", canvas.width / 2, canvas.height - 20);
      } else if (dragApproached) {
        ctx.fillStyle = "#4ecca3";
        ctx.fillText("Pause naturally, then click and slide to the right", canvas.width / 2, canvas.height - 20);
      } else {
        ctx.fillStyle = "#808090";
        ctx.fillText("Move cursor to the slider handle", canvas.width / 2, canvas.height - 20);
      }
    }
  } else if (mode === "grid") {
    if (state === "ready") {
      ctx.fillStyle = "#808090";
      ctx.font = "16px monospace";
      ctx.textAlign = "center";
      ctx.fillText("Grid tile hops for reCAPTCHA solver", canvas.width / 2, canvas.height / 2 - 10);
      ctx.font = "12px monospace";
      ctx.fillText("Press Space to begin (click 3 highlighted tiles)", canvas.width / 2, canvas.height / 2 + 16);
    } else {
      drawGrid();
    }
  } else if (mode === "browse") {
    drawBrowsePage();
  }
  // DET and CLS modes use DOM panels, not canvas
}

// ── Drag puzzle rendering ─────────────────────────────────────────────
function drawDragPuzzle() {
  if (!dragPuzzle) randomizeDragPuzzle();
  const p = dragPuzzle;

  // Background "image" area — random colored shapes to simulate a puzzle background
  ctx.fillStyle = `hsl(${p.hue}, 25%, 20%)`;
  ctx.fillRect(p.bgX, p.bgY, p.bgW, p.bgH);
  ctx.strokeStyle = `hsl(${p.hue}, 30%, 30%)`;
  ctx.lineWidth = 1;
  ctx.strokeRect(p.bgX, p.bgY, p.bgW, p.bgH);

  // Draw some random shapes in the background for visual texture
  const rng = mulberry32(p.hue * 137 + p.trackW);
  for (let i = 0; i < 12; i++) {
    const sx = p.bgX + rng() * p.bgW;
    const sy = p.bgY + rng() * p.bgH;
    const sr = 8 + rng() * 25;
    const sh = (p.hue + Math.floor(rng() * 120)) % 360;
    ctx.fillStyle = `hsla(${sh}, 40%, 35%, 0.5)`;
    ctx.beginPath();
    if (rng() > 0.5) {
      ctx.arc(sx, sy, sr, 0, Math.PI * 2);
    } else {
      ctx.rect(sx - sr / 2, sy - sr / 2, sr, sr);
    }
    ctx.fill();
  }

  // Notch cutout (darker area where piece should go)
  ctx.fillStyle = `hsla(0, 0%, 0%, 0.4)`;
  ctx.fillRect(p.notchX, p.notchY, p.pieceW, p.pieceH);
  ctx.strokeStyle = `hsla(0, 0%, 100%, 0.15)`;
  ctx.lineWidth = 1;
  ctx.strokeRect(p.notchX, p.notchY, p.pieceW, p.pieceH);

  // Puzzle piece — moves with drag, starts at left side
  const z = getDragZone();
  let pieceDrawX = p.bgX; // default: left side
  let handleDrawX = p.trackX; // default: left edge
  if (p._currentX !== undefined) {
    // Offset from start position
    const dragOffset = p._currentX - z.start.x;
    pieceDrawX = p.bgX + dragOffset;
    handleDrawX = p.trackX + dragOffset;
  }

  // Draw piece
  ctx.fillStyle = `hsl(${p.hue}, 30%, 40%)`;
  ctx.fillRect(pieceDrawX, p.notchY, p.pieceW, p.pieceH);
  ctx.strokeStyle = `hsl(${p.hue}, 40%, 55%)`;
  ctx.lineWidth = 2;
  ctx.strokeRect(pieceDrawX, p.notchY, p.pieceW, p.pieceH);
  // Inner detail on piece
  ctx.fillStyle = `hsl(${p.hue}, 35%, 50%)`;
  const inset = Math.floor(p.pieceW * 0.2);
  ctx.fillRect(pieceDrawX + inset, p.notchY + inset, p.pieceW - inset * 2, p.pieceH - inset * 2);

  // Slider track
  ctx.fillStyle = "#dee3eb";
  ctx.fillRect(p.trackX, p.trackY, p.trackW, p.trackH);
  ctx.strokeStyle = "#bcc3d0";
  ctx.lineWidth = 1;
  ctx.strokeRect(p.trackX, p.trackY, p.trackW, p.trackH);

  // Track label
  ctx.fillStyle = "#8090a0";
  ctx.font = "11px sans-serif";
  ctx.textAlign = "center";
  ctx.fillText(`${p.trackW}px track`, p.trackX + p.trackW / 2, p.trackY + p.trackH + 16);

  // Slider handle — moves with drag
  const handleW = p.trackH + 6;
  const handleH = p.trackH - 4;
  const hx = handleDrawX - 1;
  const hy = p.trackY + 2;
  ctx.fillStyle = "#5682fd";
  ctx.beginPath();
  ctx.roundRect(hx, hy, handleW, handleH, 4);
  ctx.fill();

  // Arrow on handle
  ctx.fillStyle = "#fff";
  ctx.font = "16px sans-serif";
  ctx.textAlign = "center";
  ctx.fillText("\u25B6", hx + handleW / 2, p.trackY + p.trackH / 2 + 6);

  // Track info
  ctx.fillStyle = "#606080";
  ctx.font = "10px monospace";
  ctx.textAlign = "left";
  const dragDist = Math.round(z.end.x - z.start.x);
  ctx.fillText(`${p.pieceW}px piece, ${dragDist}px drag`, p.bgX + p.bgW + 8, p.notchY + p.pieceH / 2 + 4);
}

// Simple seedable PRNG for deterministic puzzle shapes
function mulberry32(seed) {
  let s = seed | 0;
  return function() {
    s = (s + 0x6D2B79F5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
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

// ── Fail mode rendering ─────────────────────────────────────────────────
// Google reCAPTCHA grid layout (from live CSS inspection):
//   3x3: table 390x390, td 130x130, 2px td padding, img 378x378 (from 450 natural)
//   4x4: table 388x388, td  97x97,  1px td padding, img 380x380 (from 450 natural)
// Backgrounds are transparent; the iframe's white bg bleeds through the padding gaps.
// We replicate this by drawing each tile individually with white gaps between them.
const FAIL_GRID_SPECS = {
  3: { tableSize: 390, tdSize: 130, padding: 2, imgSize: 378 },
  4: { tableSize: 388, tdSize:  97, padding: 1, imgSize: 380 },
};

// ── DET DOM rendering ──────────────────────────────────────────────────

function renderDetPanel() {
  const entry = detEntries[detIndex];
  if (!entry) {
    detGridEl.innerHTML = "";
    detOutcomeEl.textContent = "";
    detInstructionEl.textContent = "";
    detProgressEl.textContent = detTotalCount > 0
      ? `All ${detTotalCount} grids annotated!`
      : "No grids to annotate";
    return;
  }

  // Outcome
  const outcome = entry.outcome || "";
  detOutcomeEl.textContent = outcome;
  detOutcomeEl.className = "det-outcome " +
    (outcome.startsWith("solved") ? "solved" : "failed");

  // Instruction
  detInstructionEl.textContent =
    `Select all squares with ${entry.keyword || "?"}`;

  // Build grid cells
  const gs = detGridSize;
  const spec = FAIL_GRID_SPECS[gs];
  const contentSize = spec.tdSize - 2 * spec.padding;
  const imgUrl = `/api/det/image/${entry.file}`;

  detGridEl.innerHTML = "";
  detGridEl.style.gridTemplateColumns = `repeat(${gs}, ${contentSize}px)`;
  detGridEl.style.gap = `${spec.padding * 2}px`;
  detGridEl.style.padding = `${spec.padding}px`;

  for (let i = 0; i < gs * gs; i++) {
    const row = Math.floor(i / gs);
    const col = i % gs;
    const cell = document.createElement("div");
    cell.className = "det-cell";
    cell.dataset.idx = i;
    cell.style.width = `${contentSize}px`;
    cell.style.height = `${contentSize}px`;
    cell.style.backgroundImage = `url(${imgUrl})`;
    cell.style.backgroundSize =
      `${contentSize * gs}px ${contentSize * gs}px`;
    cell.style.backgroundPosition =
      `-${col * contentSize}px -${row * contentSize}px`;

    const overlay = document.createElement("div");
    overlay.className = "det-cell-overlay";
    cell.appendChild(overlay);

    cell.addEventListener("click", () => {
      if (detUserPicks.has(i)) detUserPicks.delete(i);
      else detUserPicks.add(i);
      updateDetCellStates();
    });
    detGridEl.appendChild(cell);
  }

  updateDetCellStates();

  // Progress
  const remaining = detEntries.length - detIndex;
  detProgressEl.textContent =
    `${detAnnotatedCount}/${detTotalCount} annotated \u00b7 ${remaining} remaining`;
}

function updateDetCellStates() {
  const cells = detGridEl.querySelectorAll(".det-cell");
  cells.forEach(cell => {
    const idx = parseInt(cell.dataset.idx);
    const isModel = detModelPicks.includes(idx);
    const isUser = detUserPicks.has(idx);
    cell.classList.toggle("model-pick", isModel);
    cell.classList.toggle("user-pick", isUser);
    const overlay = cell.querySelector(".det-cell-overlay");
    if (isUser && isModel) {
      overlay.innerHTML =
        '<span class="check">\u2713</span><span class="badge">M+U</span>';
    } else if (isModel) {
      overlay.innerHTML = '<span class="badge">M</span>';
    } else if (isUser) {
      overlay.innerHTML = '<span class="check">\u2713</span>';
    } else {
      overlay.innerHTML = "";
    }
  });
}

function loadDetEntry() {
  const entry = detEntries[detIndex];
  if (!entry) {
    renderDetPanel();
    return;
  }

  detGridSize = entry.grid_type === "4x4" ? 4 : 3;
  detModelPicks = entry.cells_selected || [];
  detUserPicks = new Set();
  renderDetPanel();
}

function updateDetStat() {
  const el = document.getElementById("stat-det");
  const done = detAnnotatedCount >= detTotalCount && detTotalCount > 0;
  const valueEl = el.querySelector(".stat-value");
  if (valueEl) valueEl.textContent = `${detAnnotatedCount}/${detTotalCount}`;
  const iconEl = el.querySelector(".stat-icon");
  if (iconEl) iconEl.textContent = done ? "\u2705" : "\uD83D\uDD0D";
  const isActive = el.classList.contains("active-tab");
  el.className = "stat " + (done ? "complete" : "incomplete")
    + (isActive ? " active-tab" : "")
    + (!detHasEntries ? " disabled" : "");
}

async function loadDetEntries() {
  const resp = await fetch("/api/det/grids");
  const data = await resp.json();
  const unannotated = [];
  let annotated = 0;

  for (const grid of data.grids || []) {
    if (grid.annotated) { annotated++; continue; }
    unannotated.push(grid);
  }

  detEntries = unannotated;
  detAnnotatedCount = annotated;
  detTotalCount = data.total || 0;
  detIndex = 0;
  detHasEntries = detTotalCount > 0;

  // Enable/disable det tab and stat
  const detTab = document.querySelector('.tab[data-mode="det"]');
  if (detHasEntries) {
    detTab.disabled = false;
    detTab.classList.remove("disabled");
  } else {
    detTab.disabled = true;
    detTab.classList.add("disabled");
  }
  updateDetStat();

  if (mode === "det") {
    loadDetEntry();
  }
}

async function detAccept() {
  const entry = detEntries[detIndex];
  if (!entry) return;
  if (detUserPicks.size === 0) {
    if (!confirm("No cells selected. Save as 'no matching objects'?")) return;
  }
  const resp = await fetch("/api/det/annotate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      file: entry.file,
      keyword: entry.keyword,
      grid_type: entry.grid_type,
      ground_truth: [...detUserPicks].sort((a, b) => a - b),
    }),
  });
  if (!resp.ok) {
    showStatus("Annotation failed", "error");
    return;
  }
  detAnnotatedCount++;
  showStatus(`Annotated ${entry.file}`, "success");
  detAdvance();
}

function detSkip() {
  detAdvance();
}

function detAdvance() {
  detIndex++;
  updateDetStat();
  if (detIndex >= detEntries.length) {
    renderDetPanel();
    return;
  }
  loadDetEntry();
}

// ── CLS DOM rendering ──────────────────────────────────────────────────

function renderClsPanel() {
  const tile = clsFiltered[clsIndex];
  if (!tile) {
    clsTileImg.parentElement.style.display = "none";
    clsKeywordEl.textContent = "";
    clsConfWrap.innerHTML = "";
    clsButtonsWrap.innerHTML = "";
    clsProgressEl.textContent = clsTotalCount > 0
      ? `All ${clsTotalCount} tiles reviewed!`
      : "No tiles to review";
    return;
  }

  // Tile image
  clsTileImg.parentElement.style.display = "";
  clsTileImg.src = `/api/cls/image/${tile.file || ""}`;
  clsTileImg.onerror = () => clsAdvance();

  // Model info: keyword, predicted class, selected status
  const parts = [];
  if (tile.keyword) parts.push(`keyword: "${tile.keyword}"`);
  const targetName = tile.target_class != null ? CLS_NAMES[tile.target_class] || `#${tile.target_class}` : "?";
  parts.push(`target: ${targetName}`);
  parts.push(`predicted: ${tile.predicted_class || "?"}`);
  parts.push(tile.is_selected ? "selected: YES" : "selected: no");
  clsKeywordEl.textContent = parts.join("  \u00b7  ");

  // Confidence bars (all top3)
  const top3 = tile.top3 || [];
  clsConfWrap.innerHTML = "";
  for (let i = 0; i < top3.length; i++) {
    const [name, score] = top3[i];
    const row = document.createElement("div");
    row.className = "cls-conf-row";
    const pct = (score * 100).toFixed(1);
    row.innerHTML =
      `<span class="cls-conf-label${i === 0 ? " top" : ""}">${name}</span>` +
      `<div class="cls-conf-bar"><div class="cls-conf-fill${i === 0 ? " top" : ""}" style="width:${pct}%"></div></div>` +
      `<span class="cls-conf-score">${pct}%</span>`;
    clsConfWrap.appendChild(row);
  }

  // Class buttons
  clsButtonsWrap.innerHTML = "";
  for (let i = 0; i < CLS_NAMES.length; i++) {
    const btn = document.createElement("button");
    const isPredicted = tile.predicted_class === CLS_NAMES[i];
    const isSelected = clsSelectedLabel === CLS_NAMES[i];
    btn.className = "cls-btn" +
      (isPredicted ? " predicted" : "") +
      (isSelected ? " selected" : "");
    btn.textContent = CLS_NAMES[i];
    btn.addEventListener("click", () => {
      clsSelectedLabel = CLS_NAMES[i];
      updateClsButtonStates();
    });
    clsButtonsWrap.appendChild(btn);
  }

  // Progress
  const remaining = clsFiltered.length - clsIndex;
  clsProgressEl.textContent =
    `${clsReviewedCount}/${clsTotalCount} reviewed \u00b7 ${remaining} remaining`;
}

function updateClsButtonStates() {
  const tile = clsFiltered[clsIndex];
  if (!tile) return;
  const btns = clsButtonsWrap.querySelectorAll(".cls-btn");
  btns.forEach((btn, i) => {
    const isPredicted = tile.predicted_class === CLS_NAMES[i];
    const isSelected = clsSelectedLabel === CLS_NAMES[i];
    btn.className = "cls-btn" +
      (isPredicted ? " predicted" : "") +
      (isSelected ? " selected" : "");
  });
}

function loadClsTile() {
  const tile = clsFiltered[clsIndex];
  if (!tile) {
    clsSelectedLabel = null;
    renderClsPanel();
    return;
  }

  clsSelectedLabel = tile.predicted_class;
  renderClsPanel();
}

function updateClsStat() {
  const el = document.getElementById("stat-cls");
  const done = clsReviewedCount >= clsTotalCount && clsTotalCount > 0;
  const valueEl = el.querySelector(".stat-value");
  if (valueEl) valueEl.textContent = `${clsReviewedCount}/${clsTotalCount}`;
  const iconEl = el.querySelector(".stat-icon");
  if (iconEl) iconEl.textContent = done ? "\u2705" : "\uD83C\uDFF7\uFE0F";
  const isActive = el.classList.contains("active-tab");
  el.className = "stat " + (done ? "complete" : "incomplete")
    + (isActive ? " active-tab" : "")
    + (!clsHasTiles ? " disabled" : "");
}

function clsApplyFilter() {
  if (clsFilter === "all") {
    clsFiltered = clsTiles.filter(t => !t.reviewed && t.exists);
  } else if (clsFilter === "low_confidence") {
    clsFiltered = clsTiles.filter(t => !t.reviewed && t.exists && t.confidence < 0.5);
  } else {
    // "unreviewed" (default)
    clsFiltered = clsTiles.filter(t => !t.reviewed && t.exists);
  }
}

async function loadClsTiles() {
  const resp = await fetch("/api/cls/tiles");
  const data = await resp.json();

  clsTiles = data.tiles || [];
  clsReviewedCount = data.reviewed || 0;
  clsTotalCount = data.total || 0;
  clsHasTiles = data.has_tiles || false;

  clsApplyFilter();
  clsIndex = 0;

  // Enable/disable CLS tab
  const clsTab = document.querySelector('.tab[data-mode="cls"]');
  if (clsHasTiles) {
    clsTab.disabled = false;
    clsTab.classList.remove("disabled");
  } else {
    clsTab.disabled = true;
    clsTab.classList.add("disabled");
  }
  updateClsStat();

  if (mode === "cls") {
    loadClsTile();
  }
}

async function clsAccept() {
  const tile = clsFiltered[clsIndex];
  if (!tile || !clsSelectedLabel) return;
  const label = clsSelectedLabel;
  const filename = tile.file.split("/").pop();
  const resp = await fetch("/api/cls/label", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ file: tile.file, label }),
  });
  if (!resp.ok) return;
  tile.reviewed = true;
  clsReviewedCount++;
  const reviewedPath = `${label}/${filename}`;
  clsHistory.unshift({
    tile,
    label,
    imgSrc: `/api/cls/image/${reviewedPath}`,
    reviewedPath,
    originalPath: tile.file,
  });
  if (clsHistory.length > 20) clsHistory.pop();
  renderClsHistory();
  showStatus(`Labeled ${label}`, "success");
  clsAdvance();
}

async function clsUndo(entry) {
  const resp = await fetch("/api/cls/undo", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      reviewed_path: entry.reviewedPath,
      original_path: entry.originalPath,
    }),
  });
  if (!resp.ok) {
    showStatus("Undo failed", "error");
    return;
  }
  entry.tile.reviewed = false;
  clsReviewedCount--;
  clsHistory = clsHistory.filter(h => h !== entry);
  renderClsHistory();
  // Jump back to this tile
  const idx = clsFiltered.indexOf(entry.tile);
  if (idx >= 0) {
    clsIndex = idx;
    clsSelectedLabel = entry.tile.predicted_class;
    renderClsPanel();
  }
  updateClsStat();
  showStatus("Undone - relabel this tile", "success");
}

function renderClsHistory() {
  if (!clsHistoryEl) return;
  clsHistoryEl.innerHTML = "";
  for (const entry of clsHistory) {
    const item = document.createElement("div");
    item.className = "cls-history-item";
    item.title = `${entry.label} - click to undo`;
    item.innerHTML =
      `<img src="${entry.imgSrc}" alt="${entry.label}" />` +
      `<div class="cls-history-label">${entry.label}</div>`;
    item.addEventListener("click", () => clsUndo(entry));
    clsHistoryEl.appendChild(item);
  }
}

async function clsSkip() {
  clsAdvance();
}

async function clsDelete() {
  const tile = clsFiltered[clsIndex];
  if (!tile) return;
  await fetch("/api/cls/delete", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ file: tile.file }),
  });
  tile.exists = false;
  showStatus("Deleted tile", "success");
  clsAdvance();
}

function clsAdvance() {
  clsIndex++;
  updateClsStat();
  if (clsIndex >= clsFiltered.length) {
    renderClsPanel();
    return;
  }
  loadClsTile();
}

// ── Mode tabs ──────────────────────────────────────────────────────────
function switchMode(newMode) {
  if (state !== "ready") return;
  // Block switching to fail if no entries
  if (newMode === "det" && !detHasEntries) return;
  if (newMode === "cls" && !clsHasTiles) return;
  mode = newMode;
  location.hash = mode;
  tabs.forEach(t => t.classList.toggle("active", t.dataset.mode === mode));
  directionSelect.classList.toggle("hidden", mode !== "path");
  directionInfo.classList.toggle("hidden", mode !== "path");
  viewportSelect.classList.toggle("hidden", mode === "det" || mode === "cls");
  if (mode === "path") updateDirectionInfo();
  syncActiveTab();
  // Toggle canvas vs tool panels
  const isToolMode = mode === "det" || mode === "cls";
  canvas.classList.toggle("hidden", isToolMode);
  detPanel.classList.toggle("hidden", mode !== "det");
  clsPanel.classList.toggle("hidden", mode !== "cls");
  controlsRight.classList.toggle("hidden", isToolMode);
  recordingsPanel.classList.toggle("hidden", isToolMode);

  if (mode === "det") {
    if (detTotalCount > 0) {
      detIndex = 0;
      loadDetEntry();
    } else {
      loadDetEntries();
    }
  } else if (mode === "cls") {
    if (clsTotalCount > 0) {
      clsIndex = 0;
      loadClsTile();
    } else {
      loadClsTiles();
    }
  } else {
    resizeCanvas();
  }
}

tabs.forEach(tab => {
  tab.addEventListener("click", () => switchMode(tab.dataset.mode));
});

// Clicking a stat badge also switches to that mode
document.querySelectorAll(".stat[data-mode]").forEach(stat => {
  stat.style.cursor = "pointer";
  stat.addEventListener("click", () => switchMode(stat.dataset.mode));
});

// Drag recording state: approach → hover → mousedown → drag
let dragApproached = false; // cursor entered handle zone, pre-drag recording started
let dragStarted = false;    // mousedown happened, actively dragging
let dragMouseDown = false;  // mouse button currently held
let dragMousedownT = null;  // time of mousedown relative to recording start

// Browse mode: scroll events captured separately
let browseScrollEvents = [];
// Browse mode: randomized content length (sections) per recording
let browsePageSections = 6; // default, randomized on each start
let browseScrollOffset = 0; // current scroll position in the fake page

// Grid mode: 3x3 tile grid for short-hop recordings
let gridTargets = [];    // 3 random tile indices (0-8)
let gridClicks = [];     // [{t, x, y, tile}, ...] click events
let gridPhase = 0;       // 0=waiting for grid hover, 1/2/3=waiting for nth click, 4=settling
let gridStarted = false; // true once cursor entered first target tile
let gridReady = false;   // true after 500ms dwell in first tile

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
  for (const cat of ["idles", "paths", "holds", "drags", "slide_drags", "grids", "browses"]) {
    const el = document.getElementById(`stat-${cat}`);
    const info = data[cat];
    if (!el || !info) continue;
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
  const modeToStat = { idle: "stat-idles", path: "stat-paths", hold: "stat-holds", drag: "stat-drags", slide_drag: "stat-slide_drags", grid: "stat-grids", browse: "stat-browses", det: "stat-det", cls: "stat-cls" };
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
  for (const cat of ["idles", "paths", "holds", "drags", "slide_drags", "grids", "browses"]) total += (data[cat]?.files?.length || 0);
  if (emptyEl) emptyEl.classList.toggle("hidden", total > 0);
  for (const cat of ["idles", "paths", "holds", "drags", "slide_drags", "grids", "browses"]) {
    if (!data[cat]) continue;
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
    // Randomize puzzle for each recording — approach handle, pause, then drag
    randomizeDragPuzzle();
    delete dragPuzzle._currentX;
    state = "recording";
    dragApproached = false;
    dragStarted = false;
    dragMouseDown = false;
    dragMousedownT = null;
    updateButtons();
    drawGuides();
  } else if (mode === "slide_drag") {
    // Slide to verify — same state machine as drag but full-width target
    randomizeSlideTrack();
    delete slideTrack._currentX;
    state = "recording";
    dragApproached = false;
    dragStarted = false;
    dragMouseDown = false;
    dragMousedownT = null;
    updateButtons();
    drawGuides();
  } else if (mode === "grid") {
    randomizeGrid();
    gridClicks = [];
    gridPhase = 1;
    state = "recording";
    startTime = performance.now();
    points = [];
    updateButtons();
    drawGuides();
    // Timeout after 20s
    recordingTimer = setTimeout(() => {
      showStatus("Grid recording timed out (20s)", "error");
      discardRecording();
    }, 20000);
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
    if (!dragApproached) {
      // Check if cursor entered handle zone — starts pre-drag recording
      const z = getDragZone();
      const dx2 = p.x - z.start.x, dy2 = p.y - z.start.y;
      if (Math.sqrt(dx2 * dx2 + dy2 * dy2) < ZONE_R + 10) {
        dragApproached = true;
        startTime = performance.now();
        points = [{ t: 0, x: p.x, y: p.y }];
        drawGuides();
        // Timeout after 10s
        recordingTimer = setTimeout(() => {
          showStatus("Drag recording timed out (10s)", "error");
          discardRecording();
        }, 10000);
      }
    } else if (!dragStarted) {
      // Pre-drag hover phase — capture natural pause near handle
      points.push({ t: (performance.now() - startTime) / 1000, x: p.x, y: p.y });
      // Subtle hover trail
      if (points.length >= 2) {
        const prev = points[points.length - 2];
        ctx.strokeStyle = "#4ecca340";
        ctx.lineWidth = 1;
        ctx.lineCap = "round";
        ctx.beginPath();
        ctx.moveTo(prev.x, prev.y);
        ctx.lineTo(p.x, p.y);
        ctx.stroke();
      }
    } else if (dragMouseDown) {
      // Active drag phase
      points.push({ t: (performance.now() - startTime) / 1000, x: p.x, y: p.y });
      // Redraw entire puzzle with piece at current drag position
      dragPuzzle._currentX = p.x;
      clear();
      drawDragPuzzle();
      // Redraw full trail on top
      if (points.length >= 2) {
        drawPath(points, "#e94560", 2);
      }
      // Instruction text
      ctx.font = "14px monospace";
      ctx.textAlign = "center";
      ctx.fillStyle = "#e94560";
      ctx.fillText("Drag to the notch \u2014 release when placed!", canvas.width / 2, canvas.height - 20);
    }
  } else if (mode === "slide_drag") {
    if (!dragApproached) {
      // Check if cursor entered handle zone
      const z = getSlideZone();
      const dx2 = p.x - z.start.x, dy2 = p.y - z.start.y;
      if (Math.sqrt(dx2 * dx2 + dy2 * dy2) < ZONE_R + 10) {
        dragApproached = true;
        startTime = performance.now();
        points = [{ t: 0, x: p.x, y: p.y }];
        drawGuides();
        recordingTimer = setTimeout(() => {
          showStatus("Slide recording timed out (10s)", "error");
          discardRecording();
        }, 10000);
      }
    } else if (!dragStarted) {
      // Pre-drag hover phase
      points.push({ t: (performance.now() - startTime) / 1000, x: p.x, y: p.y });
      if (points.length >= 2) {
        const prev = points[points.length - 2];
        ctx.strokeStyle = "#4ecca340";
        ctx.lineWidth = 1;
        ctx.lineCap = "round";
        ctx.beginPath();
        ctx.moveTo(prev.x, prev.y);
        ctx.lineTo(p.x, p.y);
        ctx.stroke();
      }
    } else if (dragMouseDown) {
      // Active slide phase
      points.push({ t: (performance.now() - startTime) / 1000, x: p.x, y: p.y });
      slideTrack._currentX = p.x;
      clear();
      drawSlideTrack();
      if (points.length >= 2) {
        drawPath(points, "#e94560", 2);
      }
      ctx.font = "14px monospace";
      ctx.textAlign = "center";
      ctx.fillStyle = "#e94560";
      ctx.fillText("Slide all the way right \u2014 release at the end!", canvas.width / 2, canvas.height - 20);
    }
  } else if (mode === "grid") {
    if (!gridStarted) {
      // Wait for cursor to enter the first target tile, then 500ms dwell
      const firstTile = gridTargets[0];
      const b = getTileBounds(firstTile);
      if (p.x >= b.x && p.x <= b.x + b.w && p.y >= b.y && p.y <= b.y + b.h) {
        gridStarted = true;
        gridReady = false;
        startTime = performance.now();
        points = [{ t: 0, x: p.x, y: p.y }];
        drawGuides();
        setTimeout(() => {
          if (!gridStarted) return;
          gridReady = true;
          drawGuides();
        }, 500);
      }
    } else {
      points.push({ t: (performance.now() - startTime) / 1000, x: p.x, y: p.y });
      // Draw trail
      if (points.length >= 2) {
        const prev = points[points.length - 2];
        ctx.strokeStyle = "#4ecca3";
        ctx.lineWidth = 2;
        ctx.lineCap = "round";
        ctx.beginPath();
        ctx.moveTo(prev.x, prev.y);
        ctx.lineTo(p.x, p.y);
        ctx.stroke();
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
  if (state !== "recording") return;

  // Drag/slide_drag mode: mousedown transitions from pre-drag hover to active drag
  if ((mode === "drag" || mode === "slide_drag") && dragApproached && !dragStarted) {
    const p = canvasCoords(e);
    const z = mode === "slide_drag" ? getSlideZone() : getDragZone();
    const dx = p.x - z.start.x, dy = p.y - z.start.y;
    // Must click near the handle
    if (Math.sqrt(dx * dx + dy * dy) < ZONE_R + 10) {
      dragStarted = true;
      dragMouseDown = true;
      dragMousedownT = (performance.now() - startTime) / 1000;
      points.push({ t: dragMousedownT, x: p.x, y: p.y });
      drawGuides();
    }
    return;
  }

  if (mode === "grid" && gridStarted && gridReady && gridPhase >= 1 && gridPhase <= 3) {
    const p = canvasCoords(e);
    const tile = hitTestTile(p.x, p.y);
    const expectedTile = gridTargets[gridPhase - 1];
    if (tile === expectedTile) {
      const t = (performance.now() - startTime) / 1000;
      gridClicks.push({ t, x: p.x, y: p.y, tile });
      points.push({ t, x: p.x, y: p.y });

      if (gridPhase >= 3) {
        // All 3 tiles clicked - keep recording 500ms for post-click dwell
        gridPhase = 4;
        setTimeout(() => {
          clearTimeout(recordingTimer);
          finishRecording();
        }, 500);
      } else {
        gridPhase++;
      }
      // Redraw grid to show clicked state
      clear();
      drawGrid();
      // Redraw trail
      if (points.length >= 2) {
        drawPath(points, "#4ecca3", 2);
      }
    }
    return;
  }

  if (mode !== "hold") return;
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

canvas.addEventListener("mouseup", (e) => {
  if (holdActive) endHold();

  // Drag/slide_drag mode: mouseup finishes the recording
  if ((mode === "drag" || mode === "slide_drag") && dragStarted && dragMouseDown) {
    dragMouseDown = false;
    // Record the final release point
    const p = canvasCoords(e);
    points.push({ t: (performance.now() - startTime) / 1000, x: p.x, y: p.y });
    if (points.length < 5) {
      showStatus("Drag too short (need 5+ events)", "error");
      discardRecording();
      return;
    }
    clearTimeout(recordingTimer);
    finishRecording();
  }
});

canvas.addEventListener("mouseleave", () => {
  if (holdActive) endHold();
  if ((mode === "drag" || mode === "slide_drag") && dragStarted && dragMouseDown) {
    dragMouseDown = false;
    showStatus("Mouse left canvas during drag", "error");
    discardRecording();
  }
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
    drawDragPuzzle();
    drawPath(points, "#e94560", 2);
    ctx.fillStyle = "#808090";
    ctx.font = "14px monospace";
    ctx.textAlign = "center";
    const z = getDragZone();
    const dragDist = Math.round(z.end.x - z.start.x);
    ctx.fillText(`${points.length} events, ${points[points.length - 1].t.toFixed(1)}s, ${dragDist}px target drag`, canvas.width / 2, canvas.height - 20);
  } else if (mode === "slide_drag") {
    drawSlideTrack();
    drawPath(points, "#e94560", 2);
    ctx.fillStyle = "#808090";
    ctx.font = "14px monospace";
    ctx.textAlign = "center";
    const z = getSlideZone();
    const slideDist = Math.round(z.end.x - z.start.x);
    ctx.fillText(`${points.length} events, ${points[points.length - 1].t.toFixed(1)}s, ${slideDist}px slide`, canvas.width / 2, canvas.height - 20);
  } else if (mode === "grid") {
    drawGrid();
    drawPath(points, "#4ecca3", 2);
    // Mark click points
    for (let i = 0; i < gridClicks.length; i++) {
      const c = gridClicks[i];
      ctx.beginPath();
      ctx.arc(c.x, c.y, 6, 0, Math.PI * 2);
      ctx.fillStyle = "#e94560";
      ctx.fill();
      ctx.fillStyle = "#fff";
      ctx.font = "bold 10px monospace";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(String(i + 1), c.x, c.y);
    }
    ctx.fillStyle = "#808090";
    ctx.font = "14px monospace";
    ctx.textAlign = "center";
    ctx.textBaseline = "alphabetic";
    ctx.fillText(
      `${points.length} events, ${points[points.length - 1].t.toFixed(1)}s, 3 segments`,
      canvas.width / 2, canvas.height - 20
    );
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
    // Use mousedown point as drag origin (pre-drag hover is relative to this)
    let mdIdx = 0;
    if (dragMousedownT !== null) {
      mdIdx = points.findIndex(p => p.t >= dragMousedownT);
      if (mdIdx < 0) mdIdx = 0;
    }
    const sx = points[mdIdx].x, sy = points[mdIdx].y;
    const ex = z.end.x, ey = z.end.y;
    const dxRange = ex - sx;

    if (Math.abs(dxRange) < 1) {
      showStatus("Drag too short — discarding", "error");
      discardRecording();
      return;
    }

    // ry normalized relative to horizontal displacement (captures wobble)
    // Pre-drag hover events will have rx ≈ 0 (small jitter around handle)
    const rows = points.map(p => [
      parseFloat(p.t.toFixed(3)),
      parseFloat(((p.x - sx) / dxRange).toFixed(4)),
      parseFloat(((p.y - sy) / dxRange).toFixed(4)),
    ]);
    const meta = {
      viewport: vpStr,
      start: `${Math.round(sx)},${Math.round(sy)}`,
      end: `${Math.round(ex)},${Math.round(ey)}`,
    };
    if (dragMousedownT !== null) {
      meta.mousedown_t = dragMousedownT.toFixed(3);
    }
    payload = {
      type: "drags",
      columns: ["t", "rx", "ry"],
      metadata: meta,
      rows,
    };
  } else if (mode === "slide_drag") {
    const z = getSlideZone();
    let mdIdx = 0;
    if (dragMousedownT !== null) {
      mdIdx = points.findIndex(p => p.t >= dragMousedownT);
      if (mdIdx < 0) mdIdx = 0;
    }
    const sx = points[mdIdx].x, sy = points[mdIdx].y;
    const ex = z.end.x;
    const dxRange = ex - sx;

    if (Math.abs(dxRange) < 1) {
      showStatus("Slide too short — discarding", "error");
      discardRecording();
      return;
    }

    // Normalize same as drag: rx relative to total slide distance, ry relative to |dxRange|
    const rows = points.map(p => [
      parseFloat(p.t.toFixed(3)),
      parseFloat(((p.x - sx) / dxRange).toFixed(4)),
      parseFloat(((p.y - sy) / dxRange).toFixed(4)),
    ]);
    const meta = {
      viewport: vpStr,
      start: `${Math.round(sx)},${Math.round(sy)}`,
      end: `${Math.round(ex)},${Math.round(z.end.y)}`,
    };
    if (dragMousedownT !== null) {
      meta.mousedown_t = dragMousedownT.toFixed(3);
    }
    payload = {
      type: "slide_drags",
      columns: ["t", "rx", "ry"],
      metadata: meta,
      rows,
    };
  } else if (mode === "grid") {
    // Split points into 3 segments at click boundaries and save each separately
    if (gridClicks.length !== 3) {
      showStatus("Need exactly 3 clicks", "error");
      discardRecording();
      return;
    }

    const segments = [];
    // Segment boundaries: [0..click1], [click1..click2], [click2..end]
    // Last segment includes post-click dwell (500ms settle after 3rd click)
    const clickTimes = gridClicks.map(c => c.t);
    const lastT = points[points.length - 1].t;
    const boundaries = [0, clickTimes[0], clickTimes[1], lastT];
    for (let s = 0; s < 3; s++) {
      const tStart = boundaries[s];
      const tEnd = boundaries[s + 1];
      const seg = points.filter(p => p.t >= tStart - 0.001 && p.t <= tEnd + 0.001);
      if (seg.length < 2) {
        showStatus(`Segment ${s + 1} too short`, "error");
        discardRecording();
        return;
      }
      segments.push(seg);
    }

    // Save each segment as a separate recording
    let savedCount = 0;
    for (let s = 0; s < 3; s++) {
      const seg = segments[s];
      const sx = seg[0].x, sy = seg[0].y;
      const ex = seg[seg.length - 1].x, ey = seg[seg.length - 1].y;
      const dxRange = ex - sx, dyRange = ey - sy;
      const dist = Math.sqrt(dxRange * dxRange + dyRange * dyRange);

      // Normalize: rx/ry relative to the distance
      const normFactor = dist > 1 ? dist : 1;
      const tOffset = seg[0].t;
      const rows = seg.map(p => [
        parseFloat((p.t - tOffset).toFixed(3)),
        parseFloat(((p.x - sx) / normFactor).toFixed(4)),
        parseFloat(((p.y - sy) / normFactor).toFixed(4)),
      ]);

      const segPayload = {
        type: "grids",
        columns: ["t", "rx", "ry"],
        metadata: {
          viewport: vpStr,
          start: `${Math.round(sx)},${Math.round(sy)}`,
          end: `${Math.round(ex)},${Math.round(ey)}`,
        },
        direction: "grid_hop",
        rows,
      };

      const resp = await fetch("/api/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(segPayload),
      });
      const result = await resp.json();
      if (resp.ok) savedCount++;
    }

    showStatus(`Saved ${savedCount} grid hop segments`, "success");
    refreshRecordings();
    resetState();
    return;
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
  dragApproached = false;
  dragStarted = false;
  dragReady = false;
  dragMouseDown = false;
  dragMousedownT = null;
  browseScrollEvents = [];
  gridClicks = [];
  gridPhase = 0;
  gridTargets = [];
  gridStarted = false;
  gridReady = false;
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
  dragApproached = false;
  dragStarted = false;
  dragReady = false;
  dragMouseDown = false;
  dragMousedownT = null;
  browseScrollEvents = [];
  gridClicks = [];
  gridPhase = 0;
  gridTargets = [];
  gridStarted = false;
  gridReady = false;
  if (settleTimer) { clearTimeout(settleTimer); settleTimer = null; }
  holdActive = false;
  holdStartPos = null;
  updateButtons();
  drawGuides();
}

// ── Button state ───────────────────────────────────────────────────────
function updateButtons() {
  const isToolMode = mode === "det" || mode === "cls";
  const isReady = state === "ready";
  const isPreview = state === "preview";
  const isRecording = state === "recording" || state === "countdown";

  btnStart.classList.toggle("hidden", isToolMode || !isReady);
  btnAccept.classList.toggle("hidden", !isPreview);
  btnDiscard.classList.toggle("hidden", !isPreview && !isRecording);

  tabs.forEach(t => {
    if (t.dataset.mode === "det") {
      t.disabled = !detHasEntries;
    } else if (t.dataset.mode === "cls") {
      t.disabled = !clsHasTiles;
    } else {
      t.disabled = !isReady;
    }
  });
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
    if (mode !== "det" && mode !== "cls" && state === "ready") startRecording();
  } else if (e.code === "Enter") {
    e.preventDefault();
    if (mode === "det") detAccept();
    else if (mode === "cls") clsAccept();
    else if (state === "preview") acceptRecording();
  } else if (e.code === "Escape") {
    e.preventDefault();
    if (!managePopover.classList.contains("hidden")) {
      managePopover.classList.add("hidden");
    } else if (!modal.classList.contains("hidden")) {
      closePreview();
    } else if (mode === "det") {
      detSkip();
    } else if (mode === "cls") {
      clsSkip();
    } else if (state === "preview" || state === "recording" || state === "countdown") {
      discardRecording();
    }
  } else if (mode === "cls") {
    // CLS keyboard shortcuts: 1-9,0,a-d for class selection, D for delete, S for skip
    const key = e.key.toLowerCase();
    if (key === "d" && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      clsDelete();
    } else if (key === "s") {
      e.preventDefault();
      clsSkip();
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
  for (const cat of ["idles", "paths", "holds", "drags", "slide_drags", "grids", "browses"]) {
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
  for (const cat of ["idles", "paths", "holds", "drags", "slide_drags", "grids", "browses"]) {
    total += (allRecordings[cat]?.count || 0);
  }
  if (total === 0) return;
  if (!confirm(`Delete ALL ${total} recordings?`)) return;
  for (const cat of ["idles", "paths", "holds", "drags", "slide_drags", "grids", "browses"]) {
    for (const file of (allRecordings[cat]?.files || [])) {
      await fetch(`/api/recordings/${cat}/${file}`, { method: "DELETE" });
    }
  }
  showStatus("Deleted everything", "success");
  await refreshRecordings();
  populateManage();
});

// ── Init ───────────────────────────────────────────────────────────────
// Restore mode from URL hash
const validModes = ["idle", "path", "hold", "drag", "slide_drag", "grid", "browse", "det", "cls"];
const hashMode = location.hash.slice(1);
if (hashMode && validModes.includes(hashMode) && hashMode !== "det" && hashMode !== "cls") {
  switchMode(hashMode);
}
resizeCanvas();
refreshRecordings();
// Load DET grids and CLS tiles, then switch if hash matches
loadDetEntries().then(() => {
  if (hashMode === "det" && detHasEntries) {
    switchMode("det");
  }
});
loadClsTiles().then(() => {
  if (hashMode === "cls" && clsHasTiles) {
    switchMode("cls");
  }
});
