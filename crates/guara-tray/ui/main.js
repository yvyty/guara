// Guará quick-search palette.
//
// Every request goes through the same protocol types and engine as the CLI:
// the shell answers `search`, `status`, `recents`, `pin_scope`, and `scan`.

const invoke = window.__TAURI__.core.invoke;

const queryInput = document.getElementById("query");
const resultsList = document.getElementById("results");
const stateBadge = document.getElementById("state");
const pinsList = document.getElementById("pins");
const recentsList = document.getElementById("recents");
const statusLine = document.getElementById("status");
const autoStartBox = document.getElementById("autostart");
const pinButton = document.getElementById("pin");

let hits = [];
let selected = 0;
let activeRoot = null;

function setStatus(text) {
  statusLine.textContent = text;
}

function renderHits() {
  resultsList.replaceChildren();
  hits.forEach((hit, index) => {
    const row = document.createElement("div");
    row.className = index === selected ? "hit selected" : "hit";

    const path = document.createElement("span");
    path.className = "path";
    path.textContent = hit.path;

    const meta = document.createElement("span");
    meta.className = `meta verdict ${hit.verdict}`;
    const size = hit.size === null ? "" : ` · ${hit.size} B`;
    meta.textContent = `${hit.name_matched ? "name" : "content"}${size} · ${hit.verdict}`;

    row.append(path, meta);
    row.addEventListener("click", async () => {
      selected = index;
      renderHits();
      await invoke("open_hit", { path: hit.path });
    });
    resultsList.append(row);
  });
}

async function runSearch() {
  const query = queryInput.value.trim();
  if (!query) {
    hits = [];
    renderHits();
    return;
  }
  try {
    const response = await invoke("palette_search", {
      query,
      root: activeRoot,
      limit: 200,
    });
    if (response.response === "hits") {
      hits = response.hits;
      selected = 0;
      renderHits();
      setStatus(`${response.hits.length} hit(s) in ${response.stats.elapsed_ms} ms`);
      await refreshSide();
    } else {
      hits = [];
      renderHits();
      setStatus(response.message ?? "search failed");
    }
  } catch (error) {
    setStatus(String(error));
  }
}

async function refreshSide() {
  const [recents, status] = await Promise.all([
    invoke("recent_queries"),
    invoke("daemon_status"),
  ]);
  if (recents.response === "recents") {
    recentsList.replaceChildren(
      ...recents.queries.map((query) => {
        const item = document.createElement("li");
        item.textContent = query;
        item.addEventListener("click", () => {
          queryInput.value = query;
          runSearch();
        });
        return item;
      }),
    );
  }
  if (status.response === "status") {
    stateBadge.className = `state ${status.watching ? "indexing" : "idle"}`;
    stateBadge.textContent = status.watching ? "indexing" : "idle";
    activeRoot = activeRoot ?? status.roots[0] ?? null;
    setStatus(
      `${status.indexed_paths} indexed path(s) · ${status.roots.length} root(s)` +
        (status.watching ? " · watching" : ""),
    );
  }
}

async function scanSelected() {
  const hit = hits[selected];
  if (!hit) {
    return;
  }
  const response = await invoke("scan_hit", { path: hit.path });
  if (response.response === "assessment") {
    const detail = response.reasons.map((reason) => reason.message).join("; ");
    setStatus(`scan of ${response.path}: ${response.verdict}${detail ? ` (${detail})` : ""}`);
  }
}

async function openSelected() {
  const hit = hits[selected];
  if (hit) {
    await invoke("open_hit", { path: hit.path });
  }
}

queryInput.addEventListener("keydown", async (event) => {
  if (event.key === "Enter") {
    if (hits.length > 0 && event.metaKey) {
      await openSelected();
    } else {
      await runSearch();
    }
  } else if (event.key === "ArrowDown") {
    selected = Math.min(selected + 1, Math.max(hits.length - 1, 0));
    renderHits();
  } else if (event.key === "ArrowUp") {
    selected = Math.max(selected - 1, 0);
    renderHits();
  } else if (event.key === "o") {
    await openSelected();
  } else if (event.key === "s") {
    await scanSelected();
  } else if (event.key === "Escape") {
    await invoke("hide_palette");
  }
});

pinButton.addEventListener("click", async () => {
  const root = activeRoot ?? queryInput.value.trim();
  if (!root) {
    setStatus("search a root first, then pin it");
    return;
  }
  const response = await invoke("pin_scope", { root, label: null });
  if (response.response === "pinned") {
    pinsList.replaceChildren(
      ...response.scopes.map((scope) => {
        const item = document.createElement("li");
        item.textContent = `${scope.label} (${scope.root})`;
        item.addEventListener("click", () => {
          activeRoot = scope.root;
          runSearch();
        });
        return item;
      }),
    );
    setStatus(`pinned ${root}`);
  }
});

autoStartBox.addEventListener("change", async () => {
  const enabled = await invoke("toggle_auto_start");
  autoStartBox.checked = enabled;
  setStatus(`start at login: ${enabled ? "on" : "off"}`);
});

invoke("auto_start_enabled").then((enabled) => {
  autoStartBox.checked = enabled;
});
refreshSide();
queryInput.focus();