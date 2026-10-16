// Native owns discovery, trust and installation. The page receives only signed
// display text and a status; no URL, path or key enters the WebView.
const invoke = window.__TAURI_INTERNALS__?.invoke;
const banner = document.getElementById("update-banner");
const message = document.getElementById("update-message");
const progress = document.getElementById("update-progress");
const actions = document.getElementById("update-actions");
const toggle = document.getElementById("update-notes-toggle");
const install = document.getElementById("update-install");
const notes = document.getElementById("update-notes");
const dismiss = document.getElementById("update-dismiss");
// With the notes list hidden, a small indicator in the bar stands in for the card.
const chip = document.getElementById("update-chip");
let last = "";
let showNotes = false;
let poll;

function render(status) {
  const phase = status?.phase;
  if (!phase || phase === "disabled" || phase === "idle" || phase === "dismissed") {
    banner.hidden = true;
    delete document.documentElement.dataset.update;
    return;
  }
  banner.hidden = false;
  document.documentElement.dataset.update = phase;
  progress.hidden = phase !== "downloading";
  actions.hidden = phase !== "available" && phase !== "retry";
  toggle.hidden = phase !== "available";
  install.textContent = phase === "retry" ? "Try again" : "Install update";
  dismiss.hidden = phase !== "error" && phase !== "restart";
  notes.hidden = phase !== "available" || !showNotes;
  toggle.setAttribute("aria-expanded", String(showNotes));
  if (phase === "available") {
    message.textContent = `BaseHero ${status.version} is ready`;
    notes.textContent = status.whatsNew || "";
  } else if (phase === "downloading") {
    message.textContent = `Downloading BaseHero ${status.version}…`;
  } else if (phase === "saving") {
    message.textContent = "Saving your writing before BaseHero restarts…";
  } else {
    message.textContent = status.message || "Couldn't install the update. BaseHero stays open.";
  }
  chip.setAttribute("aria-label", message.textContent);
  chip.title = message.textContent;
}
async function refresh() {
  try {
    const status = await invoke("update_status");
    const encoded = JSON.stringify(status);
    if (encoded !== last) { last = encoded; render(status); }
    if (status?.phase === "disabled") clearInterval(poll);
    return status?.phase !== "disabled";
  } catch {
    return true;
  }
}
async function act(command) {
  try { await invoke(command); } catch { /* the next status explains */ }
  await refresh();
}
if (invoke) {
  toggle.addEventListener("click", () => {
    showNotes = !showNotes;
    notes.hidden = !showNotes;
    toggle.setAttribute("aria-expanded", String(showNotes));
  });
  install.addEventListener("click", () => {
    actions.hidden = true;
    void act("update_install");
  });
  document.getElementById("update-not-now").addEventListener("click", () => act("update_not_now"));
  dismiss.addEventListener("click", () => act("update_not_now"));
  void refresh().then((polling) => {
    if (polling) poll = setInterval(refresh, 1500);
  });
}
