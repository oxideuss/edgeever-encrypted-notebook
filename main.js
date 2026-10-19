const PANEL_ID = "encrypted-notebook";
const VAULT_TITLE = "Encrypted notebook data";
const VAULT_TAG = "encrypted-notebook-vault";
const ENVELOPE = "EDGE_EVER_ENCRYPTED_NOTEBOOK_V1\n";
const PBKDF2_ITERATIONS = 310000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function el(tag, text = "", className = "") {
  const node = document.createElement(tag);
  if (text) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function button(label, onClick, className = "") {
  const node = el("button", label, className);
  node.type = "button";
  node.addEventListener("click", onClick);
  return node;
}
function b64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
function unb64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
function id() {
  return crypto.randomUUID ? crypto.randomUUID() : b64(crypto.getRandomValues(new Uint8Array(16))).replace(/[+/=]/g, "");
}
function emptyNote(title) {
  return { id: id(), title, markdown: "" };
}

async function deriveKey(passphrase, salt, bits, iterations) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: bits },
    false,
    ["encrypt", "decrypt"],
  );
}
async function encrypt(value, passphrase, algorithm) {
  const bits = algorithm === "AES-GCM-128" ? 128 : 256;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, bits, PBKDF2_ITERATIONS);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, key, encoder.encode(value));
  return {
    version: 1,
    algorithm,
    kdf: "PBKDF2-HMAC-SHA-256",
    iterations: PBKDF2_ITERATIONS,
    salt: b64(salt),
    iv: b64(iv),
    ciphertext: b64(new Uint8Array(ciphertext)),
  };
}
async function decrypt(envelope, passphrase) {
  if (envelope?.version !== 1 || !["AES-GCM-128", "AES-GCM-256"].includes(envelope.algorithm)) {
    throw new Error("Unsupported encrypted notebook format.");
  }
  if (envelope.kdf !== "PBKDF2-HMAC-SHA-256" || !Number.isInteger(envelope.iterations) || envelope.iterations < 100000 || envelope.iterations > 2000000) {
    throw new Error("Invalid key derivation settings.");
  }
  const salt = unb64(envelope.salt);
  const iv = unb64(envelope.iv);
  if (salt.length !== 16 || iv.length !== 12) throw new Error("Malformed encrypted notebook.");
  const bits = envelope.algorithm === "AES-GCM-128" ? 128 : 256;
  const key = await deriveKey(passphrase, salt, bits, envelope.iterations);
  const clear = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, tagLength: 128 }, key, unb64(envelope.ciphertext),
  );
  return decoder.decode(clear);
}
function pack(envelope) {
  return ENVELOPE + b64(encoder.encode(JSON.stringify(envelope)));
}
function unpack(markdown) {
  if (!String(markdown || "").startsWith(ENVELOPE)) throw new Error("Encrypted notebook data was not found.");
  try {
    return JSON.parse(decoder.decode(unb64(markdown.slice(ENVELOPE.length))));
  } catch {
    throw new Error("Encrypted notebook data is malformed.");
  }
}
function normalizeContent(value) {
  try {
    const parsed = JSON.parse(value);
    if (parsed?.format === "encrypted-notebook-content-v1" && Array.isArray(parsed.notes)) {
      const notes = parsed.notes.filter((note) => note && typeof note.id === "string").map((note) => ({
        id: note.id,
        title: typeof note.title === "string" && note.title.trim() ? note.title : "Untitled note",
        markdown: typeof note.markdown === "string" ? note.markdown : "",
      }));
      if (notes.length) return { format: "encrypted-notebook-content-v1", activeId: notes.some((note) => note.id === parsed.activeId) ? parsed.activeId : notes[0].id, notes };
    }
  } catch { /* Older format stored one Markdown document directly. */ }
  const note = { id: id(), title: "Note 1", markdown: String(value || "") };
  return { format: "encrypted-notebook-content-v1", activeId: note.id, notes: [note] };
}

function appendInline(parent, text) {
  const pattern = /(\*\*[^*]+\*\*|__[^_]+__|`[^`]+`|\*[^*]+\*|_[^_]+_|~~[^~]+~~|\[[^\]]+\]\([^)]+\))/g;
  let cursor = 0;
  for (const match of text.matchAll(pattern)) {
    const token = match[0];
    if (match.index > cursor) parent.append(document.createTextNode(text.slice(cursor, match.index)));
    let node;
    if (token.startsWith("**") || token.startsWith("__")) node = el("strong", token.slice(2, -2));
    else if (token.startsWith("~~")) node = el("del", token.slice(2, -2));
    else if (token.startsWith("`")) node = el("code", token.slice(1, -1));
    else if (token.startsWith("*") || token.startsWith("_")) node = el("em", token.slice(1, -1));
    else {
      const [, label, rawUrl] = token.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
      let url;
      try {
        const parsed = new URL(rawUrl, window.location.href);
        if (["http:", "https:", "mailto:"].includes(parsed.protocol)) url = parsed.href;
      } catch { /* Keep invalid links as literal text. */ }
      if (url) {
        node = el("a", label);
        node.href = url;
        node.target = "_blank";
        node.rel = "noopener noreferrer";
      } else node = document.createTextNode(token);
    }
    parent.append(node);
    cursor = match.index + token.length;
  }
  if (cursor < text.length) parent.append(document.createTextNode(text.slice(cursor)));
}
function renderMarkdown(markdown) {
  const root = document.createDocumentFragment();
  const lines = String(markdown || "").replace(/\r\n?/g, "\n").split("\n");
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    if (/^\s*```/.test(line)) {
      const code = [];
      i++;
      while (i < lines.length && !/^\s*```/.test(lines[i])) code.push(lines[i++]);
      if (i < lines.length) i++;
      const pre = el("pre"); pre.append(el("code", code.join("\n"))); root.append(pre); continue;
    }
    const heading = line.match(/^\s{0,3}(#{1,6})\s+(.+)$/);
    if (heading) { const h = el(`h${heading[1].length}`); appendInline(h, heading[2]); root.append(h); i++; continue; }
    if (/^\s{0,3}(---+|\*\*\*+|___+)\s*$/.test(line)) { root.append(document.createElement("hr")); i++; continue; }
    if (/^\s*>/.test(line)) {
      const quote = el("blockquote");
      while (i < lines.length && /^\s*>/.test(lines[i])) { const p = el("p"); appendInline(p, lines[i++].replace(/^\s*>\s?/, "")); quote.append(p); }
      root.append(quote); continue;
    }
    const listItem = line.match(/^\s*(?:[-*+]\s+|\d+\.\s+)/);
    if (listItem) {
      const ordered = /^\s*\d+\./.test(line); const list = document.createElement(ordered ? "ol" : "ul");
      while (i < lines.length) {
        const item = lines[i].match(/^\s*(?:[-*+]\s+|\d+\.\s+)(.*)$/);
        if (!item || ordered !== /^\s*\d+\./.test(lines[i])) break;
        const li = el("li"); appendInline(li, item[1]); list.append(li); i++;
      }
      root.append(list); continue;
    }
    const p = el("p"); const para = [line]; i++;
    while (i < lines.length && lines[i].trim() && !/^\s{0,3}(?:#{1,6}\s|>|```|[-*+]\s+|\d+\.\s+)/.test(lines[i])) para.push(lines[i++]);
    para.forEach((part, index) => { if (index) p.append(document.createElement("br")); appendInline(p, part); }); root.append(p);
  }
  return root;
}
function createEditor(initial = "", onChange = () => {}) {
  const root = el("div", "", "enb-editor");
  const toolbar = el("div", "", "enb-format-toolbar");
  const textarea = el("textarea", "", "enb-markdown-input");
  textarea.placeholder = "Write Markdown…"; textarea.rows = 16; textarea.value = initial;
  const preview = el("div", "", "enb-markdown-preview"); preview.hidden = true;
  const tabs = el("div", "", "enb-tabs");
  const writeTab = button("Write", () => setPreview(false));
  const previewTab = button("Preview", () => setPreview(true));
  writeTab.setAttribute("aria-pressed", "true"); previewTab.setAttribute("aria-pressed", "false"); tabs.append(writeTab, previewTab);
  function wrap(before, after, placeholder = "text") {
    const start = textarea.selectionStart, end = textarea.selectionEnd;
    textarea.setRangeText(`${before}${textarea.value.slice(start, end) || placeholder}${after}`, start, end, "select"); textarea.focus(); onChange(textarea.value);
  }
  function prefix(prefixText) {
    const start = textarea.selectionStart, end = textarea.selectionEnd;
    const lineStart = textarea.value.lastIndexOf("\n", Math.max(0, start - 1)) + 1;
    const nextBreak = textarea.value.indexOf("\n", end), lineEnd = nextBreak < 0 ? textarea.value.length : nextBreak;
    textarea.setRangeText(textarea.value.slice(lineStart, lineEnd).split("\n").map((line) => prefixText + line).join("\n"), lineStart, lineEnd, "select");
    textarea.focus(); onChange(textarea.value);
  }
  [["B", "Bold", () => wrap("**", "**")], ["I", "Italic", () => wrap("*", "*")], ["Code", "Inline code", () => wrap("`", "`", "code")], ["H2", "Heading", () => prefix("## ")], ["• List", "Bullet list", () => prefix("- ")], ["Quote", "Block quote", () => prefix("> ")], ["Link", "Link", () => wrap("[", "](https://example.com)", "link text")]].forEach(([label, title, action]) => {
    const b = button(label, action); b.title = title; b.setAttribute("aria-label", title); toolbar.append(b);
  });
  function setPreview(show) {
    textarea.hidden = show; preview.hidden = !show;
    writeTab.setAttribute("aria-pressed", String(!show)); previewTab.setAttribute("aria-pressed", String(show));
    if (show) preview.replaceChildren(renderMarkdown(textarea.value)); else textarea.focus();
  }
  textarea.addEventListener("input", () => onChange(textarea.value));
  root.append(toolbar, tabs, textarea, preview);
  return { element: root, getValue: () => textarea.value, setValue(value) { textarea.value = value; if (!preview.hidden) preview.replaceChildren(renderMarkdown(value)); onChange(value); } };
}

export default {
  activate(context) {
    let panel = null;
    let notebook = null;
    let passphrase = "";
    let encryptedNoteId = null;
    let dirty = false;
    const clearSession = () => { notebook = null; passphrase = ""; encryptedNoteId = null; dirty = false; if (panel) panel.replaceChildren(); };
    const mayLeave = () => !dirty || window.confirm("Leave this notebook and discard unsaved changes?");
    async function findVault(notebookId) {
      async function findSummary(tags) {
        let offset = 0;
        for (;;) {
          const result = await context.notes.query({
            notebookId,
            ...(tags ? { tags } : {}),
            sort: "created-desc",
            limit: 200,
            offset,
          });
          const notes = Array.isArray(result?.notes) ? result.notes : [];
          const item = notes.find((note) => tags ? true : note.title === VAULT_TITLE);
          if (item) return item;
          if (result?.nextOffset == null) return null;
          if (!Number.isInteger(result.nextOffset) || result.nextOffset <= offset) {
            throw new Error("The note query returned an invalid pagination cursor.");
          }
          offset = result.nextOffset;
        }
      }

      // Fast path for new vaults; the paginated title scan also finds older vault notes.
      const tagged = await findSummary([VAULT_TAG]);
      const item = tagged || await findSummary(null);
      return item ? context.notes.get(item.id) : null;
    }
    async function home(container, noticeText = "") {
      clearSession(); panel = container;
      const heading = el("h2", "Encrypted notebooks");
      const intro = el("p", "Notebook names remain visible in EdgeEver. Notebook note titles and Markdown are stored together inside the encrypted payload.");
      const status = el("p", noticeText, "enb-status");
      const create = button("Create encrypted notebook", () => createScreen(container));
      container.append(heading, intro, create, status);
      try {
        const notebooks = await context.notebooks.list();
        const list = el("div", "", "enb-notebook-list");
        for (const item of notebooks) {
          const row = el("div", "", "enb-notebook-row");
          row.append(el("span", item.name));
          try {
            const note = await findVault(item.id);
            if (note) row.append(button("Decrypt", () => unlock(container, item)));
            else row.append(el("span", "Encrypted data note not found.", "enb-status"));
          } catch (error) {
            row.append(el("span", `Could not check encrypted data: ${error.message}`, "enb-status"));
          }
          list.append(row);
        }
        container.append(list);
      } catch (error) { status.textContent = `Could not list notebooks: ${error.message}`; }
    }
    function createScreen(container) {
      clearSession(); panel = container;
      const form = el("form", "", "enb-form");
      form.append(el("h2", "Create encrypted notebook"));
      const name = el("input"); name.placeholder = "Notebook name"; name.required = true; name.maxLength = 120;
      const password = el("input"); password.type = "password"; password.placeholder = "Passphrase (at least 12 characters)"; password.minLength = 12; password.required = true; password.autocomplete = "new-password";
      const confirm = el("input"); confirm.type = "password"; confirm.placeholder = "Confirm passphrase"; confirm.required = true; confirm.autocomplete = "new-password";
      const status = el("p", "", "enb-status"); const editor = createEditor();
      const actions = el("div", "", "enb-actions"); const submit = el("button", "Encrypt and create"); submit.type = "submit";
      const cancel = button("Cancel", () => home(container)); actions.append(submit, cancel);
      form.append(name, password, confirm, editor.element, actions, status); container.replaceChildren(form);
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (password.value.length < 12 || password.value !== confirm.value) { status.textContent = password.value !== confirm.value ? "Passphrases do not match." : "Use a passphrase with at least 12 characters."; return; }
        submit.disabled = true; status.textContent = "Encrypting and saving…";
        try {
          const setting = await context.settings.get("encryption-algorithm");
          const algorithm = setting === "AES-GCM-128" ? setting : "AES-GCM-256";
          const first = { ...emptyNote("Note 1"), markdown: editor.getValue() };
          const content = { format: "encrypted-notebook-content-v1", activeId: first.id, notes: [first] };
          const payload = await encrypt(JSON.stringify(content), password.value, algorithm);
          const created = await context.notebooks.create({ name: name.value.trim(), parentId: null });
          await context.notes.create({ notebookId: created.id, title: VAULT_TITLE, contentMarkdown: pack(payload), tags: [VAULT_TAG] });
          password.value = ""; confirm.value = ""; editor.setValue(""); name.value = "";
          await home(container, "Encrypted notebook created.");
        } catch (error) { status.textContent = `Could not create notebook: ${error.message}`; submit.disabled = false; }
      });
    }
    async function unlock(container, item) {
      clearSession(); panel = container;
      const form = el("form", "", "enb-form"); form.append(el("h2", `Decrypt “${item.name}”`));
      const password = el("input"); password.type = "password"; password.placeholder = "Passphrase"; password.required = true; password.autocomplete = "current-password";
      const status = el("p", "", "enb-status"); const actions = el("div", "", "enb-actions"); const submit = el("button", "Decrypt"); submit.type = "submit";
      actions.append(submit, button("Cancel", () => home(container))); form.append(password, actions, status); container.replaceChildren(form);
      form.addEventListener("submit", async (event) => {
        event.preventDefault(); submit.disabled = true; status.textContent = "Decrypting…";
        try {
          const saved = await findVault(item.id); if (!saved) throw new Error("Encrypted data not found.");
          notebook = normalizeContent(await decrypt(unpack(saved.contentMarkdown), password.value));
          passphrase = password.value; encryptedNoteId = saved.id; password.value = "";
          editorScreen(container, item);
        } catch { password.value = ""; status.textContent = "Could not decrypt. Check the passphrase and try again."; submit.disabled = false; }
      });
    }
    function editorScreen(container, item) {
      panel = container;
      if (!notebook?.notes?.length) { const first = emptyNote("Note 1"); notebook = { format: "encrypted-notebook-content-v1", activeId: first.id, notes: [first] }; }
      let selected = notebook.notes.find((note) => note.id === notebook.activeId) || notebook.notes[0]; notebook.activeId = selected.id;
      const heading = el("h2", item.name); const status = el("p", "Decrypted content remains in client memory while this panel is open.", "enb-status");
      const workspace = el("div", "", "enb-workspace"); const sidebar = el("aside", "", "enb-sidebar");
      const sidebarHeader = el("div", "", "enb-sidebar-header"); sidebarHeader.append(el("h3", "Notes"), button("+", () => addNote(), "enb-add-note"));
      const noteList = el("div", "", "enb-note-list"); sidebar.append(sidebarHeader, noteList);
      const toggle = button("‹", () => { const isCollapsed = workspace.classList.toggle("enb-collapsed"); toggle.textContent = isCollapsed ? "›" : "‹"; toggle.title = isCollapsed ? "Expand notes" : "Collapse notes"; }, "enb-toggle");
      const area = el("section", "", "enb-note-area"); const noteHeader = el("div", "", "enb-note-header"); const title = el("h3", selected.title);
      const rename = button("Rename", renameNote); const remove = button("Delete", deleteNote); noteHeader.append(title, rename, remove);
      const editor = createEditor(selected.markdown, (value) => { selected.markdown = value; dirty = true; });
      const actions = el("div", "", "enb-actions"); const save = button("Encrypt and save", saveNotes); const lock = button("Lock notebook", lockNotebook); actions.append(save, lock);
      area.append(noteHeader, editor.element, actions); workspace.append(sidebar, toggle, area); container.replaceChildren(heading, status, workspace);
      dirty = false;
      function renderList() {
        noteList.replaceChildren();
        for (const note of notebook.notes) {
          const select = button(note.title, () => { selected = note; notebook.activeId = note.id; title.textContent = note.title; editor.setValue(note.markdown); renderList(); }, "enb-note-select");
          select.setAttribute("aria-current", String(note.id === selected.id)); noteList.append(select);
        }
      }
      function addNote() {
        selected = emptyNote(`Note ${notebook.notes.length + 1}`); notebook.notes.push(selected); notebook.activeId = selected.id;
        title.textContent = selected.title; editor.setValue(""); dirty = true; renderList();
      }
      function renameNote() {
        const next = window.prompt("Note title", selected.title);
        if (next === null) return;
        if (!next.trim()) { status.textContent = "A note title cannot be empty."; return; }
        selected.title = next.trim(); title.textContent = selected.title; dirty = true; renderList();
      }
      function deleteNote() {
        if (notebook.notes.length < 2) { status.textContent = "A notebook must contain at least one note."; return; }
        if (!window.confirm(`Delete “${selected.title}” from this notebook?`)) return;
        notebook.notes = notebook.notes.filter((note) => note.id !== selected.id); selected = notebook.notes[0]; notebook.activeId = selected.id;
        title.textContent = selected.title; editor.setValue(selected.markdown); dirty = true; renderList();
      }
      async function saveNotes() {
        save.disabled = true; status.textContent = "Encrypting and saving…";
        try {
          const saved = await context.notes.get(encryptedNoteId); const envelope = unpack(saved.contentMarkdown);
          const payload = await encrypt(JSON.stringify(notebook), passphrase, envelope.algorithm);
          await context.notes.update(encryptedNoteId, { contentMarkdown: pack(payload) }); dirty = false; status.textContent = "Encrypted changes saved.";
        } catch (error) { status.textContent = `Could not save encrypted changes: ${error.message}`; }
        finally { save.disabled = false; }
      }
      async function lockNotebook() {
        if (!mayLeave()) return;
        await home(container, "Notebook locked. Enter its passphrase to open it again.");
      }
      renderList();
    }
    async function openPanel(screen = "home") { await context.ui.panels.open(PANEL_ID, { state: { screen } }); }
    const disposePanel = context.ui.panels.register({
      id: PANEL_ID, title: "Encrypted Notebook", purpose: "workflow", presentation: "fullscreen",
      mount(container, { shell, state }) {
        panel = container;
        shell.set({
          header: { title: "Encrypted Notebook", description: "Create or decrypt passphrase-protected notebooks.", actions: [
            { id: "create", label: "New encrypted notebook" }, { id: "home", label: "Notebook list" },
          ] },
          onAction(actionId) { if (!mayLeave()) return; if (actionId === "create") createScreen(container); if (actionId === "home") home(container); },
        });
        if (state?.screen === "create") createScreen(container); else home(container);
        return () => { clearSession(); panel = null; container.replaceChildren(); };
      },
      beforeClose() { if (!mayLeave()) return false; clearSession(); return true; },
    });
    const disposeCreate = context.commands.register({ id: "create-encrypted-notebook", title: "Create Encrypted Notebook", listed: true, menu: true, run: () => openPanel("create") });
    const disposeOpen = context.commands.register({ id: "open-encrypted-notebook", title: "Open Encrypted Notebook", listed: true, menu: true, run: () => openPanel("home") });
    return () => { clearSession(); disposePanel(); disposeCreate(); disposeOpen(); };
  },
};

