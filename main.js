// Anti-Clickjacking (CSP Compliant)
if (self === top) {
  var antiClickjack = document.getElementById("antiClickjack");
  if (antiClickjack) antiClickjack.parentNode.removeChild(antiClickjack);
} else {
  top.location = self.location;
}

(function() {
// --- Global functions and variables (File save/load, Command palette) ---
let isDirty = false;
let fileHandle = null;
let lastSavedPasswordHash = "";

async function sha256(message) {
  if (typeof message !== 'string' || message.length === 0) return "";
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- Encryption/Decryption logic ---
const MAGIC_BYTES = new TextEncoder().encode("GRINDEN2");
const MAGIC_BYTES_LEGACY = new TextEncoder().encode("GRINDENC");

function appPrompt(message, inputType = "password") {
  return new Promise((resolve) => {
    const app = window.$app;
    app.promptMessage = message;
    app.promptInput = "";
    app.promptInputType = inputType;
    app.resolvePrompt = (value) => {
      resolve(value);
      app.resolvePrompt = null;
    };
    app.showPromptModal = true;
    setTimeout(() => {
      if (app.$refs.promptInputField) app.$refs.promptInputField.focus();
    }, 100);
  });
}

async function deriveKey(password, salt, iterations = 600000) {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return window.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: iterations, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}

async function encryptData(data, password) {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt, 600000);
  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv }, key, data
  );

  const result = new Uint8Array(MAGIC_BYTES.length + salt.length + iv.length + encrypted.byteLength);
  result.set(MAGIC_BYTES, 0);
  result.set(salt, MAGIC_BYTES.length);
  result.set(iv, MAGIC_BYTES.length + salt.length);
  result.set(new Uint8Array(encrypted), MAGIC_BYTES.length + salt.length + iv.length);
  return result;
}

async function decryptData(encryptedData, password) {
  const magic = encryptedData.slice(0, 8);
  const magicStr = new TextDecoder().decode(magic);
  const isEncryptedV2 = magicStr === "GRINDEN2";
  const isEncryptedLegacy = magicStr === "GRINDENC";
  if (!isEncryptedV2 && !isEncryptedLegacy) return encryptedData;

  const salt = encryptedData.slice(8, 24);
  const iv = encryptedData.slice(24, 36);
  const data = encryptedData.slice(36);

  try {
    const iterations = isEncryptedV2 ? 600000 : 100000;
    const key = await deriveKey(password, salt, iterations);
    const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, data);
    return new Uint8Array(decrypted);
  } catch (e) {
    throw new Error("Incorrect password or corrupted file.");
  }
}

// Verify and request file system permissions for File System Access API
async function verifyFilePermission(handle, readWrite) {
  const options = {};
  if (readWrite) {
    options.mode = 'readwrite';
  }
  if ((await handle.queryPermission(options)) === 'granted') {
    return true;
  }
  if ((await handle.requestPermission(options)) === 'granted') {
    return true;
  }
  return false;
}

function setDirty(state) {
  isDirty = state;
  const badge = document.getElementById("dirty-badge");
  if (badge) {
    if (state) {
      badge.classList.remove("hidden");
      badge.classList.add("flex");
    } else {
      badge.classList.add("hidden");
      badge.classList.remove("flex");
    }
  }
  const fileName = fileHandle && fileHandle.name ? fileHandle.name : "Unsaved.qrcoder";
  const filenameBadge = document.getElementById("current-filename");
  if (filenameBadge) {
    filenameBadge.textContent = fileName;
    filenameBadge.classList.remove("hidden");
  }
}

async function processQRCoderFile(file) {
  // Warn and confirm before overwriting unsaved changes in the editor.
  const component = window.$app;
  if (component && component.hasUnsavedEdit) {
    if (!confirm("You have unsaved changes in the editor. Discard them and load the file?")) {
      return;
    }
  }

  if (file.size > 20 * 1024 * 1024) {
    alert("File size is too large. Please select a valid .qrcoder file.");
    return;
  }

  try {
    const arrayBuffer = await file.arrayBuffer();
    let Uints = new Uint8Array(arrayBuffer);

    const magic = Uints.slice(0, 8);
    const magicStr = new TextDecoder().decode(magic);
    const isEncrypted = magicStr === "GRINDENC" || magicStr === "GRINDEN2";

    let text;
    if (isEncrypted) {
      let password = document.getElementById("file-password")?.value;
      let success = false;
      let attempt = 0;
      while (!success) {
        try {
          Uints = await decryptData(Uints, password);
          success = true;
          if (password) {
            const pwInput = document.getElementById("file-password");
            if (pwInput) pwInput.value = password;
            lastSavedPasswordHash = await sha256(password);
          }
        } catch (err) {
          const msg = attempt > 0 ? "❌ Incorrect password. Please try again:" : "The file is encrypted. Enter the password to decrypt:";
          password = await appPrompt(msg);
          if (password === null) return;
          attempt++;
        }
      }
      text = new TextDecoder().decode(Uints);
    } else {
      text = new TextDecoder().decode(Uints);
      const pwInput = document.getElementById("file-password");
      if (pwInput) pwInput.value = "";
      lastSavedPasswordHash = "";
    }

    const parsedData = JSON.parse(text);

    // [New] Check if it's a theme (Design Assets) file
    const isThemeFile = file.name.endsWith('.qrcoder-theme') || parsedData.type === 'theme';

    if (isThemeFile) {
      const importedBrands = parsedData.brandKits || [];
      const importedTemplates = parsedData.templates || [];

      const isConfirmed = window.confirm(
        `Import Design Assets?\n\nBrands: ${importedBrands.length}\nTemplates: ${importedTemplates.length}\n\n[OK] = Add to existing assets\n[Cancel] = Cancel loading`
      );
      if (!isConfirmed) return;

      const mergeItems = (currentList, newItems) => {
        const existingNames = new Set(currentList.map(item => item.name));
        const result = [...currentList];
        for (const item of newItems) {
          if (!existingNames.has(item.name)) {
            item.id = component.generateUniqueId();
            result.push(item);
          } else {
            item.id = component.generateUniqueId();
            item.name = `${item.name} (Imported)`;
            result.push(item);
          }
        }
        return result;
      };

      if (importedBrands.length > 0) {
        component.brandKits = mergeItems(component.brandKits, importedBrands);
        component.saveBrandKits(false);
      }
      if (importedTemplates.length > 0) {
        component.myTemplates = mergeItems(component.myTemplates, importedTemplates);
        await component.persistMyTemplates();
      }
      component.showFlashNotification(`Imported design assets from "${file.name}"`);
      if (component.hapticFeedback) component.hapticFeedback('success');
      return;
    }

    let newQRCodes = [];
    let importedProjects = [];
    let importedBrands = [];
    let importedTemplates = [];

    if (Array.isArray(parsedData)) {
      newQRCodes = parsedData;
    } else if (parsedData.version >= 3) {
      newQRCodes = parsedData.qrcodes || [];
      importedProjects = parsedData.projects || [];
      importedBrands = parsedData.brandKits || [];
      importedTemplates = parsedData.templates || [];
    }

    // Add fail-safe to prevent data loss.
    if (component.savedQRCodes && component.savedQRCodes.length > 0) {
      const shouldMerge = window.confirm(
        "QR codes are currently saved in the dashboard.\n" +
        "Do you want to \"merge\" the loaded backup data with the existing list?\n\n" +
        "[OK] = Add to existing data\n" +
        "[Cancel] = Overwrite or cancel loading"
      );

      if (!shouldMerge) {
        const shouldOverwrite = window.confirm(
          "⚠️ Warning: Do you want to delete all current data and \"overwrite\" with the backup content?\n\n" +
          "[OK] = Overwrite (current data will be completely lost)\n" +
          "[Cancel] = Cancel loading"
        );

        if (shouldOverwrite) {
          component.savedQRCodes = newQRCodes;
          if (importedProjects.length > 0) component.projects = importedProjects;
          if (importedBrands.length > 0) component.brandKits = importedBrands;
          if (importedTemplates.length > 0) component.myTemplates = importedTemplates;
        } else {
          return; // Abort completely without doing anything.
        }
      } else {
        const projectIdMap = {};

        const mergeProjects = (currentList, newItems) => {
          const existingIds = new Set(currentList.map(item => item.id));
          const result = [...currentList];
          for (const item of newItems) {
            if (!existingIds.has(item.id)) {
              result.push(item);
            } else {
              const newId = component.generateUniqueId();
              projectIdMap[item.id] = newId;
              item.id = newId;
              result.push(item);
            }
          }
          return result;
        };

        if (importedProjects.length > 0) {
          component.projects = mergeProjects(component.projects, importedProjects);
        }

        const mergeQRs = (currentList, newItems) => {
          const existingIds = new Set(currentList.map(item => item.id));
          const result = [...currentList];
          for (const item of newItems) {
            if (projectIdMap[item.projectId]) {
              item.projectId = projectIdMap[item.projectId];
            }
            if (!existingIds.has(item.id)) {
              result.push(item);
            } else {
              item.id = component.generateUniqueId();
              result.push(item);
            }
          }
          return result;
        };

        component.savedQRCodes = mergeQRs(component.savedQRCodes, newQRCodes);

        const mergeItems = (currentList, newItems) => {
          const existingIds = new Set(currentList.map(item => item.id));
          const result = [...currentList];
          for (const item of newItems) {
            if (!existingIds.has(item.id)) {
              result.push(item);
            } else {
              item.id = component.generateUniqueId();
              result.push(item);
            }
          }
          return result;
        };

        if (importedBrands.length > 0) component.brandKits = mergeItems(component.brandKits, importedBrands);
        if (importedTemplates.length > 0) component.myTemplates = mergeItems(component.myTemplates, importedTemplates);
      }
    } else {
      component.savedQRCodes = newQRCodes;
      if (importedProjects.length > 0) component.projects = importedProjects;
      if (importedBrands.length > 0) component.brandKits = importedBrands;
      if (importedTemplates.length > 0) component.myTemplates = importedTemplates;
    }

    await component.persistSavedQRCodes();
    await component.persistProjects();
    if (importedBrands.length > 0) component.saveBrandKits(false);
    if (importedTemplates.length > 0) await component.persistMyTemplates();

    setDirty(false);
    component.showFlashNotification(`Loaded file "${file.name}"`);
    component.currentView = 'dashboard';
  } catch (err) {
    console.error(err);
    alert("Failed to load the file. It may be corrupted or in an invalid format.");
  }
}

async function loadQRCoderFile() {
  const app = window.$app;
  if (app && app.hasUnsavedEdit) {
    if (!confirm("You have unsaved changes in the editor. Discard them and load the file?")) return;
  }
  if (isDirty) {
    if (!confirm("You have unsaved changes (dashboard). Discard them and load another backup?")) return;
  }
  try {
    let file;
    if ("showOpenFilePicker" in window) {
      const [handle] = await window.showOpenFilePicker({
        types: [{ description: "QR Coder Database", accept: { "application/json": [".qrcoder"] } }]
      });
      fileHandle = handle;
      file = await handle.getFile();
    } else {
      const input = document.createElement("input");
      input.type = "file";
      input.accept = ".qrcoder";
      file = await new Promise((resolve) => {
        input.onchange = (e) => resolve(e.target.files[0]);
        input.click();
      });
      if (!file) return;
      fileHandle = { name: file.name };
    }

    await processQRCoderFile(file);
  } catch (err) {
    if (err.name === 'AbortError') return; // Do nothing on cancel.
    console.error(err);
    alert("Failed to load the file. It may be corrupted or in an invalid format.");
  }
}

async function saveQRCoderFile() {
  const component = window.$app;

  // Block forced save from shortcuts when data size limit is exceeded.
  if (component && component.qrQuality.issues.some(i => i.id === 'capacity_error')) {
    component.showFlashNotification("Cannot save because the data size exceeds the limit.");
    component.hapticFeedback('error');
    return;
  }

  // Attempt to save to dashboard automatically if there are unsaved edits.
  if (component && component.hasUnsavedEdit) {
    if (component.editingQRCodeId) {
      // Keep editor view and overwrite save if editing an existing QR code.
      await component.saveToGrind(true);
    } else {
      // Open modal to prompt for a name on new creation, pausing file save.
      component.showSaveModal = true;
      setTimeout(() => {
        if (component.$refs.saveNameInput) component.$refs.saveNameInput.focus();
      }, 310);
      component.showFlashNotification("First, enter a name to save it to the dashboard.");
      return;
    }
  }

  let success = false;
  try {
    const exportData = {
      version: 3,
      qrcodes: window.Alpine.raw(component.savedQRCodes),
      projects: window.Alpine.raw(component.projects),
      brandKits: window.Alpine.raw(component.brandKits),
      templates: window.Alpine.raw(component.myTemplates)
    };
    const dataString = JSON.stringify(exportData, null, 2);

    const encoder = new TextEncoder();
    let fileData = encoder.encode(dataString);
    const pwInput = document.getElementById("file-password");

    // Wait for UI redraw (Release main thread).
    await new Promise(resolve => setTimeout(resolve, 50));

    const currentPassword = pwInput ? pwInput.value : "";
    const currentPasswordHash = await sha256(currentPassword);

    if (lastSavedPasswordHash !== "" && currentPassword === "") {
      if (!confirm("Warning: Password is empty.\nSaving now will remove encryption and save in plain text.\n\nAre you sure you want to remove encryption?")) {
        return;
      }
    }

    if (currentPassword !== "" && currentPasswordHash !== lastSavedPasswordHash) {
      const confirmPw = await appPrompt("🔒 Set (or change) password.\nEnter the same password again to confirm:", "password");
      if (confirmPw === null) return;
      if (confirmPw !== currentPassword) {
        component.showFlashNotification("Passwords do not match. Save canceled.");
        component.hapticFeedback('error');
        return;
      }
    }

    if (currentPassword) {
      fileData = await encryptData(fileData, currentPassword);
    }

    if ("showSaveFilePicker" in window) {
      try {
        // Open save destination dialog only if no file has been selected yet.
        if (!fileHandle || typeof fileHandle.createWritable !== 'function') {
          fileHandle = await window.showSaveFilePicker({
            suggestedName: fileHandle ? fileHandle.name : "Data.qrcoder",
            types: [{ description: "QR Coder Database", accept: { "application/json": [".qrcoder"] } }]
          });
        } else {
          const hasPermission = await verifyFilePermission(fileHandle, true);
          if (!hasPermission) {
            throw new DOMException("Permission to write to file was denied.", "NotAllowedError");
          }
        }
        const writable = await fileHandle.createWritable();
        await writable.write(fileData);
        await writable.close();
      } catch (err) {
        // Rethrow error to be handled by outer catch and finally blocks.
        throw err;
      }
    } else {
      const blob = new Blob([fileData], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.target = "_blank";
      a.rel = "noopener";
      a.href = url;
      a.download = fileHandle && fileHandle.name ? fileHandle.name : "Data.qrcoder";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 10000); // Safari fix
      fileHandle = { name: a.download };
    }

    success = true;
    lastSavedPasswordHash = currentPasswordHash;

    // New success feedback logic
    if (component) {
      component.isSaveSuccess = true;
      setTimeout(() => {
        component.isSaveSuccess = false;
      }, 1500);
    }

    // Hide unsaved badge securely after restoring UI structure.
    setDirty(false);

    if (component && component.hapticFeedback) component.hapticFeedback('success');
    component.showFlashNotification("Backup saved.");
  } catch (err) {
    if (err.name !== 'AbortError') {
      console.error(err);
      alert("Failed to save.");
    }
  }
}

// --- Export Design Assets (Brand Kits & Templates) ---
async function saveDesignAssets() {
  const component = window.$app;
  try {
    const exportData = {
      version: 1,
      type: 'theme',
      brandKits: window.Alpine.raw(component.brandKits) || [],
      templates: window.Alpine.raw(component.myTemplates) || []
    };
    if (exportData.brandKits.length === 0 && exportData.templates.length === 0) {
      component.showFlashNotification("No design assets (Brand Kits or Templates) to export.");
      if (component.hapticFeedback) component.hapticFeedback('error');
      return;
    }

    const dataString = JSON.stringify(exportData, null, 2);
    const encoder = new TextEncoder();
    const fileData = encoder.encode(dataString);

    // Theme files are meant to be shared with team members, so they are explicitly NOT encrypted.
    const fileName = "Brand_Design_Assets.qrcoder-theme";

    if ("showSaveFilePicker" in window) {
      const handle = await window.showSaveFilePicker({
        suggestedName: fileName,
        types: [{ description: "QR Coder Theme", accept: { "application/json": [".qrcoder-theme"] } }]
      });
      const writable = await handle.createWritable();
      await writable.write(fileData);
      await writable.close();
    } else {
      const blob = new Blob([fileData], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.target = "_blank";
      a.rel = "noopener";
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    }

    component.showFlashNotification("Design assets exported successfully.");
    if (component.hapticFeedback) component.hapticFeedback('success');
  } catch (err) {
    if (err.name !== 'AbortError') {
      console.error(err);
      alert("Failed to export design assets.");
    }
  }
}

let isCommandPaletteOpen = false;
let selectedCommandIndex = 0;
const commandsList = [
  { id: "save", icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="1.5"><use href="icons-sprite.svg#outline-arrow-down-tray"></use></svg>', title: "Save Backup", action: () => saveQRCoderFile() },
  { id: "open", icon: '<svg class="w-5 h-5"><use href="icons-sprite.svg#outline-folder"></use></svg>', title: "Open Backup", action: () => loadQRCoderFile() },
  { id: "export_theme", icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="1.5"><use href="icons-sprite.svg#outline-sparkles"></use></svg>', title: "Export Design Assets (Brands & Templates)", action: () => saveDesignAssets() }
];

function togglePasswordVisibility() {
  const pwInput = document.getElementById("file-password");
  const iconOpen = document.getElementById("icon-eye-open");
  const iconClosed = document.getElementById("icon-eye-closed");
  if (pwInput.type === "password") {
    pwInput.type = "text";
    iconOpen.classList.remove("hidden");
    iconClosed.classList.add("hidden");
  } else {
    pwInput.type = "password";
    iconOpen.classList.add("hidden");
    iconClosed.classList.remove("hidden");
  }
}

// --- Handle input events globally and reliably ---
window.handleCommandInput = function(e) {
  selectedCommandIndex = 0;
  renderCommandList(e.target.value);
};

// --- Centralized search result processing ---
function getCommandSearchResults(query) {
  const terms = query.toLowerCase().trim().split(/\s+/).filter(Boolean);

  // 1. Search static commands
  const filteredCmds = commandsList.filter(c => terms.every(term => c.title.toLowerCase().includes(term) || c.id.includes(term)));

  // 2. Search saved QR codes
  let filteredQRs = [];
  if (window.$app && window.$app.savedQRCodes) {
    // Bypass Alpine's Proxy and get data as a pure raw array
    const rawQRs = window.Alpine ? window.Alpine.raw(window.$app.savedQRCodes) : window.$app.savedQRCodes;

    if (Array.isArray(rawQRs)) {
      filteredQRs = rawQRs
        .filter(qr => {
          // Safely combine and search including memo and tags, preventing undefined errors
          const nameStr = (qr.name || "").toLowerCase();
          const memoStr = (qr.memo || "").toLowerCase();
          const tagsArray = Array.isArray(qr.tags) ? qr.tags : (typeof qr.tags === 'string' ? qr.tags.split(',') : []);
          const tagsStr = tagsArray.join(" ").toLowerCase();
          const combinedText = `${nameStr} ${memoStr} ${tagsStr}`;

          return terms.every(term => combinedText.includes(term));
        })
        .map(qr => ({
          id: `qr-${qr.id}`,
          icon: '<svg class="w-5 h-5"><use href="icons-sprite.svg#outline-qr-code"></use></svg>',
          title: qr.name || "Untitled",
          action: () => {
            // Show confirmation dialog if there are unsaved changes in the editor
            if (window.$app.hasUnsavedEdit) {
              if (!confirm('You have unsaved changes. Discard them to open this QR code?')) return;
            }
            window.$app.editQRCode(qr.id, true);
          }
        }));
    }
  }

  return [...filteredCmds, ...filteredQRs];
}

function toggleCommandPalette() {
  const palette = document.getElementById("cmd-palette");
  const content = document.getElementById("cmd-palette-content");
  const input = document.getElementById("cmd-input");
  if (!palette || !content) return;

  isCommandPaletteOpen = !isCommandPaletteOpen;

  const metaTheme = document.getElementById("meta-theme-color");
  if (metaTheme) metaTheme.setAttribute("content", isCommandPaletteOpen ? "#111827" : "#f8fafc");

  if (isCommandPaletteOpen) {
    document.body.style.overflow = 'hidden';
    palette.classList.remove("hidden");
    palette.classList.add("flex");
    input.value = "";
    selectedCommandIndex = 0;
    renderCommandList();

    setTimeout(() => input.focus(), 50);

    requestAnimationFrame(() => {
      palette.classList.remove("opacity-0");
      palette.classList.add("opacity-100");
      content.classList.remove("scale-95");
      content.classList.add("scale-100");
    });
  } else {
    document.body.style.overflow = '';
    palette.classList.remove("opacity-100");
    palette.classList.add("opacity-0");
    content.classList.remove("scale-100");
    content.classList.add("scale-95");
    setTimeout(() => {
      if (!isCommandPaletteOpen) {
        palette.classList.add("hidden");
        palette.classList.remove("flex");
      }
    }, 300);
  }
}

// --- List rendering processing ---
function renderCommandList(query = "") {
  const list = document.getElementById("cmd-list");
  if(!list) return;
  list.innerHTML = "";

  const combinedResults = getCommandSearchResults(query);

  if (combinedResults.length === 0) {
    list.innerHTML = `<div class="px-4 py-8 text-center text-slate-400 text-sm">No results found</div>`;
    return;
  }

  if (selectedCommandIndex >= combinedResults.length) selectedCommandIndex = 0;

  // Define helper function for HTML escaping
  const escapeHtml = (str) => {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  };

  combinedResults.forEach((item, i) => {
    const div = document.createElement("div");
    const isSelected = i === selectedCommandIndex;
    div.className = `px-4 py-3 my-1 flex justify-between items-center rounded-md cursor-pointer transition-colors ${isSelected ? "bg-primary-50 text-primary" : "text-slate-600 hover:bg-slate-100"}`;
    div.innerHTML = `<div class="flex items-center gap-3"><span class="text-xl">${item.icon}</span><span class="font-medium tracking-wide truncate">${escapeHtml(item.title)}</span></div>`;
    div.onclick = () => {
      toggleCommandPalette();
      item.action();
    };
    list.appendChild(div);
  });
}

document.addEventListener("keydown", (e) => {
  const target = e.target;
  const isInputFocused = target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable;

  // Handle list navigation when command palette is open.
  if (isCommandPaletteOpen) {
    if (e.key === "Escape") {
      const input = document.getElementById("cmd-input");
      if (input && input.value !== "") {
        input.value = "";
        renderCommandList("");
        return;
      }
      toggleCommandPalette();
      return;
    }
    const input = document.getElementById("cmd-input");
    const filtered = getCommandSearchResults(input.value);

    if (filtered.length > 0) {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        selectedCommandIndex = (selectedCommandIndex + 1) % filtered.length;
        renderCommandList(input.value);
        document.querySelector('#cmd-list > div:nth-child(' + (selectedCommandIndex + 1) + ')')?.scrollIntoView({ block: 'nearest' });
        return;
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        selectedCommandIndex = (selectedCommandIndex - 1 + filtered.length) % filtered.length;
        renderCommandList(input.value);
        document.querySelector('#cmd-list > div:nth-child(' + (selectedCommandIndex + 1) + ')')?.scrollIntoView({ block: 'nearest' });
        return;
      } else if (e.key === "Enter" && filtered[selectedCommandIndex]) {
        if (e.isComposing) return;
        e.preventDefault();
        toggleCommandPalette();
        filtered[selectedCommandIndex].action();
        return;
      }
    }
    return; // Ignore other shortcuts while command palette is open.
  }

  // Handle global shortcuts even during form input (Cmd/Ctrl + S, O, K).
  if (e.metaKey || e.ctrlKey) {
    const key = e.key.toLowerCase();
    if (key === "s") {
      e.preventDefault();
      saveQRCoderFile();
      return;
    }
    if (key === "o") {
      e.preventDefault();
      loadQRCoderFile();
      return;
    }
    if (key === "k") {
      e.preventDefault();
      const app = window.$app;
      if (app && (app.showSaveModal || app.showShareModal || app.showDownloadModal || app.showUrlExportModal || app.showSceneModal || app.showPromptModal || app.showImportModal || app.showBulkMoveModal || app.showBulkTagModal || app.showQaModal || app.showUtmPresetManager)) {
        return;
      }
      toggleCommandPalette();
      return;
    }
    // Undo / Redo shortcuts (only when not typing in an input field)
    if (!isInputFocused) {
      if (key === "z") {
        e.preventDefault();
        const app = window.$app;
        if (app && app.currentView === 'generator') {
          if (e.shiftKey) {
            app.redo();
          } else {
            app.undo();
          }
          app.hapticFeedback('light');
        }
        return;
      }
      if (key === "y" && !e.metaKey) { // Redo for Windows (Ctrl+Y)
        e.preventDefault();
        const app = window.$app;
        if (app && app.currentView === 'generator') {
          app.redo();
          app.hapticFeedback('light');
        }
        return;
      }
    }
  }

  // Disable other single-key shortcuts when input form is focused (except Escape).
  if (isInputFocused && e.key !== "Escape") {
    return;
  }

  if (e.key === "Escape") {
    const app = window.$app;
    if (app && (app.showSaveModal || app.showShareModal || app.showDownloadModal || app.showUrlExportModal || app.showSceneModal || app.showPromptModal)) {
      return;
    }
  }
});

document.addEventListener("DOMContentLoaded", () => {
  const isMac = navigator.userAgent.toLowerCase().includes("mac") || navigator.platform.toLowerCase().includes("mac");
  const shortcutEl = document.getElementById("cmd-shortcut-key");
  if (shortcutEl) {
    shortcutEl.textContent = isMac ? "⌘K" : "Ctrl+K";
  }

  // Prevent accidental screen transition (data loss) caused by dropping outside.
  const dropzone = document.getElementById("global-dropzone");
  let dragCounter = 0;

  window.addEventListener("dragenter", (e) => {
    e.preventDefault();
    dragCounter++;

    if (window.$app && window.$app.showImportModal) return;

    if (dropzone) {
      dropzone.classList.remove("hidden");
      dropzone.classList.add("flex");
    }
  });

  window.addEventListener("dragleave", (e) => {
    e.preventDefault();
    dragCounter--;
    if (dragCounter === 0 && dropzone) {
      dropzone.classList.add("hidden");
      dropzone.classList.remove("flex");
    }
  });

  window.addEventListener("dragover", (e) => {
    e.preventDefault();
  });
  window.addEventListener("drop", (e) => {
    e.preventDefault();
    dragCounter = 0;
    if (dropzone) {
      dropzone.classList.add("hidden");
      dropzone.classList.remove("flex");
    }
    // Auto-import magic or Scanner image drop
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      // Check if we are in scanner mode and at least one file is an image
      const hasImages = Array.from(e.dataTransfer.files).some(file => file.type.startsWith('image/'));

      if (window.$app && window.$app.currentView === 'scanner' && hasImages) {
        // Filter out non-image files if any, and pass the array of image files
        const imageFiles = Array.from(e.dataTransfer.files).filter(file => file.type.startsWith('image/'));
        const syntheticEvent = { target: { files: imageFiles, value: '' } };
        window.$app.scanFromImage(syntheticEvent);
        return;
      }

      const file = e.dataTransfer.files[0];
      if (file.name.endsWith('.qrcoder') || file.name.endsWith('.qrcoder-theme')) {
        if (file.name.endsWith('.qrcoder')) fileHandle = { name: file.name };
        if (window.$app && typeof processQRCoderFile === 'function') {
          processQRCoderFile(file);
        }
      } else {
        if (window.$app) {
          window.$app.showFlashNotification("❌ Invalid file. Please drop a .qrcoder backup file or drop images while in the Verify tab.");
          window.$app.hapticFeedback('error');
        }
      }
    }
  });

  // Handle OS drag cancel or Escape key leaving dropzone stuck
  window.addEventListener("click", () => {
    dragCounter = 0;
    if (dropzone) {
      dropzone.classList.add("hidden");
      dropzone.classList.remove("flex");
    }
  });

  // CSP-compliant event listeners
  const btnTogglePassword = document.querySelector('button[aria-label="Toggle password visibility"]');
  if (btnTogglePassword) btnTogglePassword.addEventListener('click', togglePasswordVisibility);

  const btnLoadFile = document.querySelector('button[aria-label="Open Backup"]');
  if (btnLoadFile) btnLoadFile.addEventListener('click', loadQRCoderFile);

  const btnCmdPalette = document.querySelector('button[aria-label="Open Command Palette"]');
  if (btnCmdPalette) btnCmdPalette.addEventListener('click', toggleCommandPalette);

  const cmdPalette = document.getElementById("cmd-palette");
  if (cmdPalette) cmdPalette.addEventListener('click', toggleCommandPalette);

  const cmdPaletteContent = document.getElementById("cmd-palette-content");
  if (cmdPaletteContent) cmdPaletteContent.addEventListener('click', (e) => e.stopPropagation());

  const cmdInput = document.getElementById("cmd-input");
  if (cmdInput) cmdInput.addEventListener('input', window.handleCommandInput);

  // Handle PWA File Handling API (launch via double-click).
  if ('launchQueue' in window) {
    window.launchQueue.setConsumer(async (launchParams) => {
      if (!launchParams.files || launchParams.files.length === 0) return;
      const fileHandleParams = launchParams.files[0];

      try {
        const file = await fileHandleParams.getFile();
        fileHandle = fileHandleParams; // Set globally to enable overwrite save.

        let attempts = 0;
        const maxAttempts = 50; // Max wait 5 seconds.

        // Poll safely to wait for app initialization.
        const checkAppReady = setInterval(() => {
          attempts++;

          if (window.$app && window.$app._isInitialized) {
            clearInterval(checkAppReady);
            if (typeof processQRCoderFile === 'function') {
              processQRCoderFile(file);
            }
          } else if (attempts > maxAttempts) {
            clearInterval(checkAppReady);
            console.error("Failed to auto-load file due to timeout.");
          }
        }, 100);
      } catch (e) {
        console.error("Failed to auto-load file", e);
      }
    });
  }

  // Warn about unsaved changes before closing tab or browser (Fail-safe).
  window.addEventListener("beforeunload", (e) => {
    if (isDirty || (window.$app && window.$app.hasUnsavedEdit)) {
      e.preventDefault();
      e.returnValue = "";
    }
  });
});

// Expose for Alpine.js x-data
window.qrCodeGenerator = qrCodeGenerator;
window.saveQRCoderFile = saveQRCoderFile;

// Manage all QR code generator features in this Alpine.js component.
function qrCodeGenerator() {
  // Define initial QR code design options.
  const defaultQrOptions = {
    colorType: "single",
    foregroundColor: "#000000",
    backgroundColor: "#ffffff",
    cornerColor: "#000000",
    cornerDotColor: "#000000",
    gradient: {
      type: "linear",
      rotation: "0",
      color1: "#6366f1",
      color2: "#a855f7",
    },
    dotsStyle: "rounded",
    cornersStyle: "extra-rounded",
    cornersDotStyle: "dot",
    errorCorrectionLevel: "H",
    logo: "",
    margin: 20,
    imageOptions: {
      hideBackgroundDots: true,
      imageSize: 0.3, // Set initial size slightly larger.
      margin: 6, // Set initial margin slightly wider.
    },
  };

  // Define initial data structures for each QR code type.
  const defaultFormData = {
    url: {
      address: "https://www.grinds.jp",
      utm: { source: "", medium: "", campaign: "", term: "", content: "" },
      variations: []
    },
    text: {
      content: "",
    },
    wifi: {
      ssid: "",
      password: "",
      encryption: "WPA/WPA2",
      hidden: false,
    },
    vcard: {
      firstName: "",
      lastName: "",
      organization: "",
      phone: "",
      email: "",
      address: "",
    },
    event: {
      summary: "",
      location: "",
      start: "",
      end: "",
      description: "",
    },
    email: {
      to: "",
      subject: "",
      body: "",
    },
    geo: {
      latitude: "",
      longitude: "",
    },
    sns: {
      service: "x",
      identifier: "",
      message: "",
    },
    sms: {
      phone: "",
      message: "",
    },
    crypto: {
      currency: "bitcoin",
      address: "",
    },
    images: {
      url: "",
    },
    video: {
      url: "",
    },
  };

  return {
    // --- Manage UI display states ---
    subOpen: true, // Toggle side menu state.
    isSavingBackup: false, // Track backup saving state for UI button.
    isSaveSuccess: false,
    currentView: "generator", // 'generator' (create) or 'dashboard' (manage).
    hasUnsavedEdit: false, // Track unsaved form edits.
    currentStep: "typeSelection", // Track current step in generator.
    selectedType: "url", // Track selected QR code type.
    activeStepTab: "content", // Track active tab in generator ('content', 'design', 'logo').
    showNotification: false, // Toggle notification display.
    isUpdateNotification: false, // Track if notification is an app update
    notificationMessage: "", // Store notification message.
    showDownloadModal: false, // Toggle modal states.
    showUrlExportModal: false,
    showSaveModal: false,
    showShareModal: false,
    showSceneModal: false,
    showPromptModal: false,
    promptMessage: "",
    promptInput: "",
    promptInputType: "password",
    resolvePrompt: null,
    copied: false, // Track copy button state.
    showRawData: false, // Toggle raw data inspector.
    copiedRaw: false, // Track raw data copy state.
    rawDataString: "", // Store raw data string.
    notificationTimeout: null, // Manage notification timeout.
    draftTimer: null, // Manage auto-save draft timeout.
    includeQuietZone: true, // Toggle quiet zone (margin).
    isUpdatingPreview: false, // Flag for breathing effect during preview update.
    previewUpdateTimeout: null,
    editingQRCodeId: null, // Store ID of QR code being edited.
    saveName: "", // Store save name.
    saveMemo: "", // Store save memo.
    saveTags: "", // Store comma-separated tags.
    qrToShare: {}, // Store data for share modal.

    // --- Bulk Download Status ---
    selectedIds: [],
    isBulkDownload: false, // Track if download modal is for bulk ZIP
    isExportingBulk: false,
    exportProgress: "",

    // --- Bulk Edit Status ---
    showBulkMoveModal: false,
    bulkMoveTargetProject: 'default',
    showBulkTagModal: false,
    bulkTagInput: '',
    bulkTagMode: 'add', // 'add', 'replace', 'remove'

    // --- Bulk Import from CSV ---
    showImportModal: false,
    csvFile: null,
    csvHeaders: [],
    csvData: [], // Real data excluding headers
    csvMapping: { name: "", memo: "", tags: "", dynamic: {} },
    importTargetProject: "default",
    isImporting: false,
    importProgress: 0,

    // --- Manage QR code and application data ---
    qrCodeInstance: null, // Store QR code library instance.
    logoFileName: "", // Store uploaded logo filename.
    qrQuality: {
      score: 100,
      issues: [],
      evaluations: [],
      minSize: 0,
      densityVersion: 1
    }, // QR code quality score.
    urlError: "", // Store URL input error message.
    brandKits: [], // Array to store multiple client brand kits.
    activeBrandKitId: null, // Currently active brand kit ID.
    history: [], // Store operation history for undo/redo.
    historyIndex: -1,
    savedQRCodes: [], // Store saved QR code list.
    myTemplates: [], // Store custom design templates.
    projects: [{ id: 'default', name: 'Default Project', isDefault: true, createdAt: new Date().toISOString() }], // Store project folders.
    currentProjectId: 'all', // Track currently selected project ('all' or specific projectId).
    viewMode: 'grid', // 'grid' or 'table' view for dashboard.
    saveProjectId: 'default', // ID of project selected in save modal

    // --- UTM Presets ---
    utmPresets: [], // Stored in localStorage (like brandKits).
    showUtmPresetManager: false, // Toggle preset management modal.

    // --- QA / Pre-Download Verification ---
    showQaModal: false,
    qaCurrentQr: null,

    // --- QR Scanner (Verify Tab) ---
    scannerResults: [], // Array of { id, text, timestamp, isUrl }
    isScannerActive: false, // Camera toggle
    scannerInstance: null, // html5-qrcode instance reference

    // --- Manage dashboard pagination and sorting ---
    sortKey: "createdAt",
    sortOrder: "desc",
    itemsPerPage: 5,
    currentPage: 1,
    searchQuery: "", // Search query for dashboard filtering.
    activeTypeFilter: "all", // Active filter for QR code types

    // --- Static application data ---
    presetLogos: ["ICON_GOOGLE_MAPS.png", "ICON_FACEBOOK.png", "ICON_INSTAGRAM.png", "ICON_TIKTOK.png", "ICON_X.png", "ICON_ZOOM.png"],
    qrTypes: [
      {
        id: "url",
        title: "Website URL",
        description: "Link to any website.",
        icon: "link",
      },
      {
        id: "text",
        title: "Text",
        description: "Display plain text.",
        icon: "bars-3-bottom-left",
      },
      {
        id: "wifi",
        title: "Wi-Fi",
        description: "Connect to a network.",
        icon: "wifi",
      },
      {
        id: "vcard",
        title: "Contact (vCard)",
        description: "Share contact information.",
        icon: "user-circle",
      },
      {
        id: "event",
        title: "Calendar",
        description: "Share an event.",
        icon: "calendar-days",
      },
      {
        id: "email",
        title: "Email",
        description: "Prompt email creation.",
        icon: "envelope",
      },
      {
        id: "sms",
        title: "SMS / Text",
        description: "Send an SMS message.",
        icon: "chat-bubble-oval-left-ellipsis",
      },
      {
        id: "geo",
        title: "Location",
        description: "Share a specific location.",
        icon: "map-pin",
      },
      {
        id: "crypto",
        title: "Crypto",
        description: "Receive cryptocurrency.",
        icon: "qr-code",
      },
      {
        id: "sns",
        title: "SNS",
        description: "Share SNS profile.",
        icon: "share",
      },
      {
        id: "images",
        title: "Image Gallery",
        description: "Convert shared album links from Google Photos etc. into a QR code.",
        icon: "photo",
      },
      {
        id: "video",
        title: "Video",
        description: "Convert video sharing links from YouTube etc. into a QR code.",
        icon: "video-camera",
      },
    ],
    formData: JSON.parse(JSON.stringify(defaultFormData)),
    qrOptions: JSON.parse(JSON.stringify(defaultQrOptions)),
    frame: {
      style: "none",
      text: "SCAN ME",
    },
    download: {
      format: "png",
      size: 1024,
      fileName: "grinds-qr-code",
      zipName: "QR_Export",
      transparentBg: false,
    },
    frameStyles: [
      {
        id: "scan-me-1",
        name: "Text",
        preview: "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTgwIiBoZWlnaHQ9IjIwMCIgdmlld0JveD0iMCAwIDE4MCAyMDAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHJlY3Qgd2lkdGg9IjE4MCIgaGVpZ2h0PSIxODAiIGZpbGw9IiNmMmY0ZjkiLz48dGV4dCB4PSI5MCIgeT0iMTkwIiBkb21pbmFudC1iYXNlbGluZT0iY2VudHJhbCIgZm9udC1mYW1pbHk9InNhbnMtc2VyaWYiIGZvbnQtc2l6ZT0iMTYiIGZvbnQtd2VpZ2h0PSJib2xkIiBmaWxsPSIjMWUyOTNiIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5DVEFURVhUPC90ZXh0Pjwvc3ZnPg==",
      },
      {
        id: "scan-me-2",
        name: "Box",
        preview: "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTgwIiBoZWlnaHQ9IjIyMCIgdmlld0JveD0iMCAwIDE4MCAyMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHJlY3Qgd2lkdGg9IjE4MCIgaGVpZ2h0PSIxODAiIGZpbGw9IiNmMmY0ZjkiLz48cmVjdCB4PSIzMCIgeT0iMTgwIiB3aWR0aD0iMTIwIiBoZWlnaHQ9IjMwIiByeD0iOCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMWUyOTNiIiBzdHJva2Utd2lkdGg9IjIiLz48dGV4dCB4PSI5MCIgeT0iMTk1IiBkb21pbmFudC1iYXNlbGluZT0iY2VudHJhbCIgZm9udC1mYW1pbHk9InNhbnMtc2VyaWYiIGZvbnQtc2l6ZT0iMTYiIGZvbnQtd2VpZ2h0PSJib2xkIiBmaWxsPSIjMWUyOTNiIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5DVEFURVhUPC90ZXh0Pjwvc3ZnPg==",
      },
      {
        id: "scan-me-3",
        name: "With Background",
        preview: "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTgwIiBoZWlnaHQ9IjIyMCIgdmlld0JveD0iMCAwIDE4MCAyMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHJlY3Qgd2lkdGg9IjE4MCIgaGVpZ2h0PSIxODAiIGZpbGw9IiNmMmY0ZjkiLz48cmVjdCB4PSIwIiB5PSIxODAiIHdpZHRoPSIxODAiIGhlaWdodD0iNDAiIGZpbGw9IiMxZTI5M2IiLz48dGV4dCB4PSI5MCIgeT0iMjAwIiBkb21pbmFudC1iYXNlbGluZT0iY2VudHJhbCIgZm9udC1mYW1pbHk9InNhbnMtc2VyaWYiIGZvbnQtc2l6ZT0iMTYiIGZvbnQtd2VpZ2h0PSJib2xkIiBmaWxsPSIjRkZGIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5DVEFURVhUPC90ZXh0Pjwvc3ZnPg==",
      },
    ],
    previewScene: "default",
    mainSceneBackgroundUrl: "",
    mainSceneOptions: {
      scale: 1,
      x: 0,
      y: 0,
      rotation: 0,
    },
    scenePresets: {
      poster: {
        scale: 0.5,
        x: 0,
        y: 30,
        rotation: -10,
        backgroundUrl: "poster.jpg",
      },
      card: {
        scale: 0.4,
        x: 35,
        y: 25,
        rotation: 0,
        backgroundUrl: "card.png",
      },
      custom: {
        scale: 0.7,
        x: 0,
        y: 0,
        rotation: 0,
        backgroundUrl: `data:image/svg+xml,%3csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%22400%22 height=%22400%22 viewBox=%220 0 400 400%22%3e%3crect width=%22380%22 height=%22380%22 x=%2210%22 y=%2210%22 fill=%22%23f1f5f9%22 stroke=%22%239ca3af%22 stroke-width=%222%22 stroke-dasharray=%228 8%22 rx=%2215%22/%3e%3ctext x=%2250%25%22 y=%2250%25%22 dominant-baseline=%22middle%22 text-anchor=%22middle%22 font-family=%22sans-serif%22 font-size=%2220px%22 fill=%22%2364748b%22%3eUpload Photo Here%3c/text%3e%3c/svg%3e`,
      },
    },
    dotStyles: [
      {
        id: "square",
        name: "Square",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><rect width="100" height="100" fill="currentColor"/></svg>',
      },
      {
        id: "rounded",
        name: "Rounded",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><rect width="100" height="100" rx="30" fill="currentColor"/></svg>',
      },
      {
        id: "dots",
        name: "Dots",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><circle cx="50" cy="50" r="50" fill="currentColor"/></svg>',
      },
      {
        id: "classy",
        name: "Classy",
        svg: '<svg width="42" height="42" viewBox="0 0 100 100"><path d="M50 0A50 50 0 0 0 0 50A50 50 0 0 0 50 100A50 50 0 0 0 100 50A50 50 0 0 0 50 0M50 15A35 35 0 0 1 85 50A35 35 0 0 1 50 85A35 35 0 0 1 15 50A35 35 0 0 1 50 15" fill-rule="evenodd" fill="currentColor"/></svg>',
      },
      {
        id: "classy-rounded",
        name: "Classy (Rounded)",
        svg: '<svg width="42" height="42" viewBox="0 0 100 100"><path d="M50 0A50 50 0 0 0 0 50A50 50 0 0 0 50 100A50 50 0 0 0 100 50A50 50 0 0 0 50 0M50 25A25 25 0 0 1 75 50A25 25 0 0 1 50 75A25 25 0 0 1 25 50A25 25 0 0 1 50 25" fill-rule="evenodd" fill="currentColor"/></svg>',
      },
      {
        id: "extra-rounded",
        name: "Extra Rounded",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><rect width="100" height="100" rx="50" fill="currentColor"/></svg>',
      },
    ],
    cornerStyles: [
      {
        id: "square",
        name: "Square",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><rect width="90" height="90" x="5" y="5" stroke-width="10" stroke="currentColor" fill="none"/></svg>',
      },
      {
        id: "dot",
        name: "Dot",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><rect width="90" height="90" x="5" y="5" stroke-width="10" stroke="currentColor" fill="none" rx="45"/></svg>',
      },
      {
        id: "extra-rounded",
        name: "Rounded",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><rect width="90" height="90" x="5" y="5" stroke-width="10" stroke="currentColor" fill="none" rx="25"/></svg>',
      },
    ],
    cornerDotStyles: [
      {
        id: "square",
        name: "Square",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><rect width="50" height="50" x="25" y="25" fill="currentColor"/></svg>',
      },
      {
        id: "extra-rounded",
        name: "Rounded",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><rect width="50" height="50" x="25" y="25" rx="15" fill="currentColor"/></svg>',
      },
      {
        id: "dot",
        name: "Dot",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><circle cx="50" cy="50" r="25" fill="currentColor"/></svg>',
      },
    ],
    colorPalettes: [
      {
        name: "Default",
        fg: "#000000",
        bg: "#ffffff",
      },
      {
        name: "Slate",
        fg: "#475569",
        bg: "#ffffff",
      },
      {
        name: "Dark",
        fg: "#ffffff",
        bg: "#1e293b",
      },
      {
        name: "Indigo",
        fg: "#3c366b",
        bg: "#f5f3ff",
      },
      {
        name: "Rose",
        fg: "#9f1239",
        bg: "#fff1f2",
      },
      {
        name: "Green",
        fg: "#065f46",
        bg: "#ecfdf5",
      },
    ],
    presetTemplates: [],
    presetTemplateGroups: [],

    // --- Computed Properties ---
    get activeTypeFields() {
      switch(this.selectedType) {
        case 'url': return [{ key: 'url', label: 'URL', required: true }];
        case 'text': return [{ key: 'content', label: 'Text Content', required: true }];
        case 'wifi': return [
            { key: 'ssid', label: 'Network Name (SSID)', required: true },
            { key: 'password', label: 'Password', required: false },
            { key: 'encryption', label: 'Encryption (WPA/WEP/None)', required: false },
            { key: 'hidden', label: 'Hidden Network (true/false)', required: false }
          ];
        case 'vcard': return [
            { key: 'lastName', label: 'Last Name', required: true },
            { key: 'firstName', label: 'First Name', required: false },
            { key: 'organization', label: 'Company', required: false },
            { key: 'phone', label: 'Phone', required: false },
            { key: 'email', label: 'Email', required: false },
            { key: 'address', label: 'Address', required: false }
          ];
        case 'event': return [
            { key: 'summary', label: 'Event Name', required: true },
            { key: 'location', label: 'Location', required: false },
            { key: 'start', label: 'Start Date (YYYY-MM-DD HH:mm)', required: true },
            { key: 'end', label: 'End Date (YYYY-MM-DD HH:mm)', required: true },
            { key: 'description', label: 'Description', required: false }
          ];
        case 'email': return [
            { key: 'to', label: 'To Email', required: true },
            { key: 'subject', label: 'Subject', required: false },
            { key: 'body', label: 'Body', required: false }
          ];
        case 'sms': return [
            { key: 'phone', label: 'Phone Number', required: true },
            { key: 'message', label: 'Message', required: false }
          ];
        case 'crypto': return [
            { key: 'currency', label: 'Currency (bitcoin/ethereum)', required: true },
            { key: 'address', label: 'Wallet Address', required: true }
          ];
        case 'geo': return [
            { key: 'latitude', label: 'Latitude', required: true },
            { key: 'longitude', label: 'Longitude', required: true }
          ];
        case 'sns': return [
            { key: 'service', label: 'Service (x, instagram, etc.)', required: true },
            { key: 'identifier', label: 'Username/ID', required: true },
            { key: 'message', label: 'Prefilled Message', required: false }
          ];
        case 'images': return [{ key: 'url', label: 'Album URL', required: true }];
        case 'video': return [{ key: 'url', label: 'Video URL', required: true }];
        default: return [];
      }
    },
    get isUrlLong() {
      const dataLength = this.getQrDataString().trim().length;
      const isUrlBasedType = ['url', 'images', 'video', 'sns', 'geo'].includes(this.selectedType);
      return isUrlBasedType && dataLength > 80;
    },
    // Return list filtered by search query.
    get filteredQRCodes() {
      if (!this.savedQRCodes) return [];
      let filtered = this.savedQRCodes;

      if (this.currentProjectId && this.currentProjectId !== 'all') {
        filtered = filtered.filter(qr => (qr.projectId || 'default') === this.currentProjectId);
      }

      // Filter by QR code type
      if (this.activeTypeFilter && this.activeTypeFilter !== 'all') {
        filtered = filtered.filter(qr => qr.type === this.activeTypeFilter);
      }

      if (this.searchQuery.trim() !== "") {
        const searchTerms = this.searchQuery.toLowerCase().trim().split(/\s+/).filter(Boolean);
        filtered = filtered.filter(qr => {
          const nameStr = (qr.name || "").toLowerCase();
          const memoStr = (qr.memo || "").toLowerCase();
          const tagsArray = Array.isArray(qr.tags) ? qr.tags : (typeof qr.tags === 'string' ? qr.tags.split(',') : []);
          const tagsStr = tagsArray.join(" ").toLowerCase();
          const combinedText = `${nameStr} ${memoStr} ${tagsStr}`;

          // Check if all input keywords (AND condition) are included in the text.
          return searchTerms.every(term => combinedText.includes(term));
        });
      }
      return filtered;
    },
    // Calculate sorted and paginated items to display.
    get displayedItems() {
      const sorted = [...this.filteredQRCodes].sort((a, b) => {
        // Favorites always on top
        if (a.isFavorite && !b.isFavorite) return -1;
        if (!a.isFavorite && b.isFavorite) return 1;

        let valA = a[this.sortKey];
        let valB = b[this.sortKey];

        let comparison = 0;
        if (this.sortKey === 'createdAt' || this.sortKey === 'updatedAt') {
          comparison = new Date(valA).getTime() - new Date(valB).getTime();
        } else if (typeof valA === 'string' && typeof valB === 'string') {
          comparison = valA.localeCompare(valB, undefined, { sensitivity: 'base', numeric: true });
        } else {
          if (valA > valB) comparison = 1;
          else if (valA < valB) comparison = -1;
        }
        return this.sortOrder === "asc" ? comparison : -comparison;
      });
      const start = (this.currentPage - 1) * this.itemsPerPage;
      const end = start + this.itemsPerPage;
      return sorted.slice(start, end);
    },
    // Calculate total pages.
    get totalPages() {
      return Math.max(1, Math.ceil(this.filteredQRCodes.length / this.itemsPerPage));
    },
    // Calculate page numbers array for pagination.
    get pageNumbers() {
      if (this.totalPages <= 7) {
        return Array.from(
          {
            length: this.totalPages,
          },
          (_, i) => i + 1
        );
      }
      const pages = new Set();
      pages.add(1);
      pages.add(this.totalPages);
      for (let i = this.currentPage - 2; i <= this.currentPage + 2; i++) {
        if (i > 1 && i < this.totalPages) {
          pages.add(i);
        }
      }
      const result = Array.from(pages).sort((a, b) => a - b);
      const withEllipsis = [];
      let last = 0;
      for (const page of result) {
        if (page - last > 1) {
          withEllipsis.push(null);
        }
        withEllipsis.push(page);
        last = page;
      }
      return withEllipsis;
    },

    // Extract and sort all unique tags from saved QR codes.
    get allTags() {
      const tagMap = {};
      this.savedQRCodes.forEach(qr => {
        const tags = Array.isArray(qr.tags) ? qr.tags : (typeof qr.tags === 'string' ? qr.tags.split(',') : []);
        tags.forEach(t => {
          const cleanTag = String(t).trim();
          if (cleanTag) {
            tagMap[cleanTag] = (tagMap[cleanTag] || 0) + 1;
          }
        });
      });
      return Object.entries(tagMap)
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count);
    },

    // Get active QR code types for filtering buttons (auto-calculated)
    get activeTypes() {
      if (!this.savedQRCodes) return [];
      const typeMap = {};
      this.savedQRCodes.forEach(qr => {
        // Only count types that exist in the currently selected project
        if (this.currentProjectId !== 'all' && (qr.projectId || 'default') !== this.currentProjectId) return;
        if (qr.type) typeMap[qr.type] = (typeMap[qr.type] || 0) + 1;
      });
      return Object.entries(typeMap)
        .map(([id, count]) => {
          const typeDef = this.qrTypes.find(t => t.id === id);
          return {
            id,
            title: typeDef ? typeDef.title : id,
            icon: typeDef ? typeDef.icon : 'qr-code',
            count
          };
        }).sort((a, b) => b.count - a.count);
    },

    // Check if all items on the current page are selected.
    isAllSelected() {
      if (this.displayedItems.length === 0) return false;
      return this.displayedItems.every(qr => this.selectedIds.includes(qr.id));
    },
    // Toggle selection for all items on the current page.
    toggleSelectAll() {
      const currentIds = this.displayedItems.map(qr => qr.id);
      if (this.isAllSelected()) {
        this.selectedIds = this.selectedIds.filter(id => !currentIds.includes(id));
      } else {
        const newIds = currentIds.filter(id => !this.selectedIds.includes(id));
        this.selectedIds = [...this.selectedIds, ...newIds];
      }
    },

    // --- Clipboard Fallback Helper ---
    async copyToTextClipboard(text) {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.position = "absolute";
        const yPosition = window.pageYOffset || document.documentElement.scrollTop;
        textArea.style.top = yPosition + "px";
        textArea.style.left = "-999999px";
        document.body.appendChild(textArea);
        textArea.focus({ preventScroll: true });
        textArea.select();
        if (textArea.setSelectionRange) {
          textArea.setSelectionRange(0, 99999); // iOS Safari fallback
        }
        try {
          document.execCommand('copy');
        } catch (error) {
          console.error("Copy fallback failed", error);
        } finally {
          textArea.remove();
        }
      }
    },

    // --- Haptic feedback ---
    hapticFeedback(type = 'light') {
      if (!navigator.vibrate) return;
      if (type === 'light') navigator.vibrate(10);
      if (type === 'success') navigator.vibrate([15, 50, 15]);
      if (type === 'error') navigator.vibrate([30, 50, 30, 50, 30]);
    },

    // --- Initialization and core functions ---
    // Initialize application on page load.
    async init() {
      window.$app = this;

      // Wait for web fonts to load to ensure accurate text width calculation.
      if ("fonts" in document) {
        try {
          await document.fonts.ready;
        } catch (e) {
          console.warn("Font loading timeout or error", e);
        }
      }

      // Handle Web Share Target API or URL parameter inputs.
      const params = new URLSearchParams(window.location.search);
      let sharedContent = params.get('url') || params.get('text') || params.get('title') || "";
      if (sharedContent) {
        let finalTarget = sharedContent.trim();
        // Extract URL if included in shared text.
        const urlMatch = sharedContent.match(/(https?:\/\/[^\s]+)/i);

        if (urlMatch) {
          this.selectedType = 'url';
          this.formData.url.address = urlMatch[0];
        } else {
          this.selectedType = 'text';
          this.formData.text.content = finalTarget;
        }
        window.history.replaceState({}, document.title, window.location.pathname);
      }

      this.generatePresetTemplates();
      this.loadBrandKit();
      this.loadUtmPresets();
      this.mainSceneBackgroundUrl = this.scenePresets.custom.backgroundUrl;
      await this.loadProjects();
      await this.loadSavedQRCodes();
      await this.loadMyTemplates();
      await this.checkAndRestoreDraft();

      // Force open generator if started with shared data.
      if (sharedContent) {
        this.currentView = 'generator';
        this.currentStep = 'contentEntry';
        this.$nextTick(() => { this.updateQrCode(false); });
      }

      this.initQrCode();
      this.validateUrl();

      // Dynamically darken status bar when modal opens (UX Polish).
      const metaTheme = document.getElementById("meta-theme-color");
      const updateThemeColor = (isOpen) => {
        if (metaTheme) metaTheme.setAttribute("content", isOpen ? "#111827" : "#f8fafc");
      };
      this.$watch('showSaveModal', updateThemeColor);
      this.$watch('showShareModal', updateThemeColor);
      this.$watch('showDownloadModal', updateThemeColor);
      this.$watch('showUrlExportModal', updateThemeColor);
      this.$watch('showSceneModal', updateThemeColor);
      this.$watch('showPromptModal', updateThemeColor);

      // Prevent and control exit via browser back (swipe back) using History API.
      window.addEventListener('popstate', (e) => {
        // Prioritize closing modals if any are open.
        if (this.showSaveModal || this.showShareModal || this.showDownloadModal || this.showUrlExportModal || this.showSceneModal || this.showPromptModal) {
          this.showSaveModal = false;
          this.showShareModal = false;
          this.showDownloadModal = false;
          this.showUrlExportModal = false;
          this.showSceneModal = false;
          if (this.showPromptModal) {
            this.showPromptModal = false;
            if (this.resolvePrompt) {
              this.resolvePrompt(null);
            }
          }
          history.pushState(null, '', location.href); // Push state again to prevent exit.
          return;
        }

        // Warn if there are unsaved edits; restore history if cancelled.
        if (this.hasUnsavedEdit) {
          if (!confirm('You have unsaved changes. Are you sure you want to leave?')) {
            history.pushState(null, '', location.href);
            return;
          }
          this.hasUnsavedEdit = false;
        }

        // Handle screen transition for back action.
        if (this.currentView === 'scanner') {
          this.currentView = 'dashboard';
        } else if (this.currentView === 'generator' && this.currentStep === 'contentEntry') {
          this.currentStep = 'typeSelection';
        } else if (this.currentView === 'dashboard') {
          this.currentView = 'generator';
          this.currentStep = 'typeSelection';
        }
      });

      document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
          if (this.currentView === 'scanner' && this.isScannerActive) {
            this.stopScanner();
            this.showFlashNotification("Camera paused to save battery.");
          }
          // Emergency draft save on tab close/background (Fail-safe)
          if (this.hasUnsavedEdit) {
            this.saveDraft();
          }
        }
      });

      this.$watch('currentStep', val => {
        if (val === 'contentEntry') history.pushState({ step: 'contentEntry' }, '', '');
      });
      this.$watch('currentView', val => {
        if (val === 'dashboard') history.pushState({ view: 'dashboard' }, '', '');
        if (val === 'scanner') history.pushState({ view: 'scanner' }, '', '');
        // Stop scanner when leaving scanner view.
        if (val !== 'scanner' && this.isScannerActive) {
          this.stopScanner();
        }
        window.scrollTo({ top: 0, behavior: 'smooth' });
      });

      // Reset unsaved flag after initial generation completes.
      this.$nextTick(() => {
        setTimeout(() => {
          if (typeof setDirty === 'function') setDirty(false);
          this.hasUnsavedEdit = false;
          this._isInitialized = true; // Set initialization flag.
          history.replaceState({ view: 'generator', step: 'typeSelection' }, '', location.href);
        }, 100);
      });
    },

    // Create QR code instance and render preview.
    initQrCode() {
      this.qrCodeInstance = new QRCodeStyling({
        width: 320,
        height: 320,
        type: "svg",
        data: this.formData.url.address,
        image: this.qrOptions.logo,
        dotsOptions: this.buildDotsOptions(),
        backgroundOptions: {
          color: this.qrOptions.backgroundColor,
        },
        cornersSquareOptions: this.buildCornersSquareOptions(),
        cornersDotOptions: this.buildCornersDotOptions(),
        imageOptions: this.qrOptions.imageOptions,
        qrOptions: {
          errorCorrectionLevel: this.qrOptions.errorCorrectionLevel,
        },
        margin: this.qrOptions.margin,
      });
      this.$nextTick(() => {
        this.$refs.qrCodeCanvas.innerHTML = "";
        this.qrCodeInstance.append(this.$refs.qrCodeCanvas);
        this.rawDataString = this.getQrDataString();
        this.checkQrQuality();
      });
    },

    normalizeColors() {
      const fixColor = (color, defaultColor) => {
        if (!color) return defaultColor;
        let hex = color.trim();
        if (/^[0-9A-F]{3,6}$/i.test(hex)) hex = '#' + hex;
        if (/^#[0-9A-F]{3}$/i.test(hex)) {
          hex = '#' + hex[1] + hex[1] + hex[2] + hex[2] + hex[3] + hex[3];
        }
        if (!/^#[0-9A-F]{6}$/i.test(hex)) return defaultColor;
        return hex;
      };
      this.qrOptions.foregroundColor = fixColor(this.qrOptions.foregroundColor, "#000000");
      this.qrOptions.backgroundColor = fixColor(this.qrOptions.backgroundColor, "#ffffff");
      this.qrOptions.cornerColor = fixColor(this.qrOptions.cornerColor, "#000000");
      this.qrOptions.cornerDotColor = fixColor(this.qrOptions.cornerDotColor, "#000000");
      if (this.qrOptions.gradient) {
        this.qrOptions.gradient.color1 = fixColor(this.qrOptions.gradient.color1, "#6366f1");
        this.qrOptions.gradient.color2 = fixColor(this.qrOptions.gradient.color2, "#a855f7");
      }
    },

    // Update QR code preview when settings change.
    updateQrCode(recordHistory = true) {
      if (!this.qrCodeInstance) return;

      this.hasUnsavedEdit = true;
      setDirty(true);

      // Exclude invalid logos (e.g., relative paths) saved by old bugs to prevent errors.
      if (this.qrOptions.logo && !this.qrOptions.logo.startsWith("data:")) {
        console.warn("Excluded invalid logo detected:", this.qrOptions.logo);
        this.qrOptions.logo = "";
        this.logoFileName = "";
      }

      this.checkQrQuality();

      // [Important] Unwrap Alpine.js proxy data into plain objects.
      // Separate large Base64 strings using spread syntax to prevent UI freezes (OOM crash) during deep copy.
      const rawOptions = window.Alpine.raw(this.qrOptions);
      const { logo, ...restOptions } = rawOptions;

      const plainOptions = JSON.parse(JSON.stringify(restOptions));
      plainOptions.logo = logo;

      // Fallback to prevent library crash from invalid background color.
      const fixHex = (c) => /^#?([0-9a-fA-F]{3,8})$/.test(c) ? (c.startsWith('#') ? c : '#' + c) : '#ffffff';

      // Create configuration object to pass to the library.
      const updateConfig = {
        data: this.getQrDataString(),

        // Image data
        image: plainOptions.logo,

        // Configure image size and margin options.
        imageOptions: {
          hideBackgroundDots: plainOptions.imageOptions.hideBackgroundDots,
          imageSize: plainOptions.imageOptions.imageSize,
          margin: plainOptions.imageOptions.margin,
        },

        // Other options
        dotsOptions: this.buildDotsOptions(),
        backgroundOptions: { color: fixHex(plainOptions.backgroundColor) },
        cornersSquareOptions: this.buildCornersSquareOptions(),
        cornersDotOptions: this.buildCornersDotOptions(),
        qrOptions: {
          errorCorrectionLevel: plainOptions.errorCorrectionLevel,
        },
        // Overall margin
        margin: plainOptions.margin,
      };

      try {
        this.qrCodeInstance.update(updateConfig);
        this.qrQuality.issues = this.qrQuality.issues.filter(i => i.id !== 'capacity_error');
      } catch (error) {
        console.error("QR Code generation failed:", error);
        this.qrQuality.score = 0;
        this.qrQuality.issues.push({
          id: 'capacity_error',
          status: "bad",
          message: "Data size exceeds QR code limits. Reduce text or use a dynamic QR (short URL)."
        });
        this.hapticFeedback('error');
        return;
      }
      this.rawDataString = updateConfig.data;

      // Re-render frame.
      this.applyFrame();
      if (this.qrOptions.logo) {
        // Wait briefly and re-render frame to prevent timing desync.
        setTimeout(() => this.applyFrame(), 50);
      }

      if (recordHistory) this.recordState();

      this.isUpdatingPreview = true;
      if (this.previewUpdateTimeout) clearTimeout(this.previewUpdateTimeout);
      this.previewUpdateTimeout = setTimeout(() => { this.isUpdatingPreview = false; }, 200);

      // Auto-save draft after 3 seconds of inactivity
      if (this.draftTimer) clearTimeout(this.draftTimer);
      this.draftTimer = setTimeout(() => {
        if (this.hasUnsavedEdit) this.saveDraft();
      }, 3000);
    },

    // --- Handle user interactions ---
    // Handle QR code type selection.
    selectType(typeId) {
      this.selectedType = typeId;
      this.currentStep = "contentEntry";
      this.$nextTick(() => {
        this.updateQrCode(false);
        this.history = [];
        this.historyIndex = -1;
        this.recordState();
        this.hasUnsavedEdit = false;
        if (typeof setDirty === 'function') setDirty(false);
      });
    },

    // Sort dashboard list.
    sortBy(key) {
      if (this.sortKey === key) {
        this.sortOrder = this.sortOrder === "asc" ? "desc" : "asc";
      } else {
        this.sortKey = key;
        this.sortOrder = "desc";
      }
      this.currentPage = 1;
    },

    // Change page in pagination.
    changePage(page) {
      if (page >= 1 && page <= this.totalPages) {
        this.currentPage = page;
      }
    },

    // Toggle favorite/pin status
    async toggleFavorite(id) {
      const qr = this.savedQRCodes.find((q) => q.id === id);
      if (qr) {
        qr.isFavorite = !qr.isFavorite;
        qr.updatedAt = new Date().toISOString();
        await this.persistSavedQRCodes();
        if (typeof setDirty === 'function') setDirty(true);

        if (qr.isFavorite) this.hapticFeedback('success');
        else this.hapticFeedback('light');
      }
    },

    // Apply design preset template.
    applyPreset(template) {
      this.qrOptions = JSON.parse(JSON.stringify(template.options));
      this.includeQuietZone = this.qrOptions.margin > 0;
      this.logoFileName = "";
      this.updateQrCode();
    },

    // --- File upload handling ---
    handleDrop(event, callbackName) {
      const files = event.dataTransfer.files;
      if (files && files.length > 0) {
        const fakeEvent = { target: { files: files } };
        if (typeof this[callbackName] === 'function') {
          this[callbackName](fakeEvent);
        }
      }
    },
    handleLogoUpload(event) {
      const file = event.target.files[0];
      if (!file) return;
      if (file.type === "image/svg+xml" && file.size > 500 * 1024) {
        this.showFlashNotification("SVG logos can be heavy to process if too complex. Please select a file smaller than 500KB.");
        event.target.value = "";
        return;
      }
      if (file.size > 2 * 1024 * 1024) {
        this.showFlashNotification("Please select a logo image smaller than 2MB.");
        event.target.value = "";
        return;
      }
      this.logoFileName = file.name;
      const reader = new FileReader();
      reader.onload = (e) => {
        this.qrOptions.logo = e.target.result;
        if (["L", "M"].includes(this.qrOptions.errorCorrectionLevel)) {
          this.qrOptions.errorCorrectionLevel = "H";
          this.showFlashNotification("Set Error Correction Level to 'High' to maintain logo readability.");
        }
        this.updateQrCode();
      };
      reader.onerror = () => {
        this.showFlashNotification("Failed to read the file. It may be locked or corrupted.");
        this.hapticFeedback('error');
      };
      reader.readAsDataURL(file);
      event.target.value = "";
    },

    // --- Save and Download processing ---
    // Copy image to clipboard.
    async copyImageToClipboard() {
      if (!this.qrCodeInstance) return;

      if (!navigator.clipboard || !window.ClipboardItem) {
        this.showFlashNotification("Your browser does not support copying images (HTTPS required). Please use download.");
        return;
      }

      const visibleCanvas = this.showSceneModal ? this.$refs.modalQrCanvas : this.$refs.qrCodeCanvas;
      const svgElement = visibleCanvas.querySelector("svg");
      if (!svgElement) return;

      const svgClone = svgElement.cloneNode(true);
      const svgViewBox = svgElement.viewBox.baseVal;
      const aspectRatio = svgViewBox.height > 0 ? svgViewBox.width / svgViewBox.height : 1;
      const canvasWidth = this.download.size;
      const canvasHeight = this.download.size / Math.max(aspectRatio, 0.0001);

      svgClone.setAttribute("width", `${canvasWidth}px`);
      svgClone.setAttribute("height", `${canvasHeight}px`);

      // Add required SVG namespaces (Fix for XMLSerializer bug / Illustrator compatibility).
      svgClone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
      svgClone.setAttribute("xmlns:xlink", "http://www.w3.org/1999/xlink");

      if (this.download.transparentBg) {
        const bgRect = Array.from(svgClone.children).find(el => el.tagName.toLowerCase() === 'rect');
        if (bgRect) {
          bgRect.setAttribute("fill", "transparent");
          bgRect.style.fill = "transparent";
        }
      }

      // Convert to static array using Array.from for dynamic DOM replacement.
      const imageTags = Array.from(svgClone.querySelectorAll("image, img"));
      let hasInvalidImage = false;

      for (let img of imageTags) {
        let href = img.getAttribute("href") || img.getAttribute("xlink:href") || img.getAttribute("src");
        if (href) {
          if (!href.startsWith("data:")) {
            img.remove();
            hasInvalidImage = true;
          } else if (img.tagName.toLowerCase() === 'img') {
            img.remove();
            hasInvalidImage = true;
          } else {
            // Ultimate Illustrator compatibility fix.
            // Inline Base64 SVG as raw vector DOM instead of falling back to PNG.
            if (href.startsWith("data:image/svg+xml")) {
              try {
                let svgString = "";
                if (href.includes("base64,")) {
                  const binStr = atob(href.split("base64,")[1].replace(/\s/g, ''));
                  const bytes = Uint8Array.from(binStr, c => c.charCodeAt(0));
                  svgString = new TextDecoder('utf-8').decode(bytes); // Prevent character corruption.
                } else {
                  svgString = decodeURIComponent(href.split(",")[1]);
                }

                // Sanitize with DOMPurify
                const cleanSvgString = DOMPurify.sanitize(svgString, { USE_PROFILES: { svg: true } });

                // Parse SVG element from string.
                const parser = new DOMParser();
                const doc = parser.parseFromString(cleanSvgString, "image/svg+xml");
                const innerSvg = doc.documentElement;

                if (innerSvg && innerSvg.tagName.toLowerCase() === "svg") {
                  // Transfer coordinates and dimensions from original <image> to expanded <svg>.
                  ['x', 'y', 'width', 'height'].forEach(attr => {
                    const val = img.getAttribute(attr);
                    if (val) innerSvg.setAttribute(attr, val);
                  });

                  // Explicitly set namespace for Illustrator.
                  innerSvg.setAttribute("xmlns", "http://www.w3.org/2000/svg");

                  // Replace <image> tag with full vector shapes (<svg>).
                  img.parentNode.replaceChild(innerSvg, img);
                  continue; // Continue to next loop if SVG inline succeeds.
                }
              } catch (e) {
                console.warn("Failed to inline vector SVG. Falling back.", e);
              }
            }

            // Attach legacy xlink:href for raster images like PNG/JPEG to ensure compatibility.
            img.removeAttribute("href");
            img.removeAttribute("xlink:href");
            img.setAttributeNS("http://www.w3.org/1999/xlink", "xlink:href", href);
          }
        } else {
          img.remove();
        }
      }

      try {
        const finalSvgString = new XMLSerializer().serializeToString(svgClone);

        // Use safe Blob URL with no size limit.
        const blob = new Blob([finalSvgString], { type: "image/svg+xml;charset=utf-8" });
        const safeSvgBlobUrl = URL.createObjectURL(blob);

        const blobPromise = new Promise((resolve, reject) => {
          try {
            const image = new Image();
            image.onload = () => {
              setTimeout(() => {
                const renderCanvas = document.createElement("canvas");
                renderCanvas.width = canvasWidth;
                renderCanvas.height = canvasHeight;
                const renderCtx = renderCanvas.getContext("2d");
                renderCtx.drawImage(image, 0, 0, canvasWidth, canvasHeight);
                renderCanvas.toBlob((pngBlob) => {
                  renderCanvas.width = 0;
                  renderCanvas.height = 0;
                  if (pngBlob) resolve(pngBlob);
                  else reject(new Error("Blob generation failed"));
                  URL.revokeObjectURL(safeSvgBlobUrl);
                }, "image/png");
              }, 50);
            };
            image.onerror = () => {
              URL.revokeObjectURL(safeSvgBlobUrl);
              reject(new Error("SVG Rendering Error"));
            };
            image.src = safeSvgBlobUrl;
          } catch (e) {
            URL.revokeObjectURL(safeSvgBlobUrl);
            reject(e);
          }
        });
        const clipboardItem = new window.ClipboardItem({
          "image/png": blobPromise
        });
        await navigator.clipboard.write([clipboardItem]);
        if (hasInvalidImage) {
          this.showFlashNotification("Excluded an invalid logo and copied the image to the clipboard.");
        } else {
          this.showFlashNotification("Copied the image to the clipboard!");
        }
        this.hapticFeedback('success');
      } catch (err) {
        console.error("Copy failed", err);
        this.showFlashNotification("Failed to generate image.");
      }
    },

    // Download QR code as PNG or SVG format.
    async downloadQrCode() {
      if (!this.qrCodeInstance) return;

      const extension = this.download.format;
      const safeName = (this.download.fileName || "grinds-qr-code").trim().replace(/[\\/:*?"<>|]/g, "-");

      const visibleCanvas = this.showSceneModal ? this.$refs.modalQrCanvas : this.$refs.qrCodeCanvas;
      const svgElement = visibleCanvas.querySelector("svg");
      if (!svgElement) return;

      const svgClone = svgElement.cloneNode(true);
      const svgViewBox = svgElement.viewBox.baseVal;
      const aspectRatio = svgViewBox.height > 0 ? svgViewBox.width / svgViewBox.height : 1;
      const canvasWidth = this.download.size;
      const canvasHeight = this.download.size / Math.max(aspectRatio, 0.0001);

      // Apply download size as absolute px values for both SVG and PNG.
      // Ensures correct artboard size when opened in Illustrator.
      svgClone.setAttribute("width", `${canvasWidth}px`);
      svgClone.setAttribute("height", `${canvasHeight}px`);
      svgClone.style.width = "";
      svgClone.style.height = "";

      svgClone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
      svgClone.setAttribute("xmlns:xlink", "http://www.w3.org/1999/xlink");

      if (this.download.transparentBg) {
        const bgRect = Array.from(svgClone.children).find(el => el.tagName.toLowerCase() === 'rect');
        if (bgRect) {
          bgRect.setAttribute("fill", "transparent");
          bgRect.style.fill = "transparent";
        }
      }

      // Convert to static array using Array.from for dynamic DOM replacement.
      const imageTags = Array.from(svgClone.querySelectorAll("image, img"));
      let hasInvalidImage = false;

      for (let img of imageTags) {
        let href = img.getAttribute("href") || img.getAttribute("xlink:href") || img.getAttribute("src");
        if (href) {
          if (!href.startsWith("data:")) {
            img.remove();
            hasInvalidImage = true;
          } else if (img.tagName.toLowerCase() === 'img') {
            img.remove();
            hasInvalidImage = true;
          } else {
            // Ultimate Illustrator compatibility fix.
            // Inline Base64 SVG as raw vector DOM instead of falling back to PNG.
            if (href.startsWith("data:image/svg+xml")) {
              try {
                let svgString = "";
                if (href.includes("base64,")) {
                  const binStr = atob(href.split("base64,")[1].replace(/\s/g, ''));
                  const bytes = Uint8Array.from(binStr, c => c.charCodeAt(0));
                  svgString = new TextDecoder('utf-8').decode(bytes); // Prevent character corruption.
                } else {
                  svgString = decodeURIComponent(href.split(",")[1]);
                }

                    // Sanitize with DOMPurify
                    const cleanSvgString = DOMPurify.sanitize(svgString, { USE_PROFILES: { svg: true } });

                // Parse SVG element from string.
                const parser = new DOMParser();
                    const doc = parser.parseFromString(cleanSvgString, "image/svg+xml");
                const innerSvg = doc.documentElement;

                if (innerSvg && innerSvg.tagName.toLowerCase() === "svg") {
                  // Transfer coordinates and dimensions from original <image> to expanded <svg>.
                  ['x', 'y', 'width', 'height'].forEach(attr => {
                    const val = img.getAttribute(attr);
                    if (val) innerSvg.setAttribute(attr, val);
                  });

                  // Explicitly set namespace for Illustrator.
                  innerSvg.setAttribute("xmlns", "http://www.w3.org/2000/svg");

                  // Replace <image> tag with full vector shapes (<svg>).
                  img.parentNode.replaceChild(innerSvg, img);
                  continue; // Continue to next loop if SVG inline succeeds.
                }
              } catch (e) {
                console.warn("Failed to inline vector SVG. Falling back.", e);
              }
            }

            // Attach legacy xlink:href for raster images like PNG/JPEG to ensure compatibility.
            img.removeAttribute("href");
            img.removeAttribute("xlink:href");
            img.setAttributeNS("http://www.w3.org/1999/xlink", "xlink:href", href);
          }
        } else {
          img.remove();
        }
      }

      let svgBlobUrl = null;
      try {
        const finalSvgString = new XMLSerializer().serializeToString(svgClone);
        const blob = new Blob([finalSvgString], { type: "image/svg+xml;charset=utf-8" });
        svgBlobUrl = URL.createObjectURL(blob);

        let fileData;
        let acceptTypes;

        if (extension === "svg") {
          fileData = blob;
          acceptTypes = { "image/svg+xml": [".svg"] };
        } else if (extension === "png") {
          fileData = await new Promise((resolve, reject) => {
            const image = new Image();
            image.onload = () => {
              setTimeout(() => {
                const exportCanvas = document.createElement("canvas");
                exportCanvas.width = canvasWidth;
                exportCanvas.height = canvasHeight;
                const context2d = exportCanvas.getContext("2d");
                context2d.drawImage(image, 0, 0, canvasWidth, canvasHeight);
                exportCanvas.toBlob((blobData) => {
                  if (blobData) resolve(blobData);
                  else reject(new Error("Failed to create PNG blob."));
                }, "image/png");
              }, 50);
            };
            image.onerror = () => reject(new Error("SVG Rendering Error"));
            image.src = svgBlobUrl;
          });
          acceptTypes = { "image/png": [".png"] };
        }

        let normalizedName = safeName;
        if (normalizedName.toLowerCase().endsWith('.' + extension)) {
          normalizedName = normalizedName.slice(0, -(extension.length + 1));
        }
        const fullFileName = `${normalizedName}.${extension}`;

        if ("showSaveFilePicker" in window) {
          try {
            const fileHandle = await window.showSaveFilePicker({
              suggestedName: fullFileName,
              types: [{
                description: `${extension.toUpperCase()} Image`,
                accept: acceptTypes
              }]
            });
            const writable = await fileHandle.createWritable();
            await writable.write(fileData);
            await writable.close();
          } catch (err) {
            if (err.name !== "AbortError") {
              console.error("Save cancelled or failed.", err);
              this.showFlashNotification("Failed to save the image.");
            }
            return; // Abort if user cancelled.
          }
        } else {
          // Fallback for browsers lacking File System Access API.
          const a = document.createElement("a");
          a.target = "_blank";
          a.rel = "noopener";
          const url = extension === "png" ? URL.createObjectURL(fileData) : svgBlobUrl;
          a.href = url;
          a.download = fullFileName;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          if (extension === "png") setTimeout(() => URL.revokeObjectURL(url), 10000);
        }

        this.showDownloadModal = false;
        if (hasInvalidImage) {
          this.showFlashNotification("Downloaded excluding an invalid logo.");
        } else {
          this.showFlashNotification("Downloaded successfully.");
        }
        this.hapticFeedback('success');
      } catch (err) {
        console.error("Download failed", err);
        this.showFlashNotification("Failed to generate image.");
      } finally {
        if (svgBlobUrl) setTimeout(() => URL.revokeObjectURL(svgBlobUrl), 10000);
      }
    },

    // Save generated QR code to IndexedDB.
    // If stayOnEditor is true, keep editor open after saving instead of returning to dashboard.
    async saveToGrind(stayOnEditor = false) {
      this.saveName = this.saveName.trim() || `Untitled QR (${new Date().toLocaleDateString()})`;

      const originalQr = this.editingQRCodeId ? this.savedQRCodes.find((qr) => qr.id === this.editingQRCodeId) : null;
      const conflictingQr = this.savedQRCodes.find((qr) => qr.name.trim() === this.saveName.trim() && qr.id !== this.editingQRCodeId);

      if (conflictingQr) {
        const isConfirmed = window.confirm("A QR code with the same name already exists. Do you want to overwrite it?");
        if (!isConfirmed) {
          return;
        }
        this.savedQRCodes = this.savedQRCodes.filter((qr) => qr.id !== conflictingQr.id);
      }

      const previewOptions = {
        width: 80,
        height: 80,
        data: this.getQrDataString(),
        image: this.qrOptions.logo,
        dotsOptions: this.buildDotsOptions(),
        backgroundOptions: {
          color: this.qrOptions.backgroundColor,
        },
        cornersSquareOptions: this.buildCornersSquareOptions(),
        cornersDotOptions: this.buildCornersDotOptions(),
        qrOptions: {
          errorCorrectionLevel: this.qrOptions.errorCorrectionLevel,
        },
        imageOptions: {
          ...this.qrOptions.imageOptions,
          margin: this.qrOptions.imageOptions.margin ? this.qrOptions.imageOptions.margin / 4 : 0,
        },
        margin: this.qrOptions.margin ? this.qrOptions.margin / 4 : 0,
      };

      // Separate huge Base64 string via spread syntax to avoid UI freeze (OOM crash) during deep copy.
      const rawOptions = window.Alpine.raw(this.qrOptions);
      const { logo, ...restOptions } = rawOptions;

      const copiedOptions = JSON.parse(JSON.stringify(restOptions));
      copiedOptions.logo = logo;

      // Convert tags string to array (comma-separated, trimmed, empty removed).
      const tagsArray = this.saveTags ? this.saveTags.split(',').map(t => t.trim()).filter(t => t) : [];

      const isNew = !this.editingQRCodeId;
      const newQr = {
        id: this.editingQRCodeId || this.generateUniqueId(),
        projectId: this.saveProjectId || 'default',
        name: this.saveName,
        memo: this.saveMemo,
        tags: tagsArray,
        type: this.selectedType,
        isFavorite: originalQr ? !!originalQr.isFavorite : false,
        formData: JSON.parse(JSON.stringify(window.Alpine.raw(this.formData))),
        qrOptions: copiedOptions,
        logoFileName: this.logoFileName,
        frame: JSON.parse(JSON.stringify(this.frame)),
        createdAt: originalQr ? originalQr.createdAt : new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        previewSvgUrl: await this.getPreviewSvgUrl(previewOptions),
      };

      if (!isNew) {
        const index = this.savedQRCodes.findIndex((qr) => qr.id === this.editingQRCodeId);
        if (index !== -1) {
          this.savedQRCodes[index] = newQr;
        } else {
          this.savedQRCodes.unshift(newQr);
        }
        this.showFlashNotification("QR code settings updated.");
      } else {
        this.savedQRCodes.unshift(newQr);
        this.editingQRCodeId = newQr.id; // Seamlessly transition to edit mode after saving new code.
        this.showFlashNotification("QR code saved.");
        this.hapticFeedback('success');
        // Sync saved name to default download filename.
        this.download.fileName = this.saveName;
      }

      await this.persistSavedQRCodes();

      if (typeof setDirty === 'function') setDirty(true);

      this.hasUnsavedEdit = false;
      this.showSaveModal = false;
      this.clearDraft(); // Clear draft after successful save

      if (!stayOnEditor) {
        this.currentView = "dashboard";
        this.resetGenerator();
      }
    },

    // --- Helper functions ---
    // Generate data string to encode into QR code.
    getQrDataString() {
      let data = " ";
      switch (this.selectedType) {
        case "url": {
          let urlStr = this.formData.url.address.trim();
          if (urlStr && !/^[a-zA-Z][a-zA-Z0-9+.-]*:/i.test(urlStr)) {
            urlStr = "https://" + urlStr;
          }
          if (urlStr) {
            try {
              const urlObj = new URL(urlStr);
              const utm = this.formData.url.utm;
              if (utm) {
                const cleanParam = (val) => String(val || "").trim().replace(/^[?&]+/, '');
                if (utm.source && String(utm.source).trim()) urlObj.searchParams.set("utm_source", cleanParam(utm.source));
                if (utm.medium && String(utm.medium).trim()) urlObj.searchParams.set("utm_medium", cleanParam(utm.medium));
                if (utm.campaign && String(utm.campaign).trim()) urlObj.searchParams.set("utm_campaign", cleanParam(utm.campaign));
                if (utm.term && String(utm.term).trim()) urlObj.searchParams.set("utm_term", cleanParam(utm.term));
                if (utm.content && String(utm.content).trim()) urlObj.searchParams.set("utm_content", cleanParam(utm.content));
              }
              data = urlObj.toString();
            } catch (e) {
              data = urlStr;
            }
          } else {
            data = " ";
          }
          break;
        }
        case "text": {
          data = this.formData.text.content.trim() || " ";
          break;
        }
        case "wifi": {
          const { ssid, password, encryption, hidden } = this.formData.wifi;
          const escapeWifiStr = (str) => {
            if (!str) return "";
            return String(str).replace(/([\\;:,])/g, "\\$1");
          };
          if (ssid) {
            const encType = encryption === "WPA/WPA2" ? "WPA" : (encryption === "None" ? "nopass" : encryption);
            const hiddenFlag = hidden ? "H:true;" : "";
            data = `WIFI:T:${encType};S:${escapeWifiStr(ssid)};P:${escapeWifiStr(password)};${hiddenFlag};`;
          }
          break;
        }
        case "vcard": {
          const { firstName, lastName, organization, phone, email, address } = this.formData.vcard;
          const escapeVCard = (str) => {
            if (!str) return "";
            return String(str).replace(/([,;\\])/g, "\\$1").replace(/\r?\n/g, "\\n");
          };

          if (firstName || lastName || organization || phone || email || address) {
            const vcardLines = [
              "BEGIN:VCARD",
              "VERSION:3.0",
              `N;CHARSET=UTF-8:${escapeVCard(lastName)};${escapeVCard(firstName)};;;`,
            ];
            let fn = `${escapeVCard(lastName ? lastName + " " : "")}${escapeVCard(firstName)}`.trim();
            if (!fn) fn = escapeVCard(organization) || "Contact";
            vcardLines.push(`FN;CHARSET=UTF-8:${fn}`);

            if (organization) vcardLines.push(`ORG;CHARSET=UTF-8:${escapeVCard(organization)}`);
            if (phone) vcardLines.push(`TEL:${escapeVCard(phone)}`);
            if (email) vcardLines.push(`EMAIL:${escapeVCard(email)}`);
            if (address) vcardLines.push(`ADR;TYPE=WORK;CHARSET=UTF-8:;;${escapeVCard(address)};;;;`);
            vcardLines.push("END:VCARD");
            data = vcardLines.join("\r\n");
          }
          break;
        }
        case "event": {
          const { summary, location, start, end, description } = this.formData.event;
          const formatDT = (dt) => {
            if (!dt) return "";
            try {
              const date = new Date(dt);
              return date.toISOString().replace(/[-:]/g, "").split(".")[0] + "Z";
            } catch (e) {
              return "";
            }
          };
          const escapeICal = (str) => {
            if (!str) return "";
            return String(str).replace(/[\\;,]/g, "\\$&").replace(/\r?\n/g, "\\n");
          };
          if (summary && start && end) {
            const dtstamp = new Date().toISOString().replace(/[-:]/g, "").split(".")[0] + "Z";
            const uid = `${Date.now()}-${Math.random().toString(36).substring(2,10)}@grinds`;
            data = `BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Grinds//QRCoder//EN\r\nBEGIN:VEVENT\r\nUID:${uid}\r\nDTSTAMP:${dtstamp}\r\nSUMMARY:${escapeICal(summary)}\r\nLOCATION:${escapeICal(location)}\r\nDTSTART:${formatDT(start)}\r\nDTEND:${formatDT(end)}\r\nDESCRIPTION:${escapeICal(description)}\r\nEND:VEVENT\r\nEND:VCALENDAR`;
          }
          break;
        }
        case "email": {
          const { to, subject, body } = this.formData.email;
          if (to) {
            let query = [];
            if (subject) query.push(`subject=${encodeURIComponent(subject)}`);
            if (body) query.push(`body=${encodeURIComponent(body)}`);
            data = `mailto:${to}${query.length > 0 ? '?' + query.join('&') : ''}`;
          }
          break;
        }
        case "sms": {
          const smsPhone = this.formData.sms.phone;
          const smsMessage = this.formData.sms.message;
          if (smsPhone) {
            // iOS/Android共通で動く標準的なURIスキーム。記号や空白を正規表現で安全に除去
            let smsData = `sms:${encodeURIComponent(smsPhone.replace(/[^0-9\+]/g, ''))}`;
            if (smsMessage) smsData += `?body=${encodeURIComponent(smsMessage)}`;
            data = smsData;
          }
          break;
        }
        case "crypto": {
          const { currency, address } = this.formData.crypto;
          if (address) {
            data = `${currency}:${address.trim()}`;
          }
          break;
        }
        case "geo": {
          const { latitude, longitude } = this.formData.geo;
          if (latitude && longitude) {
            data = `geo:${latitude},${longitude}?q=${latitude},${longitude}`;
          }
          break;
        }
        case "sns": {
          const { service, identifier } = this.formData.sns;
          if (identifier) {
            // Safely remove leading @ and trim if user accidentally typed it.
            const cleanId = identifier.replace(/^@/, '').trim();
            if (/^https?:\/\//i.test(cleanId)) {
              data = cleanId;
              break;
            }
            switch (service) {
              case "x":
                data = `https://twitter.com/${encodeURIComponent(cleanId)}`;
                break;
              case "instagram":
                data = `https://www.instagram.com/${encodeURIComponent(cleanId)}`;
                break;
              case "facebook":
                data = `https://www.facebook.com/${encodeURIComponent(cleanId)}`;
                break;
              case "line":
                data = `https://line.me/R/ti/p/@${encodeURIComponent(cleanId)}`;
                break;
              case "youtube":
                data = `https://www.youtube.com/@${encodeURIComponent(cleanId)}`;
                break;
              case "tiktok":
                data = `https://www.tiktok.com/@${encodeURIComponent(cleanId)}`;
                break;
              case "threads":
                data = `https://www.threads.net/@${encodeURIComponent(cleanId)}`;
                break;
              case "linkedin":
                // Auto-prefix URL if 'in/' is missing.
                const lnId = cleanId.replace(/^in\//i, '');
                data = `https://www.linkedin.com/in/${encodeURIComponent(lnId)}`;
                break;
              case "pinterest":
                data = `https://www.pinterest.com/${encodeURIComponent(cleanId)}/`;
                break;
              case "whatsapp":
                let waUrl = `https://wa.me/${encodeURIComponent(cleanId.replace(/[^0-9]/g, ''))}`;
                if (this.formData.sns.message) {
                  waUrl += `?text=${encodeURIComponent(this.formData.sns.message)}`;
                }
                data = waUrl;
                break;
              case "telegram":
                data = `https://t.me/${encodeURIComponent(cleanId)}`;
                break;
              case "github":
                data = `https://github.com/${encodeURIComponent(cleanId)}`;
                break;
              case "discord":
                // Use directly if URL is pasted, otherwise treat as invite link.
                if (cleanId.includes("http")) {
                  data = cleanId;
                } else {
                  data = `https://discord.gg/${encodeURIComponent(cleanId)}`;
                }
                break;
              case "paypal":
                data = `https://paypal.me/${encodeURIComponent(cleanId)}`;
                break;
              case "venmo":
                data = `https://venmo.com/${encodeURIComponent(cleanId)}`;
                break;
              case "paypay":
                data = identifier.trim();
                break;
              case "twitch":
                data = `https://www.twitch.tv/${encodeURIComponent(cleanId)}`;
                break;
            }
          }
          break;
        }
        case "images": {
          let imagesUrlStr = this.formData.images.url.trim();
          if (imagesUrlStr && !/^https?:\/\//i.test(imagesUrlStr)) {
            imagesUrlStr = "https://" + imagesUrlStr;
          }
          data = imagesUrlStr || " ";
          break;
        }
        case "video": {
          let videoUrlStr = this.formData.video.url.trim();
          if (videoUrlStr && !/^https?:\/\//i.test(videoUrlStr)) {
            videoUrlStr = "https://" + videoUrlStr;
          }
          data = videoUrlStr || " ";
          break;
        }
        default:
          data = " ";
      }
      return data;
    },

    // Check QR code quality and warn of any issues.
    checkQrQuality() {
      this.qrQuality.issues = [];
      let totalScore = 0;
      const evaluations = [];

      // 1. Contrast Ratio (30 points)
      const fgColorsList = this.qrOptions.colorType === "single" ? [this.qrOptions.foregroundColor] : [this.qrOptions.gradient.color1, this.qrOptions.gradient.color2];
      fgColorsList.push(this.qrOptions.cornerColor, this.qrOptions.cornerDotColor);
      const fgColors = [...new Set(fgColorsList)];
      const bgRgb = this.hexToRgb(this.qrOptions.backgroundColor);

      let minContrast = Infinity;
      let invalidColor = !bgRgb;
      if (!invalidColor) {
        for (const color of fgColors) {
          const fgRgb = this.hexToRgb(color);
          if (!fgRgb) {
            invalidColor = true;
            break;
          }
          const contrast = this.getContrast(fgRgb, bgRgb);
          if (contrast < minContrast) minContrast = contrast;
        }
      }

      let isNegative = false;
      if (!invalidColor) {
        const bgLum = this.getLuminance(bgRgb.r, bgRgb.g, bgRgb.b);
        for (const color of fgColors) {
          const fgRgb = this.hexToRgb(color);
          if (fgRgb && this.getLuminance(fgRgb.r, fgRgb.g, fgRgb.b) > bgLum) {
            isNegative = true;
          }
        }
      }

      let contrastScore = 0;
      let contrastPass = false;
      let contrastWarn = false;
      let contrastValStr = "Invalid";

      if (invalidColor) {
        // Handled below in overall check
      } else if (isNegative) {
        contrastValStr = "Inverted";
      } else {
        contrastValStr = minContrast.toFixed(1) + ":1";
        if (minContrast >= 7.0) {
          contrastScore = 30;
          contrastPass = true;
        } else if (minContrast >= 4.5) {
          contrastScore = 20;
          contrastWarn = true;
        } else {
          contrastScore = 0;
        }
      }
      totalScore += contrastScore;
      evaluations.push({ name: 'Contrast', value: contrastValStr, score: contrastScore, max: 30, pass: contrastPass, warn: contrastWarn });

      // 2. Quiet Zone (20 points)
      let quietZoneScore = 0;
      if (this.includeQuietZone) {
        quietZoneScore = 20;
      }
      totalScore += quietZoneScore;
      evaluations.push({ name: 'Quiet Zone', value: this.includeQuietZone ? 'Safe' : 'Missing', score: quietZoneScore, max: 20, pass: this.includeQuietZone, warn: false });

      // 3. Logo Coverage (20 points)
      let logoCoverageScore = 20;
      let logoCoverageValStr = "0%";
      let logoCoveragePass = true;
      let logoCoverageWarn = false;
      let coverageRatio = 0;

      if (this.qrOptions.logo) {
        const baseQrSize = 320;
        const marginRatio = (this.qrOptions.imageOptions.margin * 2) / baseQrSize;
        const lengthRatio = this.qrOptions.imageOptions.imageSize + marginRatio;
        coverageRatio = lengthRatio * lengthRatio;
        const coveragePercent = Math.round(coverageRatio * 100);
        logoCoverageValStr = coveragePercent + "%";

        if (coverageRatio <= 0.15) {
          logoCoverageScore = 20;
          logoCoveragePass = true;
        } else if (coverageRatio <= 0.20) {
          logoCoverageScore = 15;
          logoCoverageWarn = true;
          logoCoveragePass = false;
        } else if (coverageRatio <= 0.25) {
          logoCoverageScore = 5;
          logoCoverageWarn = true;
          logoCoveragePass = false;
        } else {
          logoCoverageScore = 0;
          logoCoveragePass = false;
        }
      }
      totalScore += logoCoverageScore;
      evaluations.push({ name: 'Logo Size', value: logoCoverageValStr, score: logoCoverageScore, max: 20, pass: logoCoveragePass, warn: logoCoverageWarn });

      // 4. ECC Margin (15 points)
      let eccMarginScore = 0;
      const eccCapacities = { 'L': 0.07, 'M': 0.15, 'Q': 0.25, 'H': 0.30 };
      const eccCapacity = eccCapacities[this.qrOptions.errorCorrectionLevel] || 0.07;
      const recoveryMargin = eccCapacity - coverageRatio;
      let eccMarginValStr = "Danger";
      let eccPass = false;
      let eccWarn = false;

      if (recoveryMargin >= 0.10) {
        eccMarginScore = 15;
        eccMarginValStr = "High";
        eccPass = true;
      } else if (recoveryMargin >= 0.05) {
        eccMarginScore = 10;
        eccMarginValStr = "Med";
        eccPass = true;
      } else if (recoveryMargin >= 0.01) {
        eccMarginScore = 5;
        eccMarginValStr = "Low";
        eccWarn = true;
      } else {
        eccMarginScore = 0;
      }
      totalScore += eccMarginScore;
      evaluations.push({ name: 'ECC Margin', value: eccMarginValStr, score: eccMarginScore, max: 15, pass: eccPass, warn: eccWarn });

      // 5. Module Density (15 points)
      const currentDataStr = this.getQrDataString();
      const byteSize = new Blob([currentDataStr]).size;

      // Ensure data size limits are flagged
      if (byteSize > 180) {
        this.qrQuality.issues.push({ id: 'capacity_error', status: "warning", message: `Large data size (${byteSize} Bytes). Ensure a good scanning environment.` });
      }
      if (byteSize > 2500) {
        this.qrQuality.issues.push({ id: 'capacity_error', status: "bad", message: `Data size exceeds the limit (${byteSize} Bytes). Please use a shorter URL.` });
      }

      // Estimate version
      const qrCapacity = [
        { v: 1, L: 17, M: 14, Q: 11, H: 7 },
        { v: 2, L: 32, M: 26, Q: 20, H: 14 },
        { v: 3, L: 53, M: 42, Q: 32, H: 24 },
        { v: 4, L: 78, M: 62, Q: 46, H: 34 },
        { v: 5, L: 106, M: 84, Q: 60, H: 44 },
        { v: 6, L: 134, M: 106, Q: 74, H: 58 },
        { v: 7, L: 154, M: 122, Q: 86, H: 64 },
        { v: 8, L: 192, M: 152, Q: 108, H: 84 },
        { v: 9, L: 230, M: 180, Q: 130, H: 98 },
        { v: 10, L: 271, M: 213, Q: 151, H: 119 },
        { v: 15, L: 520, M: 412, Q: 292, H: 220 },
        { v: 20, L: 858, M: 666, Q: 482, H: 382 },
        { v: 25, L: 1273, M: 991, Q: 715, H: 535 },
        { v: 30, L: 1732, M: 1370, Q: 982, H: 742 },
        { v: 35, L: 2303, M: 1809, Q: 1283, H: 983 },
        { v: 40, L: 2953, M: 2331, Q: 1663, H: 1273 }
      ];
      let version = 40;
      for (const cap of qrCapacity) {
        if (byteSize <= cap[this.qrOptions.errorCorrectionLevel]) {
          version = cap.v;
          break;
        }
      }

      let densityScore = 0;
      let densityPass = false;
      let densityWarn = false;

      if (version <= 4) {
        densityScore = 15;
        densityPass = true;
      } else if (version <= 10) {
        densityScore = 10;
        densityPass = true;
      } else if (version <= 20) {
        densityScore = 5;
        densityWarn = true;
      } else {
        densityScore = 0;
      }
      totalScore += densityScore;
      evaluations.push({ name: 'Density', value: `V.${version}`, score: densityScore, max: 15, pass: densityPass, warn: densityWarn });

      const modules = version * 4 + 17;
      const minSize = Math.ceil((modules + (this.includeQuietZone ? 8 : 0)) * 0.38);

      this.qrQuality.minSize = minSize;
      this.qrQuality.densityVersion = version;
      this.qrQuality.evaluations = evaluations;
      this.qrQuality.score = totalScore;
    },

    // Record operation history for undo functionality.
    recordState() {
      if (this.historyIndex < this.history.length - 1) {
        this.history = this.history.slice(0, this.historyIndex + 1);
      }

      // Unwrap proxy with Alpine.raw before cloning.
      const rawOptions = window.Alpine.raw(this.qrOptions);

      // Separate large logo string to save memory during clone.
      const { logo, ...restOptions } = rawOptions;
      const clonedOptions = JSON.parse(JSON.stringify(restOptions));
      clonedOptions.logo = logo;

      const currentState = {
        qrOptions: clonedOptions,
        frame: JSON.parse(JSON.stringify(window.Alpine.raw(this.frame))),
        formData: JSON.parse(JSON.stringify(window.Alpine.raw(this.formData))),
      };

      this.history.push(currentState);
      if (this.history.length > 30) {
        this.history.shift();
      } else {
        this.historyIndex++;
      }
    },

    // Undo last operation.
    undo() {
      if (this.historyIndex > 0) {
        this.historyIndex--;
        this.applyState(this.history[this.historyIndex]);
      }
    },

    // Redo reverted operation.
    redo() {
      if (this.historyIndex < this.history.length - 1) {
        this.historyIndex++;
        this.applyState(this.history[this.historyIndex]);
      }
    },

    // Other helper functions...
    applyState(state) {
      // Avoid deep copying huge Base64 images during Undo/Redo to prevent UI freeze.
      const rawStateOptions = window.Alpine.raw(state.qrOptions);
      const { logo, ...restOptions } = rawStateOptions;

      this.qrOptions = JSON.parse(JSON.stringify(restOptions));
      this.qrOptions.logo = logo;

      this.frame = JSON.parse(JSON.stringify(window.Alpine.raw(state.frame)));
      if (state.formData) this.formData = JSON.parse(JSON.stringify(window.Alpine.raw(state.formData)));
      this.includeQuietZone = this.qrOptions.margin > 0;
      this.updateQrCode(false);
    },
    generatePresetTemplates() {
      // Define base template groups.
      const basicTemplates = [
        {
          name: "Simple", // 1
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><rect x="10" y="10" width="80" height="80" rx="8" fill="#000"/></svg>`,
          options: { ...defaultQrOptions, colorType: "single", foregroundColor: "#000000", backgroundColor: "#ffffff", dotsStyle: "rounded", cornersStyle: "extra-rounded", cornerColor: "#000000", cornerDotColor: "#000000" },
        },
        {
          name: "Minimal", // 2
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#ffffff"/><rect x="15" y="15" width="70" height="70" rx="10" fill="#64748b"/></svg>`,
          options: { ...defaultQrOptions, colorType: "single", foregroundColor: "#64748b", cornerColor: "#64748b", cornerDotColor: "#64748b", backgroundColor: "#ffffff", dotsStyle: "rounded", cornersStyle: "extra-rounded", cornersDotStyle: "square" },
        },
        {
          name: "Modern", // 3
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><circle cx="50" cy="50" r="40" fill="#4338CA"/></svg>`,
          options: { ...defaultQrOptions, colorType: "single", foregroundColor: "#4338CA", cornerColor: "#4338CA", cornerDotColor: "#4338CA", backgroundColor: "#ffffff", dotsStyle: "dots", cornersStyle: "dot", cornersDotStyle: "dot" },
        },
        {
          name: "Elegant",
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#F1F5F9"/><path d="M50 10 A 40 40 0 0 1 90 50 A 40 40 0 0 1 50 90 A 40 40 0 0 1 10 50 A 40 40 0 0 1 50 10 M50 25 A 25 25 0 0 0 25 50 A 25 25 0 0 0 50 75 A 25 25 0 0 0 75 50 A 25 25 0 0 0 50 25" fill="#1F2937"/></svg>`,
          options: { ...defaultQrOptions, colorType: "single", foregroundColor: "#1F2937", cornerColor: "#1F2937", cornerDotColor: "#1F2937", backgroundColor: "#F1F5F9", dotsStyle: "classy", cornersStyle: "square" },
        },
        {
          name: "Dark", // 5
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#1e293b"/><rect x="10" y="10" width="80" height="80" rx="8" fill="#E2E8F0"/></svg>`,
          options: { ...defaultQrOptions, colorType: "single", foregroundColor: "#E2E8F0", cornerColor: "#E2E8F0", cornerDotColor: "#E2E8F0", backgroundColor: "#1e293b", dotsStyle: "rounded", cornersStyle: "extra-rounded" },
        },
        {
          name: "Pop", // 6
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#FCE7F3"/><circle cx="50" cy="50" r="40" fill="#DB2777"/></svg>`,
          options: { ...defaultQrOptions, colorType: "single", foregroundColor: "#DB2777", cornerColor: "#DB2777", cornerDotColor: "#DB2777", backgroundColor: "#FCE7F3", dotsStyle: "extra-rounded", cornersStyle: "dot", cornersDotStyle: "dot" },
        },
        {
          name: "Sunset", // 7
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="g-sunset" gradientTransform="rotate(135)"><stop offset="0%" stop-color="#f43f5e"/><stop offset="100%" stop-color="#f59e0b"/></linearGradient></defs><rect width="100" height="100" fill="#fff7ed"/><rect x="10" y="10" width="80" height="80" rx="20" fill="url(#g-sunset)"/></svg>`,
          options: {
            ...defaultQrOptions,
            colorType: "gradient",
            gradient: {
              type: "linear",
              rotation: "135",
              color1: "#f43f5e",
              color2: "#f59e0b",
            },
            backgroundColor: "#fff7ed",
            dotsStyle: "rounded",
            cornersStyle: "extra-rounded",
            cornerColor: "#f43f5e",
            cornerDotColor: "#f43f5e",
            cornersDotStyle: "extra-rounded",
          },
        },
        {
          name: "Ocean", // 8
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="g-ocean" gradientTransform="rotate(90)"><stop offset="0%" stop-color="#0ea5e9"/><stop offset="100%" stop-color="#10b981"/></linearGradient></defs><rect width="100" height="100" fill="#ecfeff"/><path d="M50 10 A 40 40 0 0 1 90 50 A 40 40 0 0 1 50 90 A 40 40 0 0 1 10 50 A 40 40 0 0 1 50 10 M50 25 A 25 25 0 0 0 25 50 A 25 25 0 0 0 50 75 A 25 25 0 0 0 75 50 A 25 25 0 0 0 50 25" fill="url(#g-ocean)"/></svg>`,
          options: {
            ...defaultQrOptions,
            colorType: "gradient",
            gradient: {
              type: "linear",
              rotation: "90",
              color1: "#0ea5e9",
              color2: "#10b981",
            },
            backgroundColor: "#ecfeff",
            dotsStyle: "classy",
            cornersStyle: "extra-rounded",
            cornerColor: "#0ea5e9",
            cornerDotColor: "#0ea5e9",
            cornersDotStyle: "dot",
          },
        },
        {
          name: "Techno", // 9
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="g-techno" gradientTransform="rotate(45)"><stop offset="0%" stop-color="#2563EB"/><stop offset="100%" stop-color="#9333EA"/></linearGradient></defs><rect width="100" height="100" fill="#111827"/><rect x="10" y="10" width="80" height="80" fill="url(#g-techno)"/></svg>`,
          options: {
            ...defaultQrOptions,
            colorType: "gradient",
            gradient: {
              type: "linear",
              rotation: "45",
              color1: "#2563EB",
              color2: "#9333EA",
            },
            backgroundColor: "#111827",
            dotsStyle: "square",
            cornersStyle: "square",
            cornerColor: "#2563EB",
            cornerDotColor: "#2563EB",
            cornersDotStyle: "square",
          },
        },
        {
          name: "Cyberpunk", // 10
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="g-cyber" gradientTransform="rotate(45)"><stop offset="0%" stop-color="#06b6d4"/><stop offset="100%" stop-color="#db2777"/></linearGradient></defs><rect width="100" height="100" fill="#0f172a"/><circle cx="50" cy="50" r="40" fill="url(#g-cyber)"/></svg>`,
          options: {
            ...defaultQrOptions,
            colorType: "gradient",
            gradient: {
              type: "linear",
              rotation: "45",
              color1: "#06b6d4",
              color2: "#db2777",
            },
            backgroundColor: "#0f172a",
            dotsStyle: "dots",
            cornersStyle: "dot",
            cornerColor: "#06b6d4",
            cornerDotColor: "#06b6d4",
            cornersDotStyle: "dot",
          },
        },
        {
          name: "Organic", // 11
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#F0FDF4"/><rect x="15" y="15" width="70" height="70" rx="35" fill="#15803D"/></svg>`,
          options: { ...defaultQrOptions, colorType: "single", foregroundColor: "#15803D", cornerColor: "#15803D", cornerDotColor: "#15803D", backgroundColor: "#F0FDF4", dotsStyle: "rounded", cornersStyle: "dot", cornersDotStyle: "dot" },
        },
        {
          name: "Luxury", // 12
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="g-luxury" gradientTransform="rotate(45)"><stop offset="0%" stop-color="#FBBF24"/><stop offset="100%" stop-color="#D97706"/></linearGradient></defs><rect width="100" height="100" fill="#FFFBEB"/><path d="M50 10 A 40 40 0 0 1 90 50 A 40 40 0 0 1 50 90 A 40 40 0 0 1 10 50 A 40 40 0 0 1 50 10 M50 25 A 25 25 0 0 0 25 50 A 25 25 0 0 0 50 75 A 25 25 0 0 0 75 50 A 25 25 0 0 0 50 25" fill="url(#g-luxury)"/></svg>`,
          options: {
            ...defaultQrOptions,
            colorType: "gradient",
            gradient: {
              type: "linear",
              rotation: "45",
              color1: "#FBBF24",
              color2: "#D97706",
            },
            backgroundColor: "#FFFBEB",
            dotsStyle: "classy-rounded",
            cornersStyle: "extra-rounded",
            cornerColor: "#FBBF24",
            cornerDotColor: "#FBBF24",
            cornersDotStyle: "dot",
          },
        },
      ];

      // 1. Speech Bubble Icon
      const lineIconSvgInner = `<circle cx="160" cy="160" fill="#4cc764" r="160"/><path d="m266.7 150.68c0-47.8-47.92-86.68-106.81-86.68s-106.81 38.89-106.81 86.68c0 42.85 38 78.73 89.33 85.52 3.48.75 8.21 2.29 9.41 5.27 1.08 2.7.7 6.93.35 9.66 0 0-1.25 7.54-1.52 9.14-.47 2.7-2.15 10.56 9.25 5.76s61.51-36.22 83.92-62.01c15.48-16.98 22.9-34.2 22.9-53.33z" fill="#fff"/><g fill="#4cc764"><path d="m231.17 178.28c1.13 0 2.04-.91 2.04-2.04v-7.58c0-1.12-.92-2.04-2.04-2.04h-20.39v-7.87h20.39c1.13 0 2.04-.91 2.04-2.04v-7.57c0-1.12-.92-2.04-2.04-2.04h-20.39v-7.87h20.39c1.13 0 2.04-.91 2.04-2.04v-7.57c0-1.12-.92-2.04-2.04-2.04h-30.01c-1.13 0-2.04.91-2.04 2.04v.04 46.54.04c0 1.13.91 2.04 2.04 2.04z"/><path d="m120.17 178.28c1.13 0 2.04-.91 2.04-2.04v-7.58c0-1.12-.92-2.04-2.04-2.04h-20.39v-37c0-1.12-.92-2.04-2.04-2.04h-7.58c-1.13 0-2.04.91-2.04 2.04v46.58.04c0 1.13.91 2.04 2.04 2.04z"/><rect height="50.69" rx="2.04" width="11.65" x="128.62" y="127.58"/><path d="m189.8 127.58h-7.58c-1.13 0-2.04.91-2.04 2.04v27.69l-21.33-28.8c-.05-.07-.11-.14-.16-.21 0 0 0 0-.01-.01-.04-.04-.08-.09-.12-.13-.01-.01-.03-.02-.04-.03-.04-.03-.07-.06-.11-.09-.02-.01-.04-.03-.06-.04-.03-.03-.07-.05-.11-.07-.02-.01-.04-.03-.06-.04-.04-.02-.07-.04-.11-.06-.02-.01-.04-.02-.06-.03-.04-.02-.08-.04-.12-.05-.02 0-.04-.02-.07-.02-.04-.01-.08-.03-.12-.04-.02 0-.05-.01-.07-.02-.04 0-.08-.02-.12-.03-.03 0-.06 0-.09-.01-.04 0-.07-.01-.11-.01s-.07 0-.11 0c-.02 0-.05 0-.07 0h-7.53c-1.13 0-2.04.91-2.04 2.04v46.62c0 1.13.91 2.04 2.04 2.04h7.58c1.13 0 2.04-.91 2.04-2.04v-27.68l21.35 28.84c.15.21.33.38.53.51 0 0 .02.01.02.02.04.03.08.05.13.08.02.01.04.02.06.03.03.02.07.03.1.05s.07.03.1.04c.02 0 .04.02.06.02.05.02.09.03.14.04h.03c.17.04.35.07.53.07h7.53c1.13 0 2.04-.91 2.04-2.04v-46.62c0-1.13-.91-2.04-2.04-2.04z"/></g>`;
      const lineIconSvg = `<svg width="320" height="320" viewBox="0 0 320 320" xmlns="http://www.w3.org/2000/svg">${lineIconSvgInner}</svg>`;

      // 2. Text Logo
      const lineTextSvgInner = `<g fill="#4cc764"><path d="m143.05 50.69c1.13 0 2.04-.91 2.04-2.04v-7.58c0-1.12-.92-2.04-2.04-2.04h-20.39v-7.87h20.39c1.13 0 2.04-.91 2.04-2.04v-7.57c0-1.12-.92-2.04-2.04-2.04h-20.39v-7.87h20.39c1.13 0 2.04-.91 2.04-2.04v-7.56c0-1.12-.92-2.04-2.04-2.04h-30.01c-1.13 0-2.04.91-2.04 2.04v.04 46.54.04c0 1.13.91 2.04 2.04 2.04h30.01z"/><path d="m32.05 50.69c1.13 0 2.04-.91 2.04-2.04v-7.58c0-1.12-.92-2.04-2.04-2.04h-20.4v-36.99c0-1.12-.91-2.04-2.04-2.04h-7.57c-1.13 0-2.04.91-2.04 2.04v46.58.04c0 1.13.91 2.04 2.04 2.04h30.01z"/><rect height="50.69" rx="2.04" width="11.65" x="40.5"/><path d="m101.68 0h-7.58c-1.13 0-2.04.91-2.04 2.04v27.69l-21.32-28.81c-.05-.07-.11-.14-.16-.21 0 0 0 0-.01-.01-.04-.04-.08-.09-.12-.13-.01-.01-.03-.02-.04-.03-.04-.03-.07-.06-.11-.09-.02-.01-.04-.03-.06-.04-.03-.03-.07-.05-.11-.07-.02-.01-.04-.03-.06-.04-.04-.02-.07-.04-.11-.06-.02-.01-.04-.02-.06-.03-.04-.02-.08-.04-.12-.05-.02 0-.04-.02-.07-.02-.04-.01-.08-.03-.12-.04-.02 0-.05-.01-.07-.02-.04 0-.08-.02-.12-.03-.03 0-.06 0-.09-.01-.04 0-.07-.01-.11-.01s-.07 0-.11 0c-.02 0-.05 0-.07 0h-7.53c-1.13 0-2.04.91-2.04 2.04v46.62c0 1.13.91 2.04 2.04 2.04h7.58c1.13 0 2.04-.91 2.04-2.04v-27.68l21.35 28.84c.15.21.33.38.53.51 0 0 .02.01.02.02.04.03.08.05.13.08l.06.03c.03.02.07.03.1.05s.07.03.1.04c.02 0 .04.02.06.02.05.02.09.03.14.04h.03c.17.04.35.07.53.07h7.53c1.13 0 2.04-.91 2.04-2.04v-46.63c0-1.13-.91-2.04-2.04-2.04z"/></g>`;
      const lineTextSvg = `<svg width="146" height="51" viewBox="0 0 145.09 50.69" xmlns="http://www.w3.org/2000/svg">${lineTextSvgInner}</svg>`;

      // Generate Data URLs.
      const iconGreenUrl = `data:image/svg+xml;base64,${btoa(lineIconSvg)}`;
      const textGreenUrl = `data:image/svg+xml;base64,${btoa(lineTextSvg)}`;

      // Define Gmail template.
      const gmailSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="192" height="192" fill="none" viewBox="0 0 192 192"><path fill="url(#a)" d="M146 44h38v110c0 6.627-5.373 12-12 12h-20a6 6 0 0 1-6-6z"/><path fill="#fc413d" d="M46 44H8v110c0 6.627 5.373 12 12 12h20a6 6 0 0 0 6-6z"/><path fill="url(#b)" d="M39.226 30.456c-8.033-6.752-20.018-5.714-26.77 2.319-6.752 8.032-5.714 20.017 2.319 26.77l76.078 63.949a8 8 0 0 0 10.295 0l76.078-63.95c8.032-6.752 9.07-18.737 2.318-26.77-6.752-8.032-18.737-9.07-26.769-2.318L96 78.18z"/><defs><linearGradient id="a" x1="165" x2="165" y1="44" y2="166" gradientUnits="userSpaceOnUse"><stop stop-color="#60d673"/><stop offset=".17" stop-color="#42c868"/><stop offset=".39" stop-color="#0ebc5f"/><stop offset=".62" stop-color="#00a9bb"/><stop offset=".86" stop-color="#3c90ff"/><stop offset="1" stop-color="#3186ff"/></linearGradient><linearGradient id="b" x1="8" x2="184" y1="46.13" y2="46.13" gradientUnits="userSpaceOnUse"><stop offset=".08" stop-color="#ff63a0"/><stop offset=".3" stop-color="#fc413d"/><stop offset=".5" stop-color="#fc413d"/><stop offset=".65" stop-color="#fc413d"/><stop offset=".72" stop-color="#fc5c30"/><stop offset=".86" stop-color="#feb10c"/><stop offset=".91" stop-color="#fec700"/><stop offset=".96" stop-color="#ffdb0f"/></linearGradient></defs></svg>`;
      const gmailLogoUrl = `data:image/svg+xml;base64,${btoa(gmailSvg)}`;

      const gmailTemplate = {
        name: "Gmail",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#fc413d"/></g><image x="30" y="30" width="40" height="40" href="${gmailLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: gmailLogoUrl,
          colorType: "single",
          foregroundColor: "#fc413d",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#fc413d",
          cornerDotColor: "#fc413d",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 4 },
        },
      };

      // Define Facebook template.
      const facebookSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="#1877F2" d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg>`;
      const facebookLogoUrl = `data:image/svg+xml;base64,${btoa(facebookSvg)}`;

      const facebookTemplate = {
        name: "Facebook",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#1877F2"/></g><image x="30" y="30" width="40" height="40" href="${facebookLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: facebookLogoUrl,
          colorType: "single",
          foregroundColor: "#1877F2",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#1877F2",
          cornerDotColor: "#1877F2",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8 },
        },
      };

      // Define Instagram template.
      const instagramSvg = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="264.583" height="264.583" viewBox="0 0 264.583 264.583"><defs><radialGradient xlink:href="#a" id="f" cx="158.429" cy="578.088" r="52.352" fx="158.429" fy="578.088" gradientTransform="matrix(0 -4.03418 4.28018 0 -2332.227 942.236)" gradientUnits="userSpaceOnUse"/><radialGradient xlink:href="#b" id="g" cx="172.615" cy="600.692" r="65" fx="172.615" fy="600.692" gradientTransform="matrix(.67441 -1.16203 1.51283 .87801 -814.366 -47.835)" gradientUnits="userSpaceOnUse"/><radialGradient xlink:href="#c" id="h" cx="144.012" cy="51.337" r="67.081" fx="144.012" fy="51.337" gradientTransform="matrix(-2.3989 .67549 -.23008 -.81732 464.996 -26.404)" gradientUnits="userSpaceOnUse"/><radialGradient xlink:href="#d" id="e" cx="199.788" cy="628.438" r="52.352" fx="199.788" fy="628.438" gradientTransform="matrix(-3.10797 .87652 -.6315 -2.23914 1345.65 1374.198)" gradientUnits="userSpaceOnUse"/><linearGradient id="d"><stop offset="0" stop-color="#ff005f"/><stop offset="1" stop-color="#fc01d8"/></linearGradient><linearGradient id="c"><stop offset="0" stop-color="#780cff"/><stop offset="1" stop-color="#820bff" stop-opacity="0"/></linearGradient><linearGradient id="b"><stop offset="0" stop-color="#fc0"/><stop offset="1" stop-color="#fc0" stop-opacity="0"/></linearGradient><linearGradient id="a"><stop offset="0" stop-color="#fc0"/><stop offset=".124" stop-color="#fc0"/><stop offset=".567" stop-color="#fe4a05"/><stop offset=".694" stop-color="#ff0f3f"/><stop offset="1" stop-color="#fe0657" stop-opacity="0"/></linearGradient></defs><path fill="url(#e)" d="M204.15 18.143c-55.23 0-71.383.057-74.523.317-11.334.943-18.387 2.728-26.07 6.554-5.922 2.942-10.592 6.351-15.201 11.13-8.394 8.716-13.481 19.439-15.323 32.184-.895 6.188-1.156 7.45-1.209 39.056-.02 10.536 0 24.4 0 42.999 0 55.2.062 71.341.326 74.476.916 11.032 2.645 17.973 6.308 25.565 7 14.533 20.37 25.443 36.12 29.514 5.453 1.404 11.476 2.178 19.208 2.544 3.277.142 36.669.244 70.081.244 33.413 0 66.826-.04 70.02-.203 8.954-.422 14.153-1.12 19.901-2.606 15.852-4.09 28.977-14.838 36.12-29.575 3.591-7.409 5.412-14.614 6.236-25.07.18-2.28.255-38.626.255-74.924 0-36.304-.082-72.583-.26-74.863-.835-10.625-2.656-17.77-6.364-25.32-3.042-6.182-6.42-10.799-11.324-15.519-8.752-8.361-19.455-13.45-32.21-15.29-6.18-.894-7.41-1.158-39.033-1.213z" transform="translate(-71.816 -18.143)"/><path fill="url(#f)" d="M204.15 18.143c-55.23 0-71.383.057-74.523.317-11.334.943-18.387 2.728-26.07 6.554-5.922 2.942-10.592 6.351-15.201 11.13-8.394 8.716-13.481 19.439-15.323 32.184-.895 6.188-1.156 7.45-1.209 39.056-.02 10.536 0 24.4 0 42.999 0 55.2.062 71.341.326 74.476.916 11.032 2.645 17.973 6.308 25.565 7 14.533 20.37 25.443 36.12 29.514 5.453 1.404 11.476 2.178 19.208 2.544 3.277.142 36.669.244 70.081.244 33.413 0 66.826-.04 70.02-.203 8.954-.422 14.153-1.12 19.901-2.606 15.852-4.09 28.977-14.838 36.12-29.575 3.591-7.409 5.412-14.614 6.236-25.07.18-2.28.255-38.626.255-74.924 0-36.304-.082-72.583-.26-74.863-.835-10.625-2.656-17.77-6.364-25.32-3.042-6.182-6.42-10.799-11.324-15.519-8.752-8.361-19.455-13.45-32.21-15.29-6.18-.894-7.41-1.158-39.033-1.213z" transform="translate(-71.816 -18.143)"/><path fill="url(#g)" d="M204.15 18.143c-55.23 0-71.383.057-74.523.317-11.334.943-18.387 2.728-26.07 6.554-5.922 2.942-10.592 6.351-15.201 11.13-8.394 8.716-13.481 19.439-15.323 32.184-.895 6.188-1.156 7.45-1.209 39.056-.02 10.536 0 24.4 0 42.999 0 55.2.062 71.341.326 74.476.916 11.032 2.645 17.973 6.308 25.565 7 14.533 20.37 25.443 36.12 29.514 5.453 1.404 11.476 2.178 19.208 2.544 3.277.142 36.669.244 70.081.244 33.413 0 66.826-.04 70.02-.203 8.954-.422 14.153-1.12 19.901-2.606 15.852-4.09 28.977-14.838 36.12-29.575 3.591-7.409 5.412-14.614 6.236-25.07.18-2.28.255-38.626.255-74.924 0-36.304-.082-72.583-.26-74.863-.835-10.625-2.656-17.77-6.364-25.32-3.042-6.182-6.42-10.799-11.324-15.519-8.752-8.361-19.455-13.45-32.21-15.29-6.18-.894-7.41-1.158-39.033-1.213z" transform="translate(-71.816 -18.143)"/><path fill="url(#h)" d="M204.15 18.143c-55.23 0-71.383.057-74.523.317-11.334.943-18.387 2.728-26.07 6.554-5.922 2.942-10.592 6.351-15.201 11.13-8.394 8.716-13.481 19.439-15.323 32.184-.895 6.188-1.156 7.45-1.209 39.056-.02 10.536 0 24.4 0 42.999 0 55.2.062 71.341.326 74.476.916 11.032 2.645 17.973 6.308 25.565 7 14.533 20.37 25.443 36.12 29.514 5.453 1.404 11.476 2.178 19.208 2.544 3.277.142 36.669.244 70.081.244 33.413 0 66.826-.04 70.02-.203 8.954-.422 14.153-1.12 19.901-2.606 15.852-4.09 28.977-14.838 36.12-29.575 3.591-7.409 5.412-14.614 6.236-25.07.18-2.28.255-38.626.255-74.924 0-36.304-.082-72.583-.26-74.863-.835-10.625-2.656-17.77-6.364-25.32-3.042-6.182-6.42-10.799-11.324-15.519-8.752-8.361-19.455-13.45-32.21-15.29-6.18-.894-7.41-1.158-39.033-1.213z" transform="translate(-71.816 -18.143)"/><path fill="#fff" d="M132.345 33.973c-26.716 0-30.07.117-40.563.594-10.472.48-17.62 2.136-23.876 4.567-6.47 2.51-11.958 5.87-17.426 11.335-5.472 5.464-8.834 10.948-11.354 17.412-2.44 6.252-4.1 13.397-4.57 23.858-.47 10.486-.593 13.838-.593 40.535 0 26.697.119 30.037.594 40.522.482 10.465 2.14 17.609 4.57 23.859 2.515 6.465 5.876 11.95 11.346 17.414 5.466 5.468 10.955 8.834 17.42 11.345 6.26 2.431 13.41 4.088 23.881 4.567 10.493.477 13.844.594 40.559.594 26.719 0 30.061-.117 40.555-.594 10.472-.48 17.63-2.136 23.888-4.567 6.468-2.51 11.948-5.877 17.414-11.345 5.472-5.464 8.834-10.949 11.354-17.412 2.419-6.252 4.079-13.398 4.57-23.858.472-10.486.595-13.828.595-40.525s-.123-30.047-.594-40.533c-.492-10.465-2.152-17.608-4.57-23.858-2.521-6.466-5.883-11.95-11.355-17.414-5.472-5.468-10.944-8.827-17.42-11.335-6.271-2.431-13.424-4.088-23.897-4.567-10.493-.477-13.834-.594-40.558-.594zm-8.825 17.715c2.62-.004 5.542 0 8.825 0 26.266 0 29.38.094 39.752.565 9.591.438 14.797 2.04 18.264 3.385 4.591 1.782 7.864 3.912 11.305 7.352 3.443 3.44 5.575 6.717 7.362 11.305 1.346 3.46 2.951 8.663 3.388 18.247.47 10.363.573 13.475.573 39.71 0 26.233-.102 29.346-.573 39.709-.44 9.584-2.042 14.786-3.388 18.247-1.783 4.587-3.919 7.854-7.362 11.292-3.443 3.441-6.712 5.57-11.305 7.352-3.463 1.352-8.673 2.95-18.264 3.388-10.37.47-13.486.573-39.752.573-26.268 0-29.38-.102-39.751-.573-9.592-.443-14.797-2.044-18.267-3.39-4.59-1.781-7.87-3.911-11.313-7.352-3.443-3.44-5.574-6.709-7.362-11.298-1.346-3.461-2.95-8.663-3.387-18.247-.472-10.363-.566-13.476-.566-39.726s.094-29.347.566-39.71c.438-9.584 2.04-14.786 3.387-18.25 1.783-4.588 3.919-7.865 7.362-11.305 3.443-3.441 6.722-5.57 11.313-7.357 3.468-1.351 8.675-2.949 18.267-3.389 9.075-.41 12.592-.532 30.926-.553zm61.337 16.322c-6.518 0-11.805 5.277-11.805 11.792 0 6.512 5.287 11.796 11.805 11.796 6.517 0 11.804-5.284 11.804-11.796 0-6.513-5.287-11.796-11.805-11.796zm-52.512 13.782c-27.9 0-50.519 22.603-50.519 50.482 0 27.879 22.62 50.471 50.52 50.471s50.51-22.592 50.51-50.471c0-27.879-22.613-50.482-50.513-50.482zm0 17.715c18.11 0 32.792 14.67 32.792 32.767 0 18.096-14.683 32.767-32.792 32.767-18.11 0-32.791-14.671-32.791-32.767 0-18.098 14.68-32.767 32.791-32.767z"/></svg>`;
      const instagramLogoUrl = `data:image/svg+xml;base64,${btoa(instagramSvg)}`;

      const instagramTemplate = {
        name: "Instagram",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="ig-grad" x1="0%" y1="100%" x2="100%" y2="0%"><stop offset="0%" stop-color="#f09433"/><stop offset="25%" stop-color="#e6683c"/><stop offset="50%" stop-color="#dc2743"/><stop offset="75%" stop-color="#cc2366"/><stop offset="100%" stop-color="#bc1888"/></linearGradient></defs><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="url(#ig-grad)"/></g><image x="30" y="30" width="40" height="40" href="${instagramLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: instagramLogoUrl,
          colorType: "gradient",
          gradient: {
            type: "linear",
            rotation: "45",
            color1: "#f58529",
            color2: "#d6249f",
          },
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#e6683c",
          cornerDotColor: "#d6249f",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8 },
        },
      };

      // Define TikTok template.
      const tiktokSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="352.28" height="398.67" id="Layer_2" viewBox="0 0 352.28 398.67"><defs><style>.cls-2{fill:#fe2c55}.cls-3{fill:#25f4ee}</style></defs><g id="Layer_1-2"><path d="M137.17 156.98v-15.56c-5.34-.73-10.76-1.18-16.29-1.18C54.23 140.24 0 194.47 0 261.13c0 40.9 20.43 77.09 51.61 98.97-20.12-21.6-32.46-50.53-32.46-82.31 0-65.7 52.69-119.28 118.03-120.81Z" class="cls-3"/><path d="M140.02 333c29.74 0 54-23.66 55.1-53.13l.11-263.2h48.08c-1-5.41-1.55-10.97-1.55-16.67h-65.67l-.11 263.2c-1.1 29.47-25.36 53.13-55.1 53.13-9.24 0-17.95-2.31-25.61-6.34C105.3 323.9 121.6 333 140.02 333ZM333.13 106V91.37c-18.34 0-35.43-5.45-49.76-14.8 12.76 14.65 30.09 25.22 49.76 29.43Z" class="cls-3"/><path d="M283.38 76.57c-13.98-16.05-22.47-37-22.47-59.91h-17.59c4.63 25.02 19.48 46.49 40.06 59.91ZM120.88 205.92c-30.44 0-55.21 24.77-55.21 55.21 0 21.2 12.03 39.62 29.6 48.86-6.55-9.08-10.45-20.18-10.45-32.2 0-30.44 24.77-55.21 55.21-55.21 5.68 0 11.13.94 16.29 2.55v-67.05c-5.34-.73-10.76-1.18-16.29-1.18-.96 0-1.9.05-2.85.07v51.49c-5.16-1.61-10.61-2.55-16.29-2.55Z" class="cls-2"/><path d="M333.13 106v51.04c-34.05 0-65.61-10.89-91.37-29.38v133.47c0 66.66-54.23 120.88-120.88 120.88-25.76 0-49.64-8.12-69.28-21.91 22.08 23.71 53.54 38.57 88.42 38.57 66.66 0 120.88-54.23 120.88-120.88V144.33c25.76 18.49 57.32 29.38 91.37 29.38v-65.68c-6.57 0-12.97-.71-19.14-2.03Z" class="cls-2"/><path d="M241.76 261.13V127.66c25.76 18.49 57.32 29.38 91.37 29.38V106c-19.67-4.21-37-14.77-49.76-29.43-20.58-13.42-35.43-34.88-40.06-59.91h-48.08l-.11 263.2c-1.1 29.47-25.36 53.13-55.1 53.13-18.42 0-34.72-9.1-44.75-23.01-17.57-9.25-29.6-27.67-29.6-48.86 0-30.44 24.77-55.21 55.21-55.21 5.68 0 11.13.94 16.29 2.55v-51.49C71.83 158.5 19.14 212.08 19.14 277.78c0 31.78 12.34 60.71 32.46 82.31C71.23 373.87 95.12 382 120.88 382c66.65 0 120.88-54.23 120.88-120.88Z" style="fill:#000"/></g></svg>`;
      const tiktokLogoUrl = `data:image/svg+xml;base64,${btoa(tiktokSvg)}`;

      const tiktokTemplate = {
        name: "TikTok",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#000000"/></g><image x="35" y="30" width="30" height="40" href="${tiktokLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: tiktokLogoUrl,
          colorType: "single",
          foregroundColor: "#000000",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#000000",
          cornerDotColor: "#fe2c55",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.4, margin: 10 },
        },
      };

      // Define X template.
      const xSvg = `<svg width="24" height="24" fill="#000000" role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><title>X</title><path d="M14.234 10.162 22.977 0h-2.072l-7.591 8.824L7.251 0H.258l9.168 13.343L.258 24H2.33l8.016-9.318L16.749 24h6.993zm-2.837 3.299-.929-1.329L3.076 1.56h3.182l5.965 8.532.929 1.329 7.754 11.09h-3.182z"/></svg>`;
      const xLogoUrl = `data:image/svg+xml;base64,${btoa(xSvg)}`;

      const xTemplate = {
        name: "X",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#000000"/></g><image x="35" y="35" width="30" height="30" href="${xLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: xLogoUrl,
          colorType: "single",
          foregroundColor: "#000000",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#000000",
          cornerDotColor: "#000000",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10 },
        },
      };

      // Define ZOOM template.
      const zoomSvg = `<svg enable-background="new 0 0 351.8447266 80" viewBox="0 0 351.8447266 80" width="351.8447266" height="80" xmlns="http://www.w3.org/2000/svg"><path d="m73.7864151 78.8349609h-62.90728c-4.4136801 0-8.3570995-2.6350098-10.0460796-6.712677s-.76362-8.7295189 2.3573999-11.849968l43.5734711-43.573288h-31.2299404c-8.5792007 0-15.5339804-6.9547901-15.5339804-15.5339794h58.0143013c4.4132996 0 8.3565331 2.6342499 10.0456963 6.7119198 1.6893616 4.0776696.7645569 8.7287598-2.3560791 11.850729l-43.5736485 43.5732709h36.1221657c8.5792007 0 15.5339813 6.9547768 15.5339813 15.5339775zm278.0582809-48.5437011c0-16.7028199-13.588623-30.2912598-30.2912597-30.2912598-8.9343262 0-16.9751282 3.8903201-22.5242615 10.0633297-5.5491638-6.1730096-13.5899658-10.0633297-22.524292-10.0633297-16.7026367 0-30.2912598 13.5884399-30.2912598 30.2912598v48.5436859c8.5791626 0 15.5339661-6.9547882 15.5339661-15.5339699v-33.009716c0-8.1371403 6.6201477-14.7572803 14.7572937-14.7572803s14.7572937 6.6201496 14.7572937 14.7572803v33.0097313c0 8.5791664 6.9548035 15.5339699 15.5339661 15.5339699v-48.5437012c0-8.1371403 6.6201477-14.7572803 14.7572937-14.7572803s14.7572937 6.6201495 14.7572937 14.7572803v33.0097313c0 8.5791664 6.9548035 15.5339699 15.5339661 15.5339699l.0000305-48.5436897zm-113.3980712 9.7087402c0 22.0914078-17.9085846 40-40 40s-40-17.9085922-40-40 17.9086456-40 40-40 40 17.9085903 40 40zm-15.5339814 0c0-13.5122108-10.9538116-24.4660206-24.4660187-24.4660206s-24.4660186 10.9538098-24.4660186 24.4660206 10.9538116 24.4660187 24.4660187 24.4660187 24.4660186-10.9538117 24.4660186-24.4660187zm-70.6796112 0c0 22.0914078-17.9085846 40-39.9999924 40s-40-17.9085922-40-40 17.9086304-40 40-40 39.9999924 17.9085903 39.9999924 40zm-15.5339813 0c0-13.5122108-10.953804-24.4660206-24.466011-24.4660206s-24.4660187 10.9538098-24.4660187 24.4660206 10.9538116 24.4660187 24.4660187 24.4660187 24.466011-10.9538117 24.466011-24.4660187z" fill="#0b5cff"/></svg>`;
      const zoomLogoUrl = `data:image/svg+xml;base64,${btoa(zoomSvg)}`;

      const zoomTemplate = {
        name: "Zoom",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#0b5cff"/></g><image x="15" y="42" width="70" height="16" href="${zoomLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: zoomLogoUrl,
          colorType: "single",
          foregroundColor: "#0b5cff",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#0b5cff",
          cornerDotColor: "#0b5cff",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 6 },
        },
      };

      // Define Discord template.
      const discordSvg = `<svg viewBox="0 0 256 199" width="256" height="199" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid"><path d="M216.856 16.597A208.502 208.502 0 0 0 164.042 0c-2.275 4.113-4.933 9.645-6.766 14.046-19.692-2.961-39.203-2.961-58.533 0-1.832-4.4-4.55-9.933-6.846-14.046a207.809 207.809 0 0 0-52.855 16.638C5.618 67.147-3.443 116.4 1.087 164.956c22.169 16.555 43.653 26.612 64.775 33.193A161.094 161.094 0 0 0 79.735 175.3a136.413 136.413 0 0 1-21.846-10.632 108.636 108.636 0 0 0 5.356-4.237c42.122 19.702 87.89 19.702 129.51 0a131.66 131.66 0 0 0 5.355 4.237 136.07 136.07 0 0 1-21.886 10.653c4.006 8.02 8.638 15.67 13.873 22.848 21.142-6.58 42.646-16.637 64.815-33.213 5.316-56.288-9.08-105.09-38.056-148.36ZM85.474 135.095c-12.645 0-23.015-11.805-23.015-26.18s10.149-26.2 23.015-26.2c12.867 0 23.236 11.804 23.015 26.2.02 14.375-10.148 26.18-23.015 26.18Zm85.051 0c-12.645 0-23.014-11.805-23.014-26.18s10.148-26.2 23.014-26.2c12.867 0 23.236 11.804 23.015 26.2 0 14.375-10.148 26.18-23.015 26.18Z" fill="#5865F2"/></svg>`;
      const discordLogoUrl = `data:image/svg+xml;base64,${btoa(discordSvg)}`;

      const discordTemplate = {
        name: "Discord",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#5865F2"/></g><image x="30" y="30" width="40" height="40" href="${discordLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: discordLogoUrl,
          colorType: "single",
          foregroundColor: "#5865F2",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#5865F2",
          cornerDotColor: "#5865F2",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8 },
        },
      };

      // Define GitHub template.
      const githubSvg = `<svg width="1024" height="1024" viewBox="0 0 1024 1024" fill="none" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" clip-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8C0 11.54 2.29 14.53 5.47 15.59C5.87 15.66 6.02 15.42 6.02 15.21C6.02 15.02 6.01 14.39 6.01 13.72C4 14.09 3.48 13.23 3.32 12.78C3.23 12.55 2.84 11.84 2.5 11.65C2.22 11.5 1.82 11.13 2.49 11.12C3.12 11.11 3.57 11.7 3.72 11.94C4.44 13.15 5.59 12.81 6.05 12.6C6.12 12.08 6.33 11.73 6.56 11.53C4.78 11.33 2.92 10.64 2.92 7.58C2.92 6.71 3.23 5.99 3.74 5.43C3.66 5.23 3.38 4.41 3.82 3.31C3.82 3.31 4.49 3.1 6.02 4.13C6.66 3.95 7.34 3.86 8.02 3.86C8.7 3.86 9.38 3.95 10.02 4.13C11.55 3.09 12.22 3.31 12.22 3.31C12.66 4.41 12.38 5.23 12.3 5.43C12.81 5.99 13.12 6.7 13.12 7.58C13.12 10.65 11.25 11.33 9.47 11.53C9.76 11.78 10.01 12.26 10.01 13.01C10.01 14.08 10 14.94 10 15.21C10 15.42 10.15 15.67 10.55 15.59C13.71 14.53 16 11.53 16 8C16 3.58 12.42 0 8 0Z" transform="scale(64)" fill="#181717"/></svg>`;
      const githubLogoUrl = `data:image/svg+xml;base64,${btoa(githubSvg)}`;

      const githubTemplate = {
        name: "GitHub",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#181717"/></g><image x="30" y="30" width="40" height="40" href="${githubLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: githubLogoUrl,
          colorType: "single",
          foregroundColor: "#181717",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#181717",
          cornerDotColor: "#181717",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10 },
        },
      };

      // Define YouTube template.
      const youtubeSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="256" height="180" preserveAspectRatio="xMidYMid" viewBox="0 0 256 180"><path fill="#FF0000" d="M250.346 28.075A32.18 32.18 0 0 0 227.69 5.418C207.824 0 127.87 0 127.87 0S47.912.164 28.046 5.582A32.18 32.18 0 0 0 5.39 28.24c-6.009 35.298-8.34 89.084.165 122.97a32.18 32.18 0 0 0 22.656 22.657c19.866 5.418 99.822 5.418 99.822 5.418s79.955 0 99.82-5.418a32.18 32.18 0 0 0 22.657-22.657c6.338-35.348 8.291-89.1-.164-123.134Z"/><path fill="#FFF" d="m102.421 128.06 66.328-38.418-66.328-38.418z"/></svg>`;
      const youtubeLogoUrl = `data:image/svg+xml;base64,${btoa(youtubeSvg)}`;

      const youtubeTemplate = {
        name: "YouTube",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#FF0000"/></g><image x="25" y="32.5" width="50" height="35" href="${youtubeLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: youtubeLogoUrl,
          colorType: "single",
          foregroundColor: "#FF0000",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#FF0000",
          cornerDotColor: "#FF0000",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.4, margin: 8 },
        },
      };

      // Define LinkedIn template.
      const linkedinSvg = `<svg width="256" height="256" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid" viewBox="0 0 256 256"><path d="M218.123 218.127h-37.931v-59.403c0-14.165-.253-32.4-19.728-32.4-19.756 0-22.779 15.434-22.779 31.369v60.43h-37.93V95.967h36.413v16.694h.51a39.907 39.907 0 0 1 35.928-19.733c38.445 0 45.533 25.288 45.533 58.186l-.016 67.013ZM56.955 79.27c-12.157.002-22.014-9.852-22.016-22.009-.002-12.157 9.851-22.014 22.008-22.016 12.157-.003 22.014 9.851 22.016 22.008A22.013 22.013 0 0 1 56.955 79.27m18.966 138.858H37.95V95.967h37.97v122.16ZM237.033.018H18.89C8.58-.098.125 8.161-.001 18.471v219.053c.122 10.315 8.576 18.582 18.89 18.474h218.144c10.336.128 18.823-8.139 18.966-18.474V18.454c-.147-10.33-8.635-18.588-18.966-18.453" fill="#0A66C2"/></svg>`;
      const linkedinLogoUrl = `data:image/svg+xml;base64,${btoa(linkedinSvg)}`;

      const linkedinTemplate = {
        name: "LinkedIn",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#0A66C2"/></g><image x="30" y="30" width="40" height="40" href="${linkedinLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: linkedinLogoUrl,
          colorType: "single",
          foregroundColor: "#0A66C2",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#0A66C2",
          cornerDotColor: "#0A66C2",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8 },
        },
      };

      // Define Spotify template.
      const spotifySvg = `<svg viewBox="0 0 256 256" width="256" height="256" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid"><path d="M128 0C57.308 0 0 57.309 0 128c0 70.696 57.309 128 128 128 70.697 0 128-57.304 128-128C256 57.314 198.697.007 127.998.007l.001-.006Zm58.699 184.614c-2.293 3.76-7.215 4.952-10.975 2.644-30.053-18.357-67.885-22.515-112.44-12.335a7.981 7.981 0 0 1-9.552-6.007 7.968 7.968 0 0 1 6-9.553c48.76-11.14 90.583-6.344 124.323 14.276 3.76 2.308 4.952 7.215 2.644 10.975Zm15.667-34.853c-2.89 4.695-9.034 6.178-13.726 3.289-34.406-21.148-86.853-27.273-127.548-14.92-5.278 1.594-10.852-1.38-12.454-6.649-1.59-5.278 1.386-10.842 6.655-12.446 46.485-14.106 104.275-7.273 143.787 17.007 4.692 2.89 6.175 9.034 3.286 13.72v-.001Zm1.345-36.293C162.457 88.964 94.394 86.71 55.007 98.666c-6.325 1.918-13.014-1.653-14.93-7.978-1.917-6.328 1.65-13.012 7.98-14.935C93.27 62.027 168.434 64.68 215.929 92.876c5.702 3.376 7.566 10.724 4.188 16.405-3.362 5.69-10.73 7.565-16.4 4.187h-.006Z" fill="#1ED760"/></svg>`;
      const spotifyLogoUrl = `data:image/svg+xml;base64,${btoa(spotifySvg)}`;

      const spotifyTemplate = {
        name: "Spotify",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#1ED760"/></g><image x="30" y="30" width="40" height="40" href="${spotifyLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: spotifyLogoUrl,
          colorType: "single",
          foregroundColor: "#1ED760",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#1ED760",
          cornerDotColor: "#1ED760",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10 },
        },
      };

      // Define Apple Music template.
      const appleMusicSvg = `<svg width="24" height="24" fill="#fa233b" role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><title>Apple Music</title><path d="M23.994 6.124a9.23 9.23 0 00-.24-2.19c-.317-1.31-1.062-2.31-2.18-3.043a5.022 5.022 0 00-1.877-.726 10.496 10.496 0 00-1.564-.15c-.04-.003-.083-.01-.124-.013H5.986c-.152.01-.303.017-.455.026-.747.043-1.49.123-2.193.4-1.336.53-2.3 1.452-2.865 2.78-.192.448-.292.925-.363 1.408-.056.392-.088.785-.1 1.18 0 .032-.007.062-.01.093v12.223c.01.14.017.283.027.424.05.815.154 1.624.497 2.373.65 1.42 1.738 2.353 3.234 2.801.42.127.856.187 1.293.228.555.053 1.11.06 1.667.06h11.03a12.5 12.5 0 001.57-.1c.822-.106 1.596-.35 2.295-.81a5.046 5.046 0 001.88-2.207c.186-.42.293-.87.37-1.324.113-.675.138-1.358.137-2.04-.002-3.8 0-7.595-.003-11.393zm-6.423 3.99v5.712c0 .417-.058.827-.244 1.206-.29.59-.76.962-1.388 1.14-.35.1-.706.157-1.07.173-.95.045-1.773-.6-1.943-1.536a1.88 1.88 0 011.038-2.022c.323-.16.67-.25 1.018-.324.378-.082.758-.153 1.134-.24.274-.063.457-.23.51-.516a.904.904 0 00.02-.193c0-1.815 0-3.63-.002-5.443a.725.725 0 00-.026-.185c-.04-.15-.15-.243-.304-.234-.16.01-.318.035-.475.066-.76.15-1.52.303-2.28.456l-2.325.47-1.374.278c-.016.003-.032.01-.048.013-.277.077-.377.203-.39.49-.002.042 0 .086 0 .13-.002 2.602 0 5.204-.003 7.805 0 .42-.047.836-.215 1.227-.278.64-.77 1.04-1.434 1.233-.35.1-.71.16-1.075.172-.96.036-1.755-.6-1.92-1.544-.14-.812.23-1.685 1.154-2.075.357-.15.73-.232 1.108-.31.287-.06.575-.116.86-.177.383-.083.583-.323.6-.714v-.15c0-2.96 0-5.922.002-8.882 0-.123.013-.25.042-.37.07-.285.273-.448.546-.518.255-.066.515-.112.774-.165.733-.15 1.466-.296 2.2-.444l2.27-.46c.67-.134 1.34-.27 2.01-.403.22-.043.442-.088.663-.106.31-.025.523.17.554.482.008.073.012.148.012.223.002 1.91.002 3.822 0 5.732z"/></svg>`;
      const appleMusicLogoUrl = `data:image/svg+xml;base64,${btoa(appleMusicSvg)}`;

      const appleMusicTemplate = {
        name: "Apple Music",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#fa233b"/></g><image x="30" y="30" width="40" height="40" href="${appleMusicLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: appleMusicLogoUrl,
          colorType: "single",
          foregroundColor: "#fa233b",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#fa233b",
          cornerDotColor: "#fa233b",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10 },
        },
      };

      // Define Netflix template.
      const netflixSvg = `<svg width="551" height="1000" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" id="Netflix_Symbol_RGB" version="1.1" viewBox="0 0 551.111 1000"><defs id="defs4"><linearGradient id="linearGradient35887"><stop id="stop35883" offset="0" style="stop-color:#b1060f;stop-opacity:1"/><stop id="stop36053" offset=".625" style="stop-color:#7b010c;stop-opacity:1"/><stop id="stop35885" offset="1" style="stop-color:#b1060f;stop-opacity:0"/></linearGradient><linearGradient id="linearGradient19332"><stop id="stop19328" offset="0" style="stop-color:#b1060f;stop-opacity:1"/><stop id="stop19560" offset=".546" style="stop-color:#7b010c;stop-opacity:1"/><stop id="stop19330" offset="1" style="stop-color:#e50914;stop-opacity:0"/></linearGradient><linearGradient xlink:href="#linearGradient19332" id="linearGradient13368" x1="78.234" x2="221.663" y1="423.767" y2="365.092" gradientUnits="userSpaceOnUse"/><linearGradient xlink:href="#linearGradient35887" id="linearGradient35889" x1="456.365" x2="309.676" y1="521.56" y2="583.495" gradientUnits="userSpaceOnUse"/><style id="style2">.cls-1{fill:#e50914}</style></defs><path id="path6055" d="M-1.152-1.152 2.305 1002.67c73.273-14.111 130.892-12.569 195.924-18.44V0Z" style="fill:url(#linearGradient13368);stroke:none;stroke-width:1px;stroke-linecap:butt;stroke-linejoin:miter;stroke-opacity:1;fill-opacity:1"/><path id="path678" d="M353.816 0h199.381l2.305 1000.365-202.839-33.422z" style="fill:url(#linearGradient35889);stroke:none;stroke-width:1px;stroke-linecap:butt;stroke-linejoin:miter;stroke-opacity:1;fill-opacity:1"/><path id="path362" d="M1.152 0c4.61 11.525 345.749 981.925 345.749 981.925 56.056-.4 131.219 8.754 205.144 17.288L197.077 0Z" style="fill:#e50914;fill-opacity:1;stroke:none;stroke-width:1px;stroke-linecap:butt;stroke-linejoin:miter;stroke-opacity:1"/></svg>`;
      const netflixLogoUrl = `data:image/svg+xml;base64,${btoa(netflixSvg)}`;

      const netflixTemplate = {
        name: "Netflix",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#E50914"/></g><image x="37.5" y="25" width="25" height="50" href="${netflixLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: netflixLogoUrl,
          colorType: "single",
          foregroundColor: "#E50914",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#E50914",
          cornerDotColor: "#E50914",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10 },
        },
      };

      // Define SoundCloud template.
      const soundcloudSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="75" height="34" viewBox="0 0 75 33.51"><g id="Layer_2" data-name="Layer 2"><g id="Orange" fill="#FF5500"><path d="M75,23.6a10.5,10.5,0,0,1-10.63,9.91H38.82a2.14,2.14,0,0,1-2.12-2.13V3.87a2.34,2.34,0,0,1,1.41-2.24S40.46,0,45.41,0A16.74,16.74,0,0,1,54,2.36a17,17,0,0,1,8,11.08,9.8,9.8,0,0,1,2.71-.37A10.23,10.23,0,0,1,75,23.6Z"/><path d="M33.51,5.61a.83.83,0,1,0-1.65,0c-.7,9.25-1.24,17.92,0,27.14a.83.83,0,0,0,1.65,0C34.84,23.45,34.28,14.94,33.51,5.61Z"/><path d="M28.35,8.81a.87.87,0,0,0-1.73,0,103.7,103.7,0,0,0,0,23.95.87.87,0,0,0,1.72,0A93.2,93.2,0,0,0,28.35,8.81Z"/><path d="M23.16,8a.84.84,0,0,0-1.67,0c-.79,8.44-1.19,16.32,0,24.74a.83.83,0,0,0,1.66,0C24.38,24.21,24,16.55,23.16,8Z"/><path d="M18,10.41a.86.86,0,0,0-1.72,0,87.61,87.61,0,0,0,0,22.36.85.85,0,0,0,1.69,0A81.68,81.68,0,0,0,18,10.41Z"/><path d="M12.79,16a.85.85,0,0,0-1.7,0c-1.23,5.76-.65,11,.05,16.83a.81.81,0,0,0,1.6,0C13.51,26.92,14.1,21.8,12.79,16Z"/><path d="M7.62,15.12a.88.88,0,0,0-1.75,0C4.78,21,5.14,26.18,5.9,32.05c.08.89,1.59.88,1.69,0C8.43,26.09,8.82,21.06,7.62,15.12Z"/><path d="M2.4,18A.88.88,0,0,0,.65,18c-1,3.95-.69,7.22.07,11.18a.82.82,0,0,0,1.63,0C3.23,25.14,3.66,21.94,2.4,18Z"/></g></g></svg>`;
      const soundcloudLogoUrl = `data:image/svg+xml;base64,${btoa(soundcloudSvg)}`;

      const soundcloudTemplate = {
        name: "SoundCloud",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#FF5500"/></g><image x="25" y="40" width="50" height="20" href="${soundcloudLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: soundcloudLogoUrl,
          colorType: "single",
          foregroundColor: "#FF5500",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#FF5500",
          cornerDotColor: "#FF5500",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10 },
        },
      };

      // Define Steam template.
      const steamSvg = `<svg width="65" height="65" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 65 65" fill="#fff"><use xlink:href="#B" x=".5" y=".5"/><defs><linearGradient id="A" x2="50%" x1="50%" y2="100%" y1="0%"><stop stop-color="#111d2e" offset="0%"/><stop stop-color="#051839" offset="21.2%"/><stop stop-color="#0a1b48" offset="40.7%"/><stop stop-color="#132e62" offset="58.1%"/><stop stop-color="#144b7e" offset="73.8%"/><stop stop-color="#136497" offset="87.3%"/><stop stop-color="#1387b8" offset="100%"/></linearGradient></defs><symbol id="B"><g><path d="M1.305 41.202C5.259 54.386 17.488 64 31.959 64c17.673 0 32-14.327 32-32s-14.327-32-32-32C15.001 0 1.124 13.193.028 29.874c2.074 3.477 2.879 5.628 1.275 11.328z" fill="url(#A)"/><path d="M30.31 23.985l.003.158-7.83 11.375c-1.268-.058-2.54.165-3.748.662a8.14 8.14 0 0 0-1.498.8L.042 29.893s-.398 6.546 1.26 11.424l12.156 5.016c.6 2.728 2.48 5.12 5.242 6.27a8.88 8.88 0 0 0 11.603-4.782 8.89 8.89 0 0 0 .684-3.656L42.18 36.16l.275.005c6.705 0 12.155-5.466 12.155-12.18s-5.44-12.16-12.155-12.174c-6.702 0-12.155 5.46-12.155 12.174zm-1.88 23.05c-1.454 3.5-5.466 5.147-8.953 3.694a6.84 6.84 0 0 1-3.524-3.362l3.957 1.64a5.04 5.04 0 0 0 6.591-2.719 5.05 5.05 0 0 0-2.715-6.601l-4.1-1.695c1.578-.6 3.372-.62 5.05.077 1.7.703 3 2.027 3.696 3.72s.692 3.56-.01 5.246M42.466 32.1a8.12 8.12 0 0 1-8.098-8.113 8.12 8.12 0 0 1 8.098-8.111 8.12 8.12 0 0 1 8.1 8.111 8.12 8.12 0 0 1-8.1 8.113m-6.068-8.126a6.09 6.09 0 0 1 6.08-6.095c3.355 0 6.084 2.73 6.084 6.095a6.09 6.09 0 0 1-6.084 6.093 6.09 6.09 0 0 1-6.081-6.093z"/></g></symbol></svg>`;
      const steamLogoUrl = `data:image/svg+xml;base64,${btoa(steamSvg)}`;

      const steamTemplate = {
        name: "Steam",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#171a21"/></g><image x="30" y="30" width="40" height="40" href="${steamLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: steamLogoUrl,
          colorType: "single",
          foregroundColor: "#171a21",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#171a21",
          cornerDotColor: "#171a21",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8 },
        },
      };

      // Define note template.
      const noteSvg = `<svg width="493" height="493" viewBox="0 0 493 493" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="1" y="1" width="490.2" height="490.2" rx="104" fill="white"/><path d="M139.2 141.7C180.4 141.7 236.8 139.6 277.3 140.7C331.6 142.1 352.1 165.8 352.8 224.2C353.5 257.3 352.8 351.9 352.8 351.9H294C294 269.1 294.3 255.4 294 229.3C293.3 206.3 286.8 195.4 269.1 193.3C250.4 191.2 198 193 198 193V352H139.2V141.7Z" fill="#040000"/><rect x="1" y="1" width="490.2" height="490.2" rx="104" stroke="#EBEBEB" stroke-width="2"/></svg>`;
      const noteLogoUrl = `data:image/svg+xml;base64,${btoa(noteSvg)}`;

      const noteTemplate = {
        name: "note",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#41C9B4"/></g><image x="30" y="30" width="40" height="40" href="${noteLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: noteLogoUrl,
          colorType: "single",
          foregroundColor: "#41C9B4",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#41C9B4",
          cornerDotColor: "#41C9B4",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8 },
        },
      };

      // Define WhatsApp template.
      const whatsappSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="360" height="362" fill="none" viewBox="0 0 360 362"><path fill="#25D366" fill-rule="evenodd" d="M307.546 52.566C273.709 18.684 228.706.017 180.756 0 81.951 0 1.538 80.404 1.504 179.235c-.017 31.594 8.242 62.432 23.928 89.609L0 361.736l95.024-24.925c26.179 14.285 55.659 21.805 85.655 21.814h.077c98.788 0 179.21-80.413 179.244-179.244.017-47.898-18.608-92.926-52.454-126.807v-.008Zm-126.79 275.788h-.06c-26.73-.008-52.952-7.194-75.831-20.765l-5.44-3.231-56.391 14.791 15.05-54.981-3.542-5.638c-14.912-23.721-22.793-51.139-22.776-79.286.035-82.14 66.867-148.973 149.051-148.973 39.793.017 77.198 15.53 105.328 43.695 28.131 28.157 43.61 65.596 43.593 105.398-.035 82.149-66.867 148.982-148.982 148.982v.008Zm81.719-111.577c-4.478-2.243-26.497-13.073-30.606-14.568-4.108-1.496-7.09-2.243-10.073 2.243-2.982 4.487-11.568 14.577-14.181 17.559-2.613 2.991-5.226 3.361-9.704 1.117-4.477-2.243-18.908-6.97-36.02-22.226-13.313-11.878-22.304-26.54-24.916-31.027-2.613-4.486-.275-6.91 1.959-9.136 2.011-2.011 4.478-5.234 6.721-7.847 2.244-2.613 2.983-4.486 4.478-7.469 1.496-2.991.748-5.603-.369-7.847-1.118-2.243-10.073-24.289-13.812-33.253-3.636-8.732-7.331-7.546-10.073-7.692-2.613-.13-5.595-.155-8.586-.155-2.991 0-7.839 1.118-11.947 5.604-4.108 4.486-15.677 15.324-15.677 37.361s16.047 43.344 18.29 46.335c2.243 2.991 31.585 48.225 76.51 67.632 10.684 4.615 19.029 7.374 25.535 9.437 10.727 3.412 20.49 2.931 28.208 1.779 8.604-1.289 26.498-10.838 30.228-21.298 3.73-10.46 3.73-19.433 2.613-21.298-1.117-1.865-4.108-2.991-8.586-5.234l.008-.017Z" clip-rule="evenodd"/></svg>`;
      const whatsappLogoUrl = `data:image/svg+xml;base64,${btoa(whatsappSvg)}`;

      const whatsappTemplate = {
        name: "WhatsApp",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#25D366"/></g><image x="30" y="30" width="40" height="40" href="${whatsappLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: whatsappLogoUrl,
          colorType: "single",
          foregroundColor: "#25D366",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#25D366",
          cornerDotColor: "#25D366",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10 },
        },
      };

      // Define PayPal template.
      const paypalSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="38" height="45" viewBox="7.056000232696533 3 37.35095977783203 45"><g xmlns="http://www.w3.org/2000/svg"><path fill="#002991" d="M38.914 13.35c0 5.574-5.144 12.15-12.927 12.15H18.49l-.368 2.322L16.373 39H7.056l5.605-36h15.095c5.083 0 9.082 2.833 10.555 6.77a9.687 9.687 0 0 1 .603 3.58z"></path><path fill="#60CDFF" d="M44.284 23.7A12.894 12.894 0 0 1 31.53 34.5h-5.206L24.157 48H14.89l1.483-9 1.75-11.178.367-2.322h7.497c7.773 0 12.927-6.576 12.927-12.15 3.825 1.974 6.055 5.963 5.37 10.35z"></path><path fill="#008CFF" d="M38.914 13.35C37.31 12.511 35.365 12 33.248 12h-12.64L18.49 25.5h7.497c7.773 0 12.927-6.576 12.927-12.15z"></path></g></svg>`;
      const paypalLogoUrl = `data:image/svg+xml;base64,${btoa(paypalSvg)}`;

      const paypalTemplate = {
        name: "PayPal",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#002991"/></g><image x="35" y="30" width="30" height="40" href="${paypalLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: paypalLogoUrl,
          colorType: "single",
          foregroundColor: "#002991",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#002991",
          cornerDotColor: "#008CFF",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10 },
        },
      };

      // Define Notion template.
      const notionSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="256" height="268" preserveAspectRatio="xMidYMid" viewBox="0 0 256 268"><path fill="#FFF" d="M16.092 11.538 164.09.608c18.179-1.56 22.85-.508 34.28 7.801l47.243 33.282C253.406 47.414 256 48.975 256 55.207v182.527c0 11.439-4.155 18.205-18.696 19.24L65.44 267.378c-10.913.517-16.11-1.043-21.825-8.327L8.826 213.814C2.586 205.487 0 199.254 0 191.97V29.726c0-9.352 4.155-17.153 16.092-18.188Z"/><path d="M164.09.608 16.092 11.538C4.155 12.573 0 20.374 0 29.726v162.245c0 7.284 2.585 13.516 8.826 21.843l34.789 45.237c5.715 7.284 10.912 8.844 21.825 8.327l171.864-10.404c14.532-1.035 18.696-7.801 18.696-19.24V55.207c0-5.911-2.336-7.614-9.21-12.66l-1.185-.856L198.37 8.409C186.94.1 182.27-.952 164.09.608ZM69.327 52.22c-14.033.945-17.216 1.159-25.186-5.323L23.876 30.778c-2.06-2.086-1.026-4.69 4.163-5.207l142.274-10.395c11.947-1.043 18.17 3.12 22.842 6.758l24.401 17.68c1.043.525 3.638 3.637.517 3.637L71.146 52.095l-1.819.125Zm-16.36 183.954V81.222c0-6.767 2.077-9.887 8.3-10.413L230.02 60.93c5.724-.517 8.31 3.12 8.31 9.879v153.917c0 6.767-1.044 12.49-10.387 13.008l-161.487 9.361c-9.343.517-13.489-2.594-13.489-10.921ZM212.377 89.53c1.034 4.681 0 9.362-4.681 9.897l-7.783 1.542v114.404c-6.758 3.637-12.981 5.715-18.18 5.715-8.308 0-10.386-2.604-16.609-10.396l-50.898-80.079v77.476l16.1 3.646s0 9.362-12.989 9.362l-35.814 2.077c-1.043-2.086 0-7.284 3.63-8.318l9.351-2.595V109.823l-12.98-1.052c-1.044-4.68 1.55-11.439 8.826-11.965l38.426-2.585 52.958 81.113v-71.76l-13.498-1.552c-1.043-5.733 3.111-9.896 8.3-10.404l35.84-2.087Z"/></svg>`;
      const notionLogoUrl = `data:image/svg+xml;base64,${btoa(notionSvg)}`;

      const notionTemplate = {
        name: "Notion",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#000000"/></g><image x="30" y="30" width="40" height="40" href="${notionLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: notionLogoUrl,
          colorType: "single",
          foregroundColor: "#000000",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#000000",
          cornerDotColor: "#000000",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8 },
        },
      };

      // Define Google Drive template.
      const googleDriveSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="87.3" height="78" viewBox="0 0 87.3 78"><path fill="#0066da" d="m6.6 66.85 3.85 6.65c.8 1.4 1.95 2.5 3.3 3.3L27.5 53H0c0 1.55.4 3.1 1.2 4.5z"/><path fill="#00ac47" d="M43.65 25 29.9 1.2c-1.35.8-2.5 1.9-3.3 3.3l-25.4 44A9.06 9.06 0 0 0 0 53h27.5z"/><path fill="#ea4335" d="M73.55 76.8c1.35-.8 2.5-1.9 3.3-3.3l1.6-2.75L86.1 57.5c.8-1.4 1.2-2.95 1.2-4.5H59.798l5.852 11.5z"/><path fill="#00832d" d="M43.65 25 57.4 1.2C56.05.4 54.5 0 52.9 0H34.4c-1.6 0-3.15.45-4.5 1.2z"/><path fill="#2684fc" d="M59.8 53H27.5L13.75 76.8c1.35.8 2.9 1.2 4.5 1.2h50.8c1.6 0 3.15-.45 4.5-1.2z"/><path fill="#ffba00" d="m73.4 26.5-12.7-22c-.8-1.4-1.95-2.5-3.3-3.3L43.65 25 59.8 53h27.45c0-1.55-.4-3.1-1.2-4.5z"/></svg>`;
      const googleDriveLogoUrl = `data:image/svg+xml;base64,${btoa(googleDriveSvg)}`;

      const googleDriveTemplate = {
        name: "Google Drive",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#2684fc"/></g><image x="30" y="32" width="40" height="36" href="${googleDriveLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: googleDriveLogoUrl,
          colorType: "single",
          foregroundColor: "#2684fc",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#2684fc",
          cornerDotColor: "#00ac47",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10 },
        },
      };

      // Define PayPay template.
      const paypaySvg = `<svg height="1546" viewBox="0 0 1547 1546" width="1547" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><clipPath id="paypay-clip-a"><path d="m1546.61.98v1544.44h-1545.63v-1544.44z"/></clipPath><clipPath id="paypay-clip-b"><path d="m1546.61.98v1544.44h-1545.63v-1544.44z"/></clipPath><g clip-path="url(#paypay-clip-a)"><path d="m1318.19.98c125.75 0 228.42 102.67 228.42 228.42v1087.6c0 125.75-102.67 228.42-228.42 228.42h-1088.79c-125.35 0-228.42-102.67-228.42-228.42v-832.91l.8-267.02c6.36-119.79 106.25-216.09 227.62-216.09z" fill="#fff" fill-rule="evenodd"/></g><g clip-path="url(#paypay-clip-b)"><path d="m1546.61 229.4v1087.6c0 125.75-102.67 228.42-228.42 228.42h-923.64l70.44-292.1c469.98-35.81 758.89-144.85 821.76-429.38 69.64-315.58-373.67-632.74-1285.37-606.87 6.76-119.79 106.65-216.09 228.02-216.09h1088.79c125.75 0 228.42 102.67 228.42 228.42zm-1036.26 835.69 138.09-575.03c381.24 51.33 619.21 187.83 583 335.47-39 158.78-401.93 254.69-721.09 239.56zm-208.52 480.33h-72.43c-125.75 0-228.42-102.67-228.42-228.42v-832.51c204.94-21.09 396.36-20.3 564.29-3.98z" fill="#f03" fill-rule="evenodd"/></g></svg>`;
      const paypayLogoUrl = `data:image/svg+xml;base64,${btoa(paypaySvg)}`;

      const paypayTemplate = {
        name: "PayPay",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#ff0033"/></g><image x="30" y="30" width="40" height="40" href="${paypayLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: paypayLogoUrl,
          colorType: "single",
          foregroundColor: "#ff0033",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#ff0033",
          cornerDotColor: "#ff0033",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10 },
        },
      };

      // Define Bitcoin template.
      const bitcoinSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64"><path d="M63.043 39.76C58.766 56.866 41.424 67.32 24.24 63.043 7.134 58.766-3.32 41.424.957 24.24 5.234 7.134 22.576-3.32 39.76.957 56.866 5.234 67.32 22.576 63.043 39.76z" fill="#f7931a"/><path d="M46.096 27.407c.634-4.276-2.613-6.573-7.048-8.077l1.425-5.78-3.484-.87-1.425 5.623c-.95-.238-1.9-.475-2.85-.634l1.425-5.623-3.484-.87-1.425 5.78c-.792-.158-1.505-.317-2.217-.554l-4.83-1.188-.95 3.722 2.534.634c1.425.317 1.663 1.267 1.663 2.06l-1.666 6.57c.08 0 .238.08.396.08-.08 0-.238-.08-.396-.08l-2.297 9.186c-.158.396-.634 1.1-1.584.87 0 .08-2.534-.634-2.534-.634l-1.742 4.04 4.593 1.1c.87.238 1.663.475 2.534.634l-1.425 5.86 3.484.87 1.425-5.78L29 45.07l-1.425 5.78 3.484.87 1.425-5.86c6.018 1.1 10.453.713 12.354-4.75 1.505-4.355-.08-6.9-3.247-8.553 2.376-.475 4.04-1.98 4.514-5.147zM38.098 38.73c-1.1 4.355-8.394 1.98-10.77 1.425l1.9-7.76c2.376.554 9.978 1.742 8.87 6.335zm1.1-11.324c-.95 3.96-7.127 1.98-9.107 1.425l1.742-7.048c1.98.554 8.394 1.425 7.365 5.623z" fill="#fff"/></svg>`;
      const bitcoinLogoUrl = `data:image/svg+xml;base64,${btoa(bitcoinSvg)}`;

      const bitcoinTemplate = {
        name: "Bitcoin",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#F7931A"/></g><image x="30" y="30" width="40" height="40" href="${bitcoinLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: bitcoinLogoUrl,
          colorType: "single",
          foregroundColor: "#F7931A",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#F7931A",
          cornerDotColor: "#F7931A",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10 },
        },
      };

      // Define Ethereum template.
      const ethereumSvg = `<svg enable-background="new 0 0 1920 1920" viewBox="0 0 1920 1920" width="1920" height="1920" xmlns="http://www.w3.org/2000/svg"><path d="m959.8 80.7-539.7 895.6 539.7-245.3z" fill="#8a92b2"/><path d="m959.8 731-539.7 245.3 539.7 319.1z" fill="#62688f"/><path d="m1499.6 976.3-539.8-895.6v650.3z" fill="#62688f"/><path d="m959.8 1295.4 539.8-319.1-539.8-245.3z" fill="#454a75"/><path d="m420.1 1078.7 539.7 760.6v-441.7z" fill="#8a92b2"/><path d="m959.8 1397.6v441.7l540.1-760.6z" fill="#62688f"/></svg>`;
      const ethereumLogoUrl = `data:image/svg+xml;base64,${btoa(ethereumSvg)}`;

      const ethereumTemplate = {
        name: "Ethereum",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#627EEA"/></g><image x="30" y="30" width="40" height="40" href="${ethereumLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: ethereumLogoUrl,
          colorType: "single",
          foregroundColor: "#627EEA",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#627EEA",
          cornerDotColor: "#627EEA",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10 },
        },
      };

      // Define Solana template.
      const solanaSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 100 100" fill="none"><path fill="url(#solana-gradient)" d="M86.619 69.036 74.403 82.101a2.837 2.837 0 0 1-2.075.899h-57.91a1.421 1.421 0 0 1-1.3-.85 1.411 1.411 0 0 1 .263-1.53l12.225-13.064a2.837 2.837 0 0 1 2.07-.899h57.906a1.423 1.423 0 0 1 1.3.85 1.412 1.412 0 0 1-.263 1.53ZM74.403 42.727a2.837 2.837 0 0 0-2.075-.898h-57.91a1.421 1.421 0 0 0-1.3.85 1.412 1.412 0 0 0 .263 1.529l12.225 13.065a2.84 2.84 0 0 0 2.07.898h57.906a1.422 1.422 0 0 0 1.3-.85 1.412 1.412 0 0 0-.263-1.529L74.403 42.727Zm-59.985-9.384h57.91a2.844 2.844 0 0 0 2.075-.899l12.216-13.065A1.414 1.414 0 0 0 85.582 17H27.676a2.845 2.845 0 0 0-2.07.899L13.384 30.964a1.412 1.412 0 0 0 1.034 2.379Z"/><defs><linearGradient id="solana-gradient" x1="19.247" x2="79.786" y1="84.573" y2="16.138" gradientUnits="userSpaceOnUse"><stop offset=".08" stop-color="#9945FF"/><stop offset=".3" stop-color="#8752F3"/><stop offset=".5" stop-color="#5497D5"/><stop offset=".6" stop-color="#43B4CA"/><stop offset=".72" stop-color="#28E0B9"/><stop offset=".97" stop-color="#19FB9B"/></linearGradient></defs></svg>`;
      const solanaLogoUrl = `data:image/svg+xml;base64,${btoa(solanaSvg)}`;

      const solanaTemplate = {
        name: "Solana",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#9945FF"/></g><image x="20" y="20" width="60" height="60" href="${solanaLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: solanaLogoUrl,
          colorType: "gradient",
          gradient: {
            type: "linear",
            rotation: "135",
            color1: "#9945FF",
            color2: "#19FB9B",
          },
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#9945FF",
          cornerDotColor: "#19FB9B",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.35, margin: 8 },
        },
      };

      // Define Venmo template.
      const venmoSvg = `<svg width="1400" height="265.26" viewBox="0 0 1400 265.26" xmlns="http://www.w3.org/2000/svg"><path d="m148.37 16.49c5.2 10.85 8.52 24.02 8.52 43.36 0 35.33-25.07 87.15-45.38 120.12l-21.74-174.33-89.77 8.49 41.12 244.99h102.52c44.89-58.89 100.19-142.75 100.19-207.31 0-20.24-4.26-36.26-13.71-51.82l-81.75 16.49zm247.23-15.56c-93.56 0-138.94 81.05-138.94 157.37 0 58.89 27.9 106 105.85 106 30.73 0 62.39-6.6 82.7-16.49l10.86-73.48c-28.83 14.6-51.02 20.24-74.18 20.24-21.28 0-37.32-11.28-37.32-40.04 48.21-.47 131.35-20.24 131.35-84.8 0-40.04-28.8-68.8-80.31-68.8zm-49.14 106.95c2.37-28.26 24.08-48.04 40.62-48.04 9.46 0 17.48 5.64 17.48 16.95 0 23.55-41.59 31.08-58.11 31.08zm328.48-106.94c-33.53 0-57.17 12.74-75.12 24.51l-.96-20.27h-76.08l-40.16 253.95h87.9l27.87-178.08c7.56-3.78 18.91-8.96 30.23-8.96 8.53 0 15.62 2.82 15.62 14.13 0 4.71-1.43 13.2-1.9 17.42l-24.57 155.49h87.41s26.94-169.62 26.94-169.62c1.43-8.93 2.86-22.6 2.86-32.02 0-33.94-15.62-56.56-60.04-56.55zm400.8-.01c-32.59 0-56.23 9.91-81.27 27.8-9-16.02-26.94-27.8-54.35-27.79-31.66 0-55.27 12.74-72.76 25.44l-2.36-21.2h-75.15l-40.16 253.95h87.87l27.89-178.08c7.56-3.78 18.89-8.96 30.23-8.96 8.49 0 15.59 2.82 15.59 15.56 0 3.28-.94 8.46-1.4 12.71l-25.04 158.77h87.41l27.87-178.08c8.06-4.25 18.91-8.96 29.77-8.96 8.52 0 15.62 2.82 15.62 15.56 0 3.28-.97 8.46-1.43 12.71l-25.04 158.77h87.43l26.91-169.62c1.43-8.93 2.86-22.6 2.86-32.02 0-33.94-15.61-56.56-60.49-56.56zm223.6 0c-97.82 0-140.34 74.94-140.34 155.02 0 60.77 24.57 109.31 98.75 109.31 100.18 0 142.24-81.97 142.24-161.13 0-59.84-26.94-103.2-100.66-103.2zm-29.31 196.95c-15.58 0-22.2-14.6-22.2-38.18 0-31.09 7.08-91.86 41.58-91.86 15.58 0 20.78 14.13 20.78 34.87 0 31.09-7.56 95.18-40.17 95.18z" fill="#008cff"/></svg>`;
      const venmoLogoUrl = `data:image/svg+xml;base64,${btoa(venmoSvg)}`;

      const venmoTemplate = {
        name: "Venmo",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#008CFF"/></g><image x="15" y="43" width="70" height="14" href="${venmoLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: venmoLogoUrl,
          colorType: "single",
          foregroundColor: "#008CFF",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#008CFF",
          cornerDotColor: "#008CFF",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8 },
        },
      };

      // Define Slack template.
      const slackSvg = `<svg width="2448" height="2453" enable-background="new 0 0 2447.6 2452.5" viewBox="0 0 2447.6 2452.5" xmlns="http://www.w3.org/2000/svg"><g clip-rule="evenodd" fill-rule="evenodd"><path d="m897.4 0c-135.3.1-244.8 109.9-244.7 245.2-.1 135.3 109.5 245.1 244.8 245.2h244.8v-245.1c.1-135.3-109.5-245.1-244.9-245.3.1 0 .1 0 0 0m0 654h-652.6c-135.3.1-244.9 109.9-244.8 245.2-.2 135.3 109.4 245.1 244.7 245.3h652.7c135.3-.1 244.9-109.9 244.8-245.2.1-135.4-109.5-245.2-244.8-245.3z" fill="#36c5f0"/><path d="m2447.6 899.2c.1-135.3-109.5-245.1-244.8-245.2-135.3.1-244.9 109.9-244.8 245.2v245.3h244.8c135.3-.1 244.9-109.9 244.8-245.3zm-652.7 0v-654c.1-135.2-109.4-245-244.7-245.2-135.3.1-244.9 109.9-244.8 245.2v654c-.2 135.3 109.4 245.1 244.7 245.3 135.3-.1 244.9-109.9 244.8-245.3z" fill="#2eb67d"/><path d="m1550.1 2452.5c135.3-.1 244.9-109.9 244.8-245.2.1-135.3-109.5-245.1-244.8-245.2h-244.8v245.2c-.1 135.2 109.5 245 244.8 245.2zm0-654.1h652.7c135.3-.1 244.9-109.9 244.8-245.2.2-135.3-109.4-245.1-244.7-245.3h-652.7c-135.3.1-244.9 109.9-244.8 245.2-.1 135.4 109.4 245.2 244.7 245.3z" fill="#ecb22e"/><path d="m0 1553.2c-.1 135.3 109.5 245.1 244.8 245.2 135.3-.1 244.9-109.9 244.8-245.2v-245.2h-244.8c-135.3.1-244.9 109.9-244.8 245.2zm652.7 0v654c-.2 135.3 109.4 245.1 244.7 245.3 135.3-.1 244.9-109.9 244.8-245.2v-653.9c.2-135.3-109.4-245.1-244.7-245.3-135.4 0-244.9 109.8-244.8 245.1 0 0 0 .1 0 0" fill="#e01e5a"/></g></svg>`;
      const slackLogoUrl = `data:image/svg+xml;base64,${btoa(slackSvg)}`;

      const slackTemplate = {
        name: "Slack",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#000000"/></g><image x="30" y="30" width="40" height="40" href="${slackLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: slackLogoUrl,
          colorType: "single",
          foregroundColor: "#000000",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#000000",
          cornerDotColor: "#000000",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8 },
        },
      };

      // Define Figma template.
      const figmaSvg = `<svg width="54" height="80" viewBox="0 0 54 80" fill="none" xmlns="http://www.w3.org/2000/svg"><g clip-path="url(#clip0_912_3)"><path d="M13.3333 80.0002C20.6933 80.0002 26.6667 74.0268 26.6667 66.6668V53.3335H13.3333C5.97333 53.3335 0 59.3068 0 66.6668C0 74.0268 5.97333 80.0002 13.3333 80.0002Z" fill="#0ACF83"/><path d="M0 39.9998C0 32.6398 5.97333 26.6665 13.3333 26.6665H26.6667V53.3332H13.3333C5.97333 53.3332 0 47.3598 0 39.9998Z" fill="#A259FF"/><path d="M0 13.3333C0 5.97333 5.97333 0 13.3333 0H26.6667V26.6667H13.3333C5.97333 26.6667 0 20.6933 0 13.3333Z" fill="#F24E1E"/><path d="M26.6667 0H40.0001C47.3601 0 53.3334 5.97333 53.3334 13.3333C53.3334 20.6933 47.3601 26.6667 40.0001 26.6667H26.6667V0Z" fill="#FF7262"/><path d="M53.3334 39.9998C53.3334 47.3598 47.3601 53.3332 40.0001 53.3332C32.6401 53.3332 26.6667 47.3598 26.6667 39.9998C26.6667 32.6398 32.6401 26.6665 40.0001 26.6665C47.3601 26.6665 53.3334 32.6398 53.3334 39.9998Z" fill="#1ABCFE"/></g><defs><clipPath id="clip0_912_3"><rect width="53.3333" height="80" fill="white"/></clipPath></defs></svg>`;
      const figmaLogoUrl = `data:image/svg+xml;base64,${btoa(figmaSvg)}`;

      const figmaTemplate = {
        name: "Figma",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#000000"/></g><image x="35" y="25" width="30" height="50" href="${figmaLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: figmaLogoUrl,
          colorType: "single",
          foregroundColor: "#000000",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#000000",
          cornerDotColor: "#000000",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10 },
        },
      };

      // Define Dropbox template.
      const dropboxSvg = `<svg role="img" width="24" height="24" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><title>Dropbox</title><path fill="#0061FF" d="M6 1.807L0 5.629l6 3.822 6.001-3.822L6 1.807zM18 1.807l-6 3.822 6 3.822 6-3.822-6-3.822zM0 13.274l6 3.822 6.001-3.822L6 9.452l-6 3.822zM18 9.452l-6 3.822 6 3.822 6-3.822-6-3.822zM6 18.371l6.001 3.822 6-3.822-6-3.822L6 18.371z"/></svg>`;
      const dropboxLogoUrl = `data:image/svg+xml;base64,${btoa(dropboxSvg)}`;

      const dropboxTemplate = {
        name: "Dropbox",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#0061FF"/></g><image x="30" y="30" width="40" height="40" href="${dropboxLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: dropboxLogoUrl,
          colorType: "single",
          foregroundColor: "#0061FF",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#0061FF",
          cornerDotColor: "#0061FF",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10 },
        },
      };

      // Define Threads template.
      const threadsSvg = `<svg width="24" height="24" role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><title>Threads</title><path d="M12.186 24h-.007c-3.581-.024-6.334-1.205-8.184-3.509C2.35 18.44 1.5 15.586 1.472 12.01v-.017c.03-3.579.879-6.43 2.525-8.482C5.845 1.205 8.6.024 12.18 0h.014c2.746.02 5.043.725 6.826 2.098 1.677 1.29 2.858 3.13 3.509 5.467l-2.04.569c-1.104-3.96-3.898-5.984-8.304-6.015-2.91.022-5.11.936-6.54 2.717C4.307 6.504 3.616 8.914 3.589 12c.027 3.086.718 5.496 2.057 7.164 1.43 1.783 3.631 2.698 6.54 2.717 2.623-.02 4.358-.631 5.8-2.045 1.647-1.613 1.618-3.593 1.09-4.798-.31-.71-.873-1.3-1.634-1.75-.192 1.352-.622 2.446-1.284 3.272-.886 1.102-2.14 1.704-3.73 1.79-1.202.065-2.361-.218-3.259-.801-1.063-.689-1.685-1.74-1.752-2.964-.065-1.19.408-2.285 1.33-3.082.88-.76 2.119-1.207 3.583-1.291a13.853 13.853 0 0 1 3.02.142c-.126-.742-.375-1.332-.75-1.757-.513-.586-1.308-.883-2.359-.89h-.029c-.844 0-1.992.232-2.721 1.32L7.734 7.847c.98-1.454 2.568-2.256 4.478-2.256h.044c3.194.02 5.097 1.975 5.287 5.388.108.046.216.094.321.142 1.49.7 2.58 1.761 3.154 3.07.797 1.82.871 4.79-1.548 7.158-1.85 1.81-4.094 2.628-7.277 2.65Zm1.003-11.69c-.242 0-.487.007-.739.021-1.836.103-2.98.946-2.916 2.143.067 1.256 1.452 1.839 2.784 1.767 1.224-.065 2.818-.543 3.086-3.71a10.5 10.5 0 0 0-2.215-.221z"/></svg>`;
      const threadsLogoUrl = `data:image/svg+xml;base64,${btoa(threadsSvg)}`;

      const threadsTemplate = {
        name: "Threads",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#000000"/></g><image x="30" y="30" width="40" height="40" href="${threadsLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: threadsLogoUrl,
          colorType: "single",
          foregroundColor: "#000000",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#000000",
          cornerDotColor: "#000000",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8 },
        },
      };

      // Define Telegram template.
      const telegramSvg = `<svg viewBox="0 0 256 256" xmlns="http://www.w3.org/2000/svg" width="256" height="256" preserveAspectRatio="xMidYMid"><defs><linearGradient id="a" x1="50%" x2="50%" y1="0%" y2="100%"><stop offset="0%" stop-color="#2AABEE"/><stop offset="100%" stop-color="#229ED9"/></linearGradient></defs><path fill="url(#a)" d="M128 0C94.06 0 61.48 13.494 37.5 37.49A128.038 128.038 0 0 0 0 128c0 33.934 13.5 66.514 37.5 90.51C61.48 242.506 94.06 256 128 256s66.52-13.494 90.5-37.49c24-23.996 37.5-56.576 37.5-90.51 0-33.934-13.5-66.514-37.5-90.51C194.52 13.494 161.94 0 128 0Z"/><path fill="#FFF" d="M57.94 126.648c37.32-16.256 62.2-26.974 74.64-32.152 35.56-14.786 42.94-17.354 47.76-17.441 1.06-.017 3.42.245 4.96 1.49 1.28 1.05 1.64 2.47 1.82 3.467.16.996.38 3.266.2 5.038-1.92 20.24-10.26 69.356-14.5 92.026-1.78 9.592-5.32 12.808-8.74 13.122-7.44.684-13.08-4.912-20.28-9.63-11.26-7.386-17.62-11.982-28.56-19.188-12.64-8.328-4.44-12.906 2.76-20.386 1.88-1.958 34.64-31.748 35.26-34.45.08-.338.16-1.598-.6-2.262-.74-.666-1.84-.438-2.64-.258-1.14.256-19.12 12.152-54 35.686-5.1 3.508-9.72 5.218-13.88 5.128-4.56-.098-13.36-2.584-19.9-4.708-8-2.606-14.38-3.984-13.82-8.41.28-2.304 3.46-4.662 9.52-7.072Z"/></svg>`;
      const telegramLogoUrl = `data:image/svg+xml;base64,${btoa(telegramSvg)}`;

      const telegramTemplate = {
        name: "Telegram",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#24A1DE"/></g><image x="30" y="30" width="40" height="40" href="${telegramLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: telegramLogoUrl,
          colorType: "single",
          foregroundColor: "#24A1DE",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#24A1DE",
          cornerDotColor: "#24A1DE",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8 },
        },
      };

      // Define Pinterest template.
      const pinterestSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 256 256"><path fill="#CB1F27" d="M0 128.002c0 52.414 31.518 97.442 76.619 117.239c-.36-8.938-.064-19.668 2.228-29.393c2.461-10.391 16.47-69.748 16.47-69.748s-4.089-8.173-4.089-20.252c0-18.969 10.994-33.136 24.686-33.136c11.643 0 17.268 8.745 17.268 19.217c0 11.704-7.465 29.211-11.304 45.426c-3.207 13.578 6.808 24.653 20.203 24.653c24.252 0 40.586-31.149 40.586-68.055c0-28.054-18.895-49.052-53.262-49.052c-38.828 0-63.017 28.956-63.017 61.3c0 11.152 3.288 19.016 8.438 25.106c2.368 2.797 2.697 3.922 1.84 7.134c-.614 2.355-2.024 8.025-2.608 10.272c-.852 3.242-3.479 4.401-6.409 3.204c-17.884-7.301-26.213-26.886-26.213-48.902c0-36.361 30.666-79.961 91.482-79.961c48.87 0 81.035 35.364 81.035 73.325c0 50.213-27.916 87.726-69.066 87.726c-13.819 0-26.818-7.47-31.271-15.955c0 0-7.431 29.492-9.005 35.187c-2.714 9.869-8.026 19.733-12.883 27.421a127.897 127.897 0 0 0 36.277 5.249c70.684 0 127.996-57.309 127.996-128.005C256.001 57.309 198.689 0 128.005 0C57.314 0 0 57.309 0 128.002"/></svg>`;
      const pinterestLogoUrl = `data:image/svg+xml;base64,${btoa(pinterestSvg)}`;

      const pinterestTemplate = {
        name: "Pinterest",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#CB1F27"/></g><image x="30" y="30" width="40" height="40" href="${pinterestLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: pinterestLogoUrl,
          colorType: "single",
          foregroundColor: "#CB1F27",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#CB1F27",
          cornerDotColor: "#CB1F27",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8 },
        },
      };

      // Define Twitch template.
      const twitchSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="2400" height="2800" xml:space="preserve" viewBox="0 0 2400 2800"><path fill="#fff" d="m2200 1300-400 400h-400l-350 350v-350H600V200h1600z"/><g fill="#9146ff"><path d="M500 0 0 500v1800h600v500l500-500h400l900-900V0H500zm1700 1300-400 400h-400l-350 350v-350H600V200h1600v1100z"/><path d="M1700 550h200v600h-200zm-550 0h200v600h-200z"/></g></svg>`;
      const twitchLogoUrl = `data:image/svg+xml;base64,${btoa(twitchSvg)}`;

      const twitchTemplate = {
        name: "Twitch",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#9146FF"/></g><image x="30" y="30" width="40" height="40" href="${twitchLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: twitchLogoUrl,
          colorType: "single",
          foregroundColor: "#9146FF",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#9146FF",
          cornerDotColor: "#9146FF",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8 },
        },
      };

      // Define Wi-Fi template.
      const wifiSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" width="24" height="24"><path fill-rule="evenodd" d="M1.371 8.143c5.858-5.857 15.356-5.857 21.213 0a.75.75 0 0 1 0 1.061l-.53.53a.75.75 0 0 1-1.06 0c-4.98-4.979-13.053-4.979-18.032 0a.75.75 0 0 1-1.06 0l-.53-.53a.75.75 0 0 1 0-1.06Zm3.182 3.182c4.1-4.1 10.749-4.1 14.85 0a.75.75 0 0 1 0 1.061l-.53.53a.75.75 0 0 1-1.062 0 8.25 8.25 0 0 0-11.667 0 .75.75 0 0 1-1.06 0l-.53-.53a.75.75 0 0 1 0-1.06Zm3.204 3.182a6 6 0 0 1 8.486 0 .75.75 0 0 1 0 1.061l-.53.53a.75.75 0 0 1-1.061 0 3.75 3.75 0 0 0-5.304 0 .75.75 0 0 1-1.06 0l-.53-.53a.75.75 0 0 1 0-1.06Zm3.182 3.182a1.5 1.5 0 0 1 2.122 0 .75.75 0 0 1 0 1.061l-.53.53a.75.75 0 0 1-1.061 0l-.53-.53a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" /></svg>`;
      const wifiLogoUrl = `data:image/svg+xml;base64,${btoa(wifiSvg)}`;

      const wifiTemplate = {
        name: "Wi-Fi",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#0284c7"/></g><image x="30" y="30" width="40" height="40" href="${wifiLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: wifiLogoUrl,
          colorType: "single",
          foregroundColor: "#0284c7",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#0284c7",
          cornerDotColor: "#0284c7",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8 },
        },
      };

      // Define Google Maps template.
      const gmapsSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="92.3" height="132.3" viewBox="0 0 92.3 132.3"><path fill="#1a73e8" d="M60.2 2.2C55.8.8 51 0 46.1 0 32 0 19.3 6.4 10.8 16.5l21.8 18.3L60.2 2.2z"/><path fill="#ea4335" d="M10.8 16.5C4.1 24.5 0 34.9 0 46.1c0 8.7 1.7 15.7 4.6 22l28-33.3-21.8-18.3z"/><path fill="#4285f4" d="M46.2 28.5c9.8 0 17.7 7.9 17.7 17.7 0 4.3-1.6 8.3-4.2 11.4 0 0 13.9-16.6 27.5-32.7-5.6-10.8-15.3-19-27-22.7L32.6 34.8c3.3-3.8 8.1-6.3 13.6-6.3"/><path fill="#fbbc04" d="M46.2 63.8c-9.8 0-17.7-7.9-17.7-17.7 0-4.3 1.5-8.3 4.1-11.3l-28 33.3c4.8 10.6 12.8 19.2 21 29.9l34.1-40.5c-3.3 3.9-8.1 6.3-13.5 6.3"/><path fill="#34a853" d="M59.1 109.2c15.4-24.1 33.3-35 33.3-63 0-7.7-1.9-14.9-5.2-21.3L25.6 98c2.6 3.4 5.3 7.3 7.9 11.3 9.4 14.5 6.8 23.1 12.8 23.1s3.4-8.7 12.8-23.2"/></svg>`;
      const gmapsLogoUrl = `data:image/svg+xml;base64,${btoa(gmapsSvg)}`;

      const gmapsTemplate = {
        name: "Google Maps",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#EA4335"/></g><image x="36" y="30" width="28" height="40" href="${gmapsLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: gmapsLogoUrl,
          colorType: "single",
          foregroundColor: "#EA4335",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#EA4335",
          cornerDotColor: "#EA4335",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.25, margin: 8 },
        },
      };

      // Define Microsoft Teams template.
      const teamsSvg = `<svg xmlns="http://www.w3.org/2000/svg" fill="none" width="36" height="38" viewBox="4 4 36 38"><path fill="url(#a)" d="M22 20h12a6 6 0 0 1 6 6v10a6 6 0 0 1-12 0V26a6 6 0 0 0-6-6Z"/><path fill="url(#b)" d="M8 24a6 6 0 0 1 6-6h8a6 6 0 0 1 6 6v12a6 6 0 0 0 6 6H18c-5.523 0-10-4.477-10-10v-8Z"/><path fill="url(#c)" fill-opacity=".7" d="M8 24a6 6 0 0 1 6-6h8a6 6 0 0 1 6 6v12a6 6 0 0 0 6 6H18c-5.523 0-10-4.477-10-10v-8Z"/><path fill="url(#d)" fill-opacity=".7" d="M8 24a6 6 0 0 1 6-6h8a6 6 0 0 1 6 6v12a6 6 0 0 0 6 6H18c-5.523 0-10-4.477-10-10v-8Z"/><path fill="url(#e)" d="M33 18a5 5 0 1 0 0-10 5 5 0 0 0 0 10Z"/><path fill="url(#f)" fill-opacity=".46" d="M33 18a5 5 0 1 0 0-10 5 5 0 0 0 0 10Z"/><path fill="url(#g)" fill-opacity=".4" d="M33 18a5 5 0 1 0 0-10 5 5 0 0 0 0 10Z"/><path fill="url(#h)" d="M18 16a6 6 0 1 0 0-12 6 6 0 0 0 0 12Z"/><path fill="url(#i)" fill-opacity=".6" d="M18 16a6 6 0 1 0 0-12 6 6 0 0 0 0 12Z"/><path fill="url(#j)" fill-opacity=".5" d="M18 16a6 6 0 1 0 0-12 6 6 0 0 0 0 12Z"/><rect width="16" height="16" x="4" y="23" fill="url(#k)" rx="3.25"/><rect width="16" height="16" x="4" y="23" fill="url(#l)" fill-opacity=".7" rx="3.25"/><path fill="#fff" d="M15.48 28.105h-2.448v7.466h-2.065v-7.466H8.52V26.43h6.96v1.676Z"/><defs><radialGradient id="a" cx="0" cy="0" r="1" gradientTransform="matrix(13.4784 0 0 33.2694 39.797 22.174)" gradientUnits="userSpaceOnUse"><stop stop-color="#A98AFF"/><stop offset=".14" stop-color="#8C75FF"/><stop offset=".565" stop-color="#5F50E2"/><stop offset=".9" stop-color="#3C2CB8"/></radialGradient><radialGradient id="b" cx="0" cy="0" r="1" gradientTransform="matrix(12.1875 30.39997 -30.74442 12.3256 8.812 16.4)" gradientUnits="userSpaceOnUse"><stop stop-color="#85C2FF"/><stop offset=".69" stop-color="#7588FF"/><stop offset="1" stop-color="#6459FE"/></radialGradient><radialGradient id="d" cx="0" cy="0" r="1" gradientTransform="rotate(113.326 8.093 17.645) scale(19.2186 15.4273)" gradientUnits="userSpaceOnUse"><stop stop-color="#BD96FF"/><stop offset=".687" stop-color="#BD96FF" stop-opacity="0"/></radialGradient><radialGradient id="e" cx="0" cy="0" r="1" gradientTransform="matrix(0 -10 12.6216 0 33 11.571)" gradientUnits="userSpaceOnUse"><stop offset=".268" stop-color="#6868F7"/><stop offset="1" stop-color="#3923B1"/></radialGradient><radialGradient id="f" cx="0" cy="0" r="1" gradientTransform="matrix(5.47024 4.59847 -6.65117 7.91208 28.867 10.544)" gradientUnits="userSpaceOnUse"><stop offset=".271" stop-color="#A1D3FF"/><stop offset=".813" stop-color="#A1D3FF" stop-opacity="0"/></radialGradient><radialGradient id="g" cx="0" cy="0" r="1" gradientTransform="rotate(-41.658 32.118 -43.42) scale(8.51275 20.8824)" gradientUnits="userSpaceOnUse"><stop stop-color="#E3ACFD"/><stop offset=".816" stop-color="#9FA2FF" stop-opacity="0"/></radialGradient><radialGradient id="h" cx="0" cy="0" r="1" gradientTransform="matrix(0 -12 15.146 0 18 8.286)" gradientUnits="userSpaceOnUse"><stop offset=".268" stop-color="#8282FF"/><stop offset="1" stop-color="#3923B1"/></radialGradient><radialGradient id="i" cx="0" cy="0" r="1" gradientTransform="rotate(40.052 -3.155 21.416) scale(8.57554 12.4035)" gradientUnits="userSpaceOnUse"><stop offset=".271" stop-color="#A1D3FF"/><stop offset=".813" stop-color="#A1D3FF" stop-opacity="0"/></radialGradient><radialGradient id="j" cx="0" cy="0" r="1" gradientTransform="rotate(-41.658 20.382 -26.516) scale(10.2153 25.0589)" gradientUnits="userSpaceOnUse"><stop stop-color="#E3ACFD"/><stop offset=".816" stop-color="#9FA2FF" stop-opacity="0"/></radialGradient><radialGradient id="k" cx="0" cy="0" r="1" gradientTransform="rotate(45 -25.763 16.328) scale(22.6274)" gradientUnits="userSpaceOnUse"><stop offset=".047" stop-color="#688EFF"/><stop offset=".947" stop-color="#230F94"/></radialGradient><radialGradient id="l" cx="0" cy="0" r="1" gradientTransform="matrix(0 11.2 -13.0702 0 12 32.6)" gradientUnits="userSpaceOnUse"><stop offset=".571" stop-color="#6965F6" stop-opacity="0"/><stop offset="1" stop-color="#8F8FFF"/></radialGradient><linearGradient id="c" x1="20.594" x2="20.594" y1="18" y2="42" gradientUnits="userSpaceOnUse"><stop offset=".801" stop-color="#6864F6" stop-opacity="0"/><stop offset="1" stop-color="#5149DE"/></linearGradient></defs></svg>`;
      const teamsLogoUrl = `data:image/svg+xml;base64,${btoa(teamsSvg)}`;

      const teamsTemplate = {
        name: "Teams",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#6264A7"/></g><image x="31" y="29" width="38" height="42" href="${teamsLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: teamsLogoUrl,
          colorType: "single",
          foregroundColor: "#6264A7",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#6264A7",
          cornerDotColor: "#6264A7",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.35, margin: 6 },
        },
      };

      // Define WeChat template.
      const wechatSvg = `<svg fill="#07C160" role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" width="24" height="24"><title>WeChat</title><path d="M8.691 2.188C3.891 2.188 0 5.476 0 9.53c0 2.212 1.17 4.203 3.002 5.55a.59.59 0 0 1 .213.665l-.39 1.48c-.019.07-.048.141-.048.213 0 .163.13.295.29.295a.326.326 0 0 0 .167-.054l1.903-1.114a.864.864 0 0 1 .717-.098 10.16 10.16 0 0 0 2.837.403c.276 0 .543-.027.811-.05-.857-2.578.157-4.972 1.932-6.446 1.703-1.415 3.882-1.98 5.853-1.838-.576-3.583-4.196-6.348-8.596-6.348zM5.785 5.991c.642 0 1.162.529 1.162 1.18a1.17 1.17 0 0 1-1.162 1.178A1.17 1.17 0 0 1 4.623 7.17c0-.651.52-1.18 1.162-1.18zm5.813 0c.642 0 1.162.529 1.162 1.18a1.17 1.17 0 0 1-1.162 1.178 1.17 1.17 0 0 1-1.162-1.178c0-.651.52-1.18 1.162-1.18zm5.34 2.867c-1.797-.052-3.746.512-5.28 1.786-1.72 1.428-2.687 3.72-1.78 6.22.942 2.453 3.666 4.229 6.884 4.229.826 0 1.622-.12 2.361-.336a.722.722 0 0 1 .598.082l1.584.926a.272.272 0 0 0 .14.047c.134 0 .24-.111.24-.247 0-.06-.023-.12-.038-.177l-.327-1.233a.582.582 0 0 1-.023-.156.49.49 0 0 1 .201-.398C23.024 18.48 24 16.82 24 14.98c0-3.21-2.931-5.837-6.656-6.088V8.89c-.135-.01-.27-.027-.407-.03zm-2.53 3.274c.535 0 .969.44.969.982a.976.976 0 0 1-.969.983.976.976 0 0 1-.969-.983c0-.542.434-.982.97-.982zm4.844 0c.535 0 .969.44.969.982a.976.976 0 0 1-.969.983.976.976 0 0 1-.969-.983c0-.542.434-.982.969-.982z"/></svg>`;
      const wechatLogoUrl = `data:image/svg+xml;base64,${btoa(wechatSvg)}`;

      const wechatTemplate = {
        name: "WeChat",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#07C160"/></g><image x="30" y="30" width="40" height="40" href="${wechatLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: wechatLogoUrl,
          colorType: "single",
          foregroundColor: "#07C160",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#07C160",
          cornerDotColor: "#07C160",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.35, margin: 6 },
        },
      };

      // Define Linktree template.
      const linktreeSvg = `<svg fill="#43E55E" role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" width="24" height="24"><title>Linktree</title><path d="m13.73635 5.85251 4.00467-4.11665 2.3248 2.3808-4.20064 4.00466h5.9085v3.30473h-5.9365l4.22865 4.10766-2.3248 2.3338L12.0005 12.099l-5.74052 5.76852-2.3248-2.3248 4.22864-4.10766h-5.9375V8.12132h5.9085L3.93417 4.11666l2.3248-2.3808 4.00468 4.11665V0h3.4727zm-3.4727 10.30614h3.4727V24h-3.4727z"/></svg>`;
      const linktreeLogoUrl = `data:image/svg+xml;base64,${btoa(linktreeSvg)}`;

      const linktreeTemplate = {
        name: "Linktree",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#43E55E"/></g><image x="30" y="30" width="40" height="40" href="${linktreeLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: linktreeLogoUrl,
          colorType: "single",
          foregroundColor: "#000000",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "square",
          cornerColor: "#000000",
          cornerDotColor: "#43E55E",
          cornersDotStyle: "square",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10 },
        },
      };

      // Define LINE template.
      const lineTemplates = [
        // 1. Icon (Green)
        {
          name: "LINE",
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#4cc764"/></g><image x="30" y="30" width="40" height="40" href="${iconGreenUrl}" /></svg>`,
          options: {
            ...defaultQrOptions,
            errorCorrectionLevel: "H",
            logo: iconGreenUrl,
            colorType: "single",
            foregroundColor: "#4cc764",
            backgroundColor: "#ffffff",
            dotsStyle: "dots",
            cornersStyle: "extra-rounded",
            cornerColor: "#4cc764",
            cornerDotColor: "#4cc764",
            cornersDotStyle: "extra-rounded",
            imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 6 },
          },
        },
        // 2. Text Logo (Green)
        {
          name: "LINE (Text)",
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#4cc764"/></g><image x="20" y="40" width="60" height="20" href="${textGreenUrl}" /></svg>`,
          options: {
            ...defaultQrOptions,
            errorCorrectionLevel: "H",
            logo: textGreenUrl,
            colorType: "single",
            foregroundColor: "#4cc764",
            backgroundColor: "#ffffff",
            dotsStyle: "dots",
            cornersStyle: "extra-rounded",
            cornerColor: "#4cc764",
            cornerDotColor: "#4cc764",
            cornersDotStyle: "extra-rounded",
            imageOptions: { hideBackgroundDots: true, imageSize: 0.35, margin: 6 },
          },
        },
      ];

      // Group templates by category.
      this.presetTemplateGroups = [
        {
          name: "Styles & Patterns",
          templates: basicTemplates
        },
        {
          name: "SNS & Communication",
          templates: [
            facebookTemplate,
            whatsappTemplate,
            wechatTemplate,
            instagramTemplate,
            tiktokTemplate,
            xTemplate,
            telegramTemplate,
            discordTemplate,
            threadsTemplate,
            pinterestTemplate,
            twitchTemplate,
            linktreeTemplate,
            lineTemplates[0],
            lineTemplates[1]
          ]
        },
        {
          name: "Business & Tools",
          templates: [
            wifiTemplate,
            gmapsTemplate,
            linkedinTemplate,
            gmailTemplate,
            googleDriveTemplate,
            dropboxTemplate,
            slackTemplate,
            teamsTemplate,
            zoomTemplate,
            notionTemplate,
            figmaTemplate,
            githubTemplate,
            youtubeTemplate
          ]
        },
        {
          name: "Finance & Crypto",
          templates: [
            paypalTemplate,
            venmoTemplate,
            paypayTemplate,
            bitcoinTemplate,
            ethereumTemplate,
            solanaTemplate
          ]
        },
        {
          name: "Entertainment & Media",
          templates: [
            netflixTemplate,
            spotifyTemplate,
            appleMusicTemplate,
            soundcloudTemplate,
            steamTemplate,
            noteTemplate
          ]
        }
      ];

      // Keep a flat array for existing processes.
      this.presetTemplates = this.presetTemplateGroups.flatMap(group => group.templates);
    },
    getActiveType() {
      return this.qrTypes.find((t) => t.id === this.selectedType) || {};
    },
    getActiveProjectName() {
      if (!this.projects) return 'QR_Codes';
      if (this.currentProjectId === 'all') return 'All_Projects';
      const p = this.projects.find(proj => proj.id === this.currentProjectId);
      return p ? p.name.replace(/[\\/:*?"<>|]/g, "-").replace(/\s+/g, "_") : 'Project';
    },
    showFlashNotification(message, isUpdate = false) {
      this.notificationMessage = message;
      this.isUpdateNotification = isUpdate;
      this.showNotification = true;
      if (this.notificationTimeout) clearTimeout(this.notificationTimeout);
      this.notificationTimeout = setTimeout(() => {
        this.showNotification = false;
        setTimeout(() => { this.isUpdateNotification = false; }, 300);
      }, 4000);
    },
    generateUniqueId() {
      if (typeof crypto !== 'undefined' && crypto.randomUUID) {
        return crypto.randomUUID();
      }
      // Fallback for randomUUID (Secure random generation).
      const array = new Uint32Array(1);
      crypto.getRandomValues(array);
      return Date.now().toString(36) + array[0].toString(36);
    },
    getSnsPlaceholder() {
      const placeholders = {
        x: "grinds_jp",
        instagram: "grinds_official",
        facebook: "GrindJapan",
        line: "grinds",
        youtube: "grinds_channel",
        tiktok: "grinds.official",
        threads: "Username (e.g. grinds_official)",
        linkedin: "Username (e.g. john-doe)",
        pinterest: "Username (e.g. grinds)",
        whatsapp: "Phone number with country code (e.g. 1234567890)",
        telegram: "Username (e.g. grinds)",
        github: "Username (e.g. octocat)",
        discord: "Server invite code or URL",
        twitch: "Channel name (e.g. grinds_channel)",
        paypal: "PayPal.me ID (e.g. grinds)",
        venmo: "Venmo Username (e.g. john-doe)",
        paypay: "Payment link URL (e.g. https://qr.paypay.ne.jp/...)",
      };
      return placeholders[this.formData.sns.service] || "";
    },
    buildDotsOptions() {
      const fixColor = (color, def) => /^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(color) ? (color.startsWith('#') ? color : '#' + color) : def;
      const fgColor = fixColor(this.qrOptions.foregroundColor, "#000000");

      if (this.qrOptions.colorType === "gradient") {
        return {
          type: this.qrOptions.dotsStyle,
          gradient: {
            type: this.qrOptions.gradient.type,
            rotation: Number(this.qrOptions.gradient.rotation) * Math.PI / 180,
            colorStops: [
              {
                offset: 0,
                color: fixColor(this.qrOptions.gradient.color1, "#6366f1"),
              },
              {
                offset: 1,
                color: fixColor(this.qrOptions.gradient.color2, "#a855f7"),
              },
            ],
          },
        };
      }
      return {
        type: this.qrOptions.dotsStyle,
        color: fgColor,
        gradient: null,
      };
    },
    buildCornersSquareOptions() {
      const fixColor = (color, def) => /^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(color) ? (color.startsWith('#') ? color : '#' + color) : def;
      return {
        type: this.qrOptions.cornersStyle,
        color: fixColor(this.qrOptions.cornerColor, "#000000"),
      };
    },
    buildCornersDotOptions() {
      const fixColor = (color, def) => /^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(color) ? (color.startsWith('#') ? color : '#' + color) : def;
      return {
        type: this.qrOptions.cornersDotStyle,
        color: fixColor(this.qrOptions.cornerDotColor, "#000000"),
      };
    },
    validateUrl() {
      const url = this.formData.url.address || "";
      if (url.trim() === "") {
        this.urlError = "URL is required.";
      } else {
        try {
          let fullUrl = url;
          if (!/^https?:\/\//i.test(fullUrl)) {
            fullUrl = "https://" + fullUrl;
          }
          new URL(fullUrl);
          this.urlError = "";
        } catch (_) {
          this.urlError = "Invalid URL format.";
        }
      }
      this.updateQrCode();
    },
    removeLogo() {
      this.qrOptions.logo = "";
      this.logoFileName = "";
      this.updateQrCode();
    },
    formatUtmParam(key) {
      if (this.formData.url.utm[key]) {
        this.formData.url.utm[key] = String(this.formData.url.utm[key] || "").toLowerCase().trim().replace(/\s+/g, '-');
        this.updateQrCode(false);
      }
    },
    formatVariationUtmParam(variation, key) {
      if (variation.utm[key]) {
        variation.utm[key] = String(variation.utm[key] || "").toLowerCase().trim().replace(/\s+/g, '-');
        this.updateQrCode(false);
      }
    },

    // --- UTM Presets CRUD ---
    loadUtmPresets() {
      try {
        const stored = localStorage.getItem('grindsUtmPresets');
        if (stored) {
          this.utmPresets = JSON.parse(stored);
        }
      } catch (e) {
        console.warn('Failed to load UTM presets', e);
        this.utmPresets = [];
      }
    },
    saveUtmPresets() {
      try {
        localStorage.setItem('grindsUtmPresets', JSON.stringify(this.utmPresets));
      } catch (e) {
        this.showFlashNotification('Could not save UTM presets due to storage limits.');
      }
    },
    addVariationFromPreset(preset) {
      this.formData.url.variations.push({
        id: this.generateUniqueId(),
        name: preset.name,
        utm: JSON.parse(JSON.stringify(preset.utm))
      });
      this.hasUnsavedEdit = true;
      this.updateQrCode(false);
    },
    async saveCurrentRowAsPreset(variation) {
      const name = await appPrompt('Enter a name for this UTM preset:', 'text');
      if (!name || !name.trim()) return;
      this.utmPresets.push({
        id: this.generateUniqueId(),
        name: name.trim(),
        utm: JSON.parse(JSON.stringify(variation.utm))
      });
      this.saveUtmPresets();
      this.showFlashNotification(`Preset "${name.trim()}" saved.`);
      this.hapticFeedback('success');
    },
    deleteUtmPreset(presetId) {
      if (!confirm("Are you sure you want to delete this preset?")) return;
      this.utmPresets = this.utmPresets.filter(p => p.id !== presetId);
      this.saveUtmPresets();
      this.showFlashNotification('Preset deleted.');
    },
    async renameUtmPreset(presetId) {
      const preset = this.utmPresets.find(p => p.id === presetId);
      if (!preset) return;
      const newName = await appPrompt(`Rename "${preset.name}":`, 'text');
      if (!newName || !newName.trim()) return;
      preset.name = newName.trim();
      this.saveUtmPresets();
    },

    // --- URLs Export (Campaigns) ---
    getUrlsForExport() {
      const targets = this.savedQRCodes.filter(qr => this.selectedIds.includes(qr.id) && qr.type === 'url');
      const list = [];
      targets.forEach(qr => {
        let baseUrlStr = qr.formData.url.address?.trim() || "";
        if (baseUrlStr && !/^[a-zA-Z][a-zA-Z0-9+.-]*:/i.test(baseUrlStr)) {
          baseUrlStr = 'https://' + baseUrlStr;
        }
        let finalBaseUrl = baseUrlStr;
        try {
          const urlObj = new URL(baseUrlStr);
          const utm = qr.formData.url.utm;
          if (utm) {
             const cleanParam = (val) => String(val || "").trim().replace(/^[?&]+/, '');
             if (utm.source && String(utm.source).trim()) urlObj.searchParams.set("utm_source", cleanParam(utm.source));
             if (utm.medium && String(utm.medium).trim()) urlObj.searchParams.set("utm_medium", cleanParam(utm.medium));
             if (utm.campaign && String(utm.campaign).trim()) urlObj.searchParams.set("utm_campaign", cleanParam(utm.campaign));
             if (utm.term && String(utm.term).trim()) urlObj.searchParams.set("utm_term", cleanParam(utm.term));
             if (utm.content && String(utm.content).trim()) urlObj.searchParams.set("utm_content", cleanParam(utm.content));
          }
          finalBaseUrl = urlObj.toString();
        } catch(e) {}

        list.push({
          qrName: qr.name || 'Untitled',
          variantName: 'Base URL',
          url: finalBaseUrl,
          utmSource: qr.formData.url.utm?.source || '',
          utmMedium: qr.formData.url.utm?.medium || '',
          utmCampaign: qr.formData.url.utm?.campaign || '',
          utmTerm: qr.formData.url.utm?.term || '',
          utmContent: qr.formData.url.utm?.content || ''
        });

        if (qr.formData.url.variations && qr.formData.url.variations.length > 0) {
          qr.formData.url.variations.forEach(v => {
            list.push({
              qrName: qr.name || 'Untitled',
              variantName: v.name || 'Variant',
              url: this.generateVariantUrl(qr.formData.url.address, v),
              utmSource: v.utm?.source || '',
              utmMedium: v.utm?.medium || '',
              utmCampaign: v.utm?.campaign || '',
              utmTerm: v.utm?.term || '',
              utmContent: v.utm?.content || ''
            });
          });
        }
      });
      return list;
    },
    downloadUrlsAsCsv() {
      const list = this.getUrlsForExport();
      if (list.length === 0) return;
      const headers = ["QR Name", "Variant Name", "Final URL", "UTM Source", "UTM Medium", "UTM Campaign", "UTM Term", "UTM Content"];
      const escapeCSV = (str) => {
        let val = String(str || "");
        if (/^[=\-+\@\t\r]/.test(val)) {
          val = "'" + val;
        }
        return `"${val.replace(/"/g, '""')}"`;
      };

      const csvRows = [headers.map(escapeCSV).join(",")];
      list.forEach(item => {
        csvRows.push([
          item.qrName, item.variantName, item.url, item.utmSource, item.utmMedium, item.utmCampaign, item.utmTerm, item.utmContent
        ].map(escapeCSV).join(","));
      });

      const csvContent = "\uFEFF" + csvRows.join("\r\n");
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      const now = new Date();
      const dateStr = `${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}`;
      link.download = `Campaign_URLs_${dateStr}.csv`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      setTimeout(() => URL.revokeObjectURL(url), 1000);

      this.showUrlExportModal = false;
      this.showFlashNotification(`Exported ${list.length} URLs as CSV.`);
      this.hapticFeedback('success');
    },
    copyUrlsAsMarkdown() {
      const targets = this.savedQRCodes.filter(qr => this.selectedIds.includes(qr.id) && qr.type === 'url');
      if (targets.length === 0) return;

      let md = "## Campaign URLs\n\n";
      targets.forEach(qr => {
        md += `### ${qr.name || 'Untitled'}\n`;

        let baseUrlStr = qr.formData.url.address?.trim() || "";
        if (baseUrlStr && !/^[a-zA-Z][a-zA-Z0-9+.-]*:/i.test(baseUrlStr)) baseUrlStr = 'https://' + baseUrlStr;
        let finalBaseUrl = baseUrlStr;
        try {
          const urlObj = new URL(baseUrlStr);
          const utm = qr.formData.url.utm;
          if (utm) {
             const cleanParam = (val) => String(val || "").trim().replace(/^[?&]+/, '');
             if (utm.source && String(utm.source).trim()) urlObj.searchParams.set("utm_source", cleanParam(utm.source));
             if (utm.medium && String(utm.medium).trim()) urlObj.searchParams.set("utm_medium", cleanParam(utm.medium));
             if (utm.campaign && String(utm.campaign).trim()) urlObj.searchParams.set("utm_campaign", cleanParam(utm.campaign));
             if (utm.term && String(utm.term).trim()) urlObj.searchParams.set("utm_term", cleanParam(utm.term));
             if (utm.content && String(utm.content).trim()) urlObj.searchParams.set("utm_content", cleanParam(utm.content));
          }
          finalBaseUrl = urlObj.toString();
        } catch(e) {}

        md += `- **Base URL:** ${finalBaseUrl}\n`;

        if (qr.formData.url.variations && qr.formData.url.variations.length > 0) {
          qr.formData.url.variations.forEach(v => {
             const vUrl = this.generateVariantUrl(qr.formData.url.address, v);
             md += `- **${v.name || 'Variant'}:** ${vUrl}\n`;
          });
        }
        md += "\n";
      });

      this.copyToTextClipboard(md);
      this.showUrlExportModal = false;
      this.showFlashNotification("Copied Markdown to clipboard.");
      this.hapticFeedback('success');
    },

    // --- Smart Paste ---
    handleSmartUrlPaste(event) {
      const text = (event.clipboardData || window.clipboardData).getData('text/plain');
      if (!text) return;

      const lines = text.split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0);
      // Detect lines that look like URLs
      const urls = lines.filter(l => /^https?:\/\//i.test(l) || /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}/.test(l));

      if (urls.length > 0) {
        const formatUrl = (u) => /^https?:\/\//i.test(u) ? u : 'https://' + u;

        const parseUrlWithUtm = (urlStr) => {
          let base = formatUrl(urlStr);
          let utm = { source: '', medium: '', campaign: '', term: '', content: '' };
          let hasUtm = false;
          try {
            const urlObj = new URL(base);
            const params = new URLSearchParams(urlObj.search);
            ['source', 'medium', 'campaign', 'term', 'content'].forEach(key => {
              const utmKey = `utm_${key}`;
              if (params.has(utmKey)) {
                utm[key] = params.get(utmKey);
                params.delete(utmKey);
                hasUtm = true;
              }
            });
            if (hasUtm) {
              urlObj.search = params.toString();
              base = urlObj.toString().replace(/\?$/, '');
            }
          } catch(e) {}
          return { base, utm, hasUtm };
        };

        // If it's a single URL without UTMs, rely on default browser paste behavior
        if (urls.length === 1 && !parseUrlWithUtm(urls[0]).hasUtm && lines.length === 1) {
          return;
        }

        event.preventDefault();

        if (urls.length === 1) {
          const parsed = parseUrlWithUtm(urls[0]);
          this.formData.url.address = parsed.base;
          if (parsed.hasUtm) {
            this.formData.url.utm = parsed.utm;
            this.showFlashNotification('Smart Paste: Extracted UTM parameters.');
            this.hapticFeedback('success');
          }
        } else {
          const firstParsed = parseUrlWithUtm(urls[0]);
          this.formData.url.address = firstParsed.base;
          if (firstParsed.hasUtm) {
            this.formData.url.utm = firstParsed.utm;
          }

          for (let i = 1; i < urls.length; i++) {
            const parsed = parseUrlWithUtm(urls[i]);
            const isSameBase = parsed.base === firstParsed.base;

            this.formData.url.variations.push({
              id: this.generateUniqueId(),
              name: `Link ${this.formData.url.variations.length + 1}`,
              utm: parsed.utm,
              customUrl: isSameBase ? '' : parsed.base
            });
          }
          this.showFlashNotification(`Smart Paste: Added ${urls.length} URLs & parsed UTMs.`);
          this.hapticFeedback('success');
        }

        this.hasUnsavedEdit = true;
        this.updateQrCode(false);
      }
    },

    // --- Variation Management ---
    addEmptyVariation() {
      this.formData.url.variations.push({
        id: this.generateUniqueId(),
        name: `Variant ${this.formData.url.variations.length + 1}`,
        utm: { source: '', medium: '', campaign: '', term: '', content: '' },
        customUrl: ''
      });
      this.hasUnsavedEdit = true;
      this.updateQrCode(true);
    },
    removeVariation(variationId) {
      this.formData.url.variations = this.formData.url.variations.filter(v => v.id !== variationId);
      this.hasUnsavedEdit = true;
      this.updateQrCode(true);
    },
    buildVariationUrl(variation) {
      if (variation.customUrl && variation.customUrl.trim() !== '') {
        let customUrlStr = variation.customUrl.trim();
        if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/i.test(customUrlStr)) {
          customUrlStr = 'https://' + customUrlStr;
        }
        return customUrlStr;
      }
      let urlStr = this.formData.url.address.trim();
      if (!urlStr) return '';
      if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/i.test(urlStr)) {
        urlStr = 'https://' + urlStr;
      }
      try {
        const urlObj = new URL(urlStr);
        const utm = variation.utm;
        const cleanParam = (val) => String(val || "").trim().replace(/^[?&]+/, '');
        if (utm.source && String(utm.source).trim()) urlObj.searchParams.set('utm_source', cleanParam(utm.source));
        if (utm.medium && String(utm.medium).trim()) urlObj.searchParams.set('utm_medium', cleanParam(utm.medium));
        if (utm.campaign && String(utm.campaign).trim()) urlObj.searchParams.set('utm_campaign', cleanParam(utm.campaign));
        if (utm.term && String(utm.term).trim()) urlObj.searchParams.set('utm_term', cleanParam(utm.term));
        if (utm.content && String(utm.content).trim()) urlObj.searchParams.set('utm_content', cleanParam(utm.content));
        return urlObj.toString();
      } catch (e) {
        return urlStr;
      }
    },
    generateVariantUrl(baseAddress, variation) {
      if (variation.customUrl && variation.customUrl.trim() !== '') {
        let customUrlStr = variation.customUrl.trim();
        if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/i.test(customUrlStr)) {
          customUrlStr = 'https://' + customUrlStr;
        }
        return customUrlStr;
      }
      let urlStr = String(baseAddress || "").trim();
      if (!urlStr) return '';
      if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/i.test(urlStr)) {
        urlStr = 'https://' + urlStr;
      }
      try {
        const urlObj = new URL(urlStr);
        const utm = variation.utm;
        if (utm) {
          const cleanParam = (val) => String(val || "").trim().replace(/^[?&]+/, '');
          if (utm.source && String(utm.source).trim()) urlObj.searchParams.set('utm_source', cleanParam(utm.source));
          if (utm.medium && String(utm.medium).trim()) urlObj.searchParams.set('utm_medium', cleanParam(utm.medium));
          if (utm.campaign && String(utm.campaign).trim()) urlObj.searchParams.set('utm_campaign', cleanParam(utm.campaign));
          if (utm.term && String(utm.term).trim()) urlObj.searchParams.set('utm_term', cleanParam(utm.term));
          if (utm.content && String(utm.content).trim()) urlObj.searchParams.set('utm_content', cleanParam(utm.content));
        }
        return urlObj.toString();
      } catch (e) {
        return urlStr;
      }
    },

    // --- Enhanced Raw Data Inspector ---
    getRawDataList() {
      if (this.selectedType !== 'url' || !this.formData.url.variations || this.formData.url.variations.length === 0) {
        return [{ label: 'QR Data', url: this.rawDataString.trim() }];
      }
      const list = [{ label: 'Base URL', url: this.getQrDataString() }];
      for (const v of this.formData.url.variations) {
        list.push({ label: v.name || 'Variant', url: this.buildVariationUrl(v) });
      }
      return list;
    },

    // --- QR Scanner (Verify Tab) ---
    async startScanner() {
      if (this.isScannerActive) return;
      try {
        if (typeof Html5Qrcode === 'undefined') {
          this.showFlashNotification('Scanner library not loaded. Please check your connection.');
          return;
        }
        this.scannerInstance = new Html5Qrcode('qr-scanner-viewport');
        await this.scannerInstance.start(
          { facingMode: 'environment' },
          { fps: 10, qrbox: { width: 250, height: 250 } },
          (decodedText) => this.onScanSuccess(decodedText),
          () => {} // Ignore errors during continuous scanning
        );
        this.isScannerActive = true;
      } catch (e) {
        console.error('Failed to start scanner', e);
        this.showFlashNotification('Could not access camera. Please grant camera permission.');
        this.hapticFeedback('error');
      }
    },
    async stopScanner() {
      if (!this.isScannerActive || !this.scannerInstance) return;
      try {
        await this.scannerInstance.stop();
        this.scannerInstance.clear();
      } catch (e) {
        console.warn('Error stopping scanner', e);
      }
      this.scannerInstance = null;
      this.isScannerActive = false;
    },
    onScanSuccess(decodedText) {
      // Deduplicate consecutive identical scans.
      if (this.scannerResults.length > 0 && this.scannerResults[0].text === decodedText) return;
      const isUrl = /^https?:\/\//i.test(decodedText);
      this.scannerResults.unshift({
        id: this.generateUniqueId(),
        text: decodedText,
        timestamp: new Date().toLocaleTimeString(),
        isUrl: isUrl
      });
      this.playBeep();
      this.hapticFeedback('success');
    },
    analyzeQrImage(canvas, ctx) {
      const analysis = {
        score: 100,
        status: 'Safe for Print',
        decodeStatus: 'Success (Instant)',
        contrast: { pass: true, ratio: '0:1' },
        quietZone: { pass: true, message: 'Safe' },
        density: { version: 1 }
      };

      try {
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const data = imageData.data;

        const lums = [];
        let darkPixelsOnEdge = 0;
        let edgePixelsCount = 0;
        const step = 4 * 4; // Sample every 4th pixel

        for (let i = 0; i < data.length; i += step) {
          const r = data[i], g = data[i+1], b = data[i+2];
          const lum = this.getLuminance(r, g, b);
          lums.push(lum);

          const pxIndex = i / 4;
          const x = pxIndex % canvas.width;
          const y = Math.floor(pxIndex / canvas.width);

          // Check 5% border for quiet zone
          const edgeThresholdX = canvas.width * 0.05;
          const edgeThresholdY = canvas.height * 0.05;
          if (x < edgeThresholdX || x > canvas.width - edgeThresholdX || y < edgeThresholdY || y > canvas.height - edgeThresholdY) {
            edgePixelsCount++;
            if (lum < 0.5) darkPixelsOnEdge++;
          }
        }

        lums.sort((a, b) => a - b);
        const darkLum = lums[Math.floor(lums.length * 0.05)] || 0;
        const brightLum = lums[Math.floor(lums.length * 0.95)] || 1;

        const contrast = (brightLum + 0.05) / (darkLum + 0.05);
        analysis.contrast.ratio = contrast.toFixed(1) + ':1';

        if (contrast >= 7.0) {
          // Excellent
        } else if (contrast >= 4.5) {
          analysis.score -= 10;
        } else {
          analysis.contrast.pass = false;
          analysis.score -= 40;
        }

        if (edgePixelsCount > 0 && (darkPixelsOnEdge / edgePixelsCount) > 0.05) {
          analysis.quietZone.pass = false;
          analysis.quietZone.message = 'Insufficient margin detected';
          analysis.score -= 20;
        }
      } catch (e) {
        console.warn("Analysis failed", e);
      }
      return analysis;
    },
    async scanFromImage(event) {
      const files = event.target.files;
      if (!files || files.length === 0) return;

      if (typeof Html5Qrcode === 'undefined') {
        this.showFlashNotification('Scanner library not loaded.');
        return;
      }

      if (files.length > 20) {
        this.showFlashNotification("To prevent crashing, please select up to 20 images at a time.");
        this.hapticFeedback('error');
        event.target.value = '';
        return;
      }

      let successCount = 0;
      let failCount = 0;

      const tempScanner = new Html5Qrcode('qr-scanner-temp');
      await new Promise(resolve => setTimeout(resolve, 50)); // Provide some buffer time for Html5Qrcode initialization

      try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        if (!file.type.startsWith('image/')) continue;

        if (file.size > 10 * 1024 * 1024) {
          console.warn(`Skipped ${file.name}: File is too large for local scanning.`);
          failCount++;
          continue;
        }

        try {
          // Pre-process image: resize and add white background to fix transparency and high-res scan failures
          const resultObj = await new Promise((resolve) => {
            const img = new Image();
            const url = URL.createObjectURL(file);
            img.onload = () => {
              URL.revokeObjectURL(url);
              const canvas = document.createElement("canvas");
              const ctx = canvas.getContext("2d");

              let w = img.width || 1024;
              let h = img.height || 1024;

              const maxDim = 1200; // Optimal max size for ZXing scanner
              if (w > maxDim || h > maxDim) {
                const ratio = Math.min(maxDim / w, maxDim / h);
                w = Math.round(w * ratio);
                h = Math.round(h * ratio);
              }

              canvas.width = w;
              canvas.height = h;

              // Fill with white background to prevent transparent background issues
              ctx.fillStyle = "#ffffff";
              ctx.fillRect(0, 0, w, h);
              ctx.drawImage(img, 0, 0, w, h);

              const analysis = this.analyzeQrImage(canvas, ctx);

              canvas.toBlob((blob) => {
                if (blob) resolve({ file: new File([blob], file.name + ".png", { type: "image/png" }), analysis });
                else resolve({ file, analysis }); // Fallback
              }, "image/png");
            };
            img.onerror = () => {
              URL.revokeObjectURL(url);
              resolve({ file, analysis: null }); // Fallback for direct scan if image fails to draw
            };
            img.src = url;
          });

          let decodedText = "";
          let isUrl = false;
          try {
            const result = await tempScanner.scanFile(resultObj.file, true);
            decodedText = result;
            isUrl = /^https?:\/\//i.test(decodedText);
          } catch (scanErr) {
            decodedText = "Decode Failed (No valid QR detected)";
            if (resultObj.analysis) {
              resultObj.analysis.decodeStatus = "Fail";
              resultObj.analysis.score -= 50;
            }
          }

          let analysis = resultObj.analysis;
          if (analysis) {
            const byteSize = new Blob([decodedText]).size;
            const qrCapacity = [
              { v: 1, max: 17 }, { v: 2, max: 32 }, { v: 3, max: 53 }, { v: 4, max: 78 },
              { v: 5, max: 106 }, { v: 6, max: 134 }, { v: 7, max: 154 }, { v: 8, max: 192 },
              { v: 9, max: 230 }, { v: 10, max: 271 }, { v: 15, max: 520 }, { v: 20, max: 858 },
              { v: 30, max: 1732 }, { v: 40, max: 3000 }
            ];
            let version = 40;
            if (decodedText !== "Decode Failed (No valid QR detected)") {
              for (const cap of qrCapacity) {
                if (byteSize <= cap.max) {
                  version = cap.v;
                  break;
                }
              }
              analysis.density.version = version;
              if (version > 10) {
                analysis.score -= 10;
              }
            } else {
              analysis.density.version = "Unknown";
            }

            if (analysis.score >= 80) analysis.status = 'Safe for Print';
            else if (analysis.score >= 50) analysis.status = 'Review Needed';
            else analysis.status = 'High Risk';

            if (analysis.score < 0) analysis.score = 0;
          }

          // Directly add to results without deduplication to allow comparing multiple similar QR codes
          this.scannerResults.unshift({
            id: this.generateUniqueId(),
            text: decodedText,
            timestamp: new Date().toLocaleTimeString(),
            isUrl: isUrl,
            analysis: analysis,
            fileName: file.name,
            filePreview: URL.createObjectURL(file)
          });
          successCount++;
        } catch (e) {
          failCount++;
        }
      }
      } finally {
        try { tempScanner.clear(); } catch(e) {}

        if (successCount > 0) {
          this.playBeep();
          this.hapticFeedback('success');
          this.showFlashNotification(`Successfully scanned ${successCount} QR code(s).`);
        } else if (failCount > 0) {
          this.showFlashNotification('No QR codes found in the selected image(s).');
          this.hapticFeedback('error');
        }
        if(event.target) event.target.value = '';
      }
    },
    clearScanResults() {
      this.scannerResults = [];
      this.showFlashNotification('Scan results cleared.');
    },
    copyAllScanResults() {
      if (this.scannerResults.length === 0) return;
      const text = this.scannerResults.map(r => r.text).join('\n');
      this.copyToTextClipboard(text);
      this.showFlashNotification(`Copied ${this.scannerResults.length} result(s) to clipboard.`);
      this.hapticFeedback('light');
    },
    playBeep() {
      try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = ctx.createOscillator();
        const gain = ctx.createGain();
        oscillator.type = 'sine';
        oscillator.frequency.setValueAtTime(1200, ctx.currentTime);
        gain.gain.setValueAtTime(0.15, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.15);
        oscillator.connect(gain);
        gain.connect(ctx.destination);
        oscillator.start(ctx.currentTime);
        oscillator.stop(ctx.currentTime + 0.15);
        setTimeout(() => ctx.close(), 200);
      } catch (e) { /* Silently fail if Web Audio API is unsupported */ }
    },

    // --- Variation-aware ZIP Export ---
    async downloadVariationsAsZip(qr) {
      if (!qr || !qr.formData || !qr.formData.url || !qr.formData.url.variations || qr.formData.url.variations.length === 0) return;

      this.isExportingBulk = true;
      this.exportProgress = 'Preparing variations...';

      try {
        const zipData = {};
        const variations = qr.formData.url.variations;
        const nameCountMap = {};

        // 1. Load the base design of the parent QR into the editor (without screen transition)
        this.editQRCode(qr.id, false);
        await new Promise(resolve => setTimeout(resolve, 250)); // Wait for DOM reflection

        for (let i = 0; i < variations.length; i++) {
          this.exportProgress = `Generating ${i + 1} of ${variations.length}...`;
          await new Promise(r => setTimeout(r, 10)); // Release thread for UI update

          const variation = variations[i];
          const vUrl = this.generateVariantUrl(qr.formData.url.address, variation);

          // 2. Update QR Code with the variation URL only
          this.qrCodeInstance.update({ data: vUrl });
          this.applyFrame(); // Re-draw frame

          await new Promise(resolve => setTimeout(resolve, 100)); // Wait for SVG & frame DOM reflection

          // 3. Clone the on-screen SVG element
          const visibleCanvas = this.showSceneModal ? this.$refs.modalQrCanvas : this.$refs.qrCodeCanvas;
          const svgElement = visibleCanvas.querySelector("svg");
          if (!svgElement) continue;

          const svgClone = svgElement.cloneNode(true);
          const svgViewBox = svgElement.viewBox.baseVal;
          const aspectRatio = svgViewBox.height > 0 ? svgViewBox.width / svgViewBox.height : 1;
          const canvasWidth = this.download.size || 1024;
          const canvasHeight = canvasWidth / Math.max(aspectRatio, 0.0001);

          svgClone.setAttribute("width", `${canvasWidth}px`);
          svgClone.setAttribute("height", `${canvasHeight}px`);
          svgClone.style.width = "";
          svgClone.style.height = "";
          svgClone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
          svgClone.setAttribute("xmlns:xlink", "http://www.w3.org/1999/xlink");

          if (this.download.transparentBg) {
            const bgRect = Array.from(svgClone.children).find(el => el.tagName.toLowerCase() === 'rect');
            if (bgRect) {
              bgRect.setAttribute("fill", "transparent");
              bgRect.style.fill = "transparent";
            }
          }

          // 4. Illustrator compatibility & SVG sanitization (same as bulkDownloadZIP)
          const imageTags = Array.from(svgClone.querySelectorAll("image, img"));
          for (let img of imageTags) {
            let href = img.getAttribute("href") || img.getAttribute("xlink:href") || img.getAttribute("src");
            if (href) {
              if (!href.startsWith("data:")) img.remove();
              else if (img.tagName.toLowerCase() === 'img') img.remove();
              else {
                if (href.startsWith("data:image/svg+xml")) {
                  try {
                    let svgString = "";
                    if (href.includes("base64,")) {
                      const binStr = atob(href.split("base64,")[1].replace(/\s/g, ''));
                      const bytes = Uint8Array.from(binStr, c => c.charCodeAt(0));
                      svgString = new TextDecoder('utf-8').decode(bytes);
                    } else {
                      svgString = decodeURIComponent(href.slice(href.indexOf(",") + 1));
                    }

                    // Sanitize with DOMPurify
                    const cleanSvgString = DOMPurify.sanitize(svgString, { USE_PROFILES: { svg: true } });

                    const parser = new DOMParser();
                    const doc = parser.parseFromString(cleanSvgString, "image/svg+xml");
                    const innerSvg = doc.documentElement;
                    if (innerSvg && innerSvg.tagName.toLowerCase() === "svg") {
                      ['x', 'y', 'width', 'height'].forEach(attr => {
                        const val = img.getAttribute(attr);
                        if (val) innerSvg.setAttribute(attr, val);
                      });
                      innerSvg.setAttribute("xmlns", "http://www.w3.org/2000/svg");
                      img.parentNode.replaceChild(innerSvg, img);
                      continue;
                    }
                  } catch (e) { console.warn("Fallback inline SVG", e); }
                }
                img.removeAttribute("href");
                img.removeAttribute("xlink:href");
                img.setAttributeNS("http://www.w3.org/1999/xlink", "xlink:href", href);
              }
            } else {
              img.remove();
            }
          }

          const finalSvgStr = new XMLSerializer().serializeToString(svgClone);
          const svgBlob = new Blob([finalSvgStr], { type: "image/svg+xml;charset=utf-8" });
          const safeSvgUrl = URL.createObjectURL(svgBlob);

          // 5. Convert SVG to PNG Blob
          let fileBytes;
          try {
            const pngBlob = await this.svgDataUrlToPngBlob(safeSvgUrl, canvasWidth);
            const arrayBuffer = await pngBlob.arrayBuffer();
            fileBytes = new Uint8Array(arrayBuffer);
          } finally {
            URL.revokeObjectURL(safeSvgUrl);
          }

          // 6. Handle duplicate names and store
          let baseName = (variation.name || `variant_${i + 1}`).trim();
          let safeName = baseName.replace(/[\\/:*?"<>|]/g, "_").replace(/[\s.]+$/, "");
          let finalName = safeName;

          if (nameCountMap[safeName]) {
            let counter = ++nameCountMap[safeName];
            finalName = `${safeName}_${counter}`;
            while (zipData[`${finalName}.png`] !== undefined) {
              counter++;
              finalName = `${safeName}_${counter}`;
            }
            nameCountMap[safeName] = counter;
          } else {
            nameCountMap[safeName] = 1;
          }

          zipData[`${finalName}.png`] = fileBytes;
        }

        this.exportProgress = 'Creating ZIP...';
        await new Promise(r => setTimeout(r, 100));

        await new Promise((resolve, reject) => {
          fflate.zip(zipData, { level: 0 }, (err, data) => {
            if (err) { reject(err); return; }
            const blob = new Blob([data], { type: 'application/zip' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${(qr.name || 'QR_Variants').trim().replace(/[\\/:*?"<>|]/g, '_')}.zip`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            setTimeout(() => URL.revokeObjectURL(url), 10000);
            resolve();
          });
        });

        this.showFlashNotification(`Exported ${variations.length} variants as ZIP.`);
        this.hapticFeedback('success');
      } catch (e) {
        console.error('Failed to export variations', e);
        this.showFlashNotification('Failed to create ZIP file.');
        this.hapticFeedback('error');
      } finally {
        this.isExportingBulk = false;
        this.exportProgress = '';
        this.resetGenerator(); // Restore clean state
        this.currentView = "dashboard";
        this.hasUnsavedEdit = false;
      }
    },
    applyColorPalette(palette) {
      this.qrOptions.colorType = "single";
      this.qrOptions.foregroundColor = palette.fg;
      this.qrOptions.backgroundColor = palette.bg;
      this.qrOptions.cornerColor = palette.fg;
      this.qrOptions.cornerDotColor = palette.fg;
      this.updateQrCode();
    },
    isCurrentTemplate(template) {
      const current = this.qrOptions;
      const tempOpts = template.options;

      // Compare color type
      if (current.colorType !== tempOpts.colorType) return false;

      // Compare colors
      if (current.colorType === "single") {
        if (current.foregroundColor?.toLowerCase() !== tempOpts.foregroundColor?.toLowerCase() ||
            current.backgroundColor?.toLowerCase() !== tempOpts.backgroundColor?.toLowerCase()) return false;
      } else {
        if (!current.gradient || !tempOpts.gradient) return false;
        if (current.gradient.color1?.toLowerCase() !== tempOpts.gradient.color1?.toLowerCase() ||
            current.gradient.color2?.toLowerCase() !== tempOpts.gradient.color2?.toLowerCase()) return false;
      }

      // Compare logos
      const currentLogo = current.logo || "";
      const tempLogo = tempOpts.logo || "";
      if (currentLogo !== tempLogo) return false;

      // Compare shapes
      return current.dotsStyle === tempOpts.dotsStyle && current.cornersStyle === tempOpts.cornersStyle;
    },
    applyFrame() {
      this.$nextTick(() => {
        const visibleCanvas = this.showSceneModal ? this.$refs.modalQrCanvas : this.$refs.qrCodeCanvas;
        if (!visibleCanvas) return;
        const svgElement = visibleCanvas.querySelector("svg");
        if (!svgElement) return;
        svgElement.querySelectorAll(".qr-frame").forEach((el) => el.remove());
        const originalSize = this.qrCodeInstance._options.width;
        svgElement.setAttribute("viewBox", `0 0 ${originalSize} ${originalSize}`);

        // Overwrite fixed pixel dimensions from qr-code-styling to allow vertical expansion
        svgElement.setAttribute("width", "100%");
        svgElement.removeAttribute("height");
        svgElement.style.height = "auto";

        if (this.frame.style === "none") return;
        const frameGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
        frameGroup.classList.add("qr-frame");
        const textColor = this.qrOptions.colorType === "single" ? this.qrOptions.foregroundColor : this.qrOptions.gradient.color1;
        let frameHeight, textY, fontSize;

        const systemFontStack = `system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans JP", "Hiragino Kaku Gothic ProN", "Meiryo", sans-serif`;

        const textToMeasure = this.frame.text || "";

        const measureCanvas = document.createElement("canvas");
        const mCtx = measureCanvas.getContext("2d");

        switch (this.frame.style) {
          case "scan-me-1": {
            frameHeight = 40;
            fontSize = 24;
            let currentFontSize = fontSize;
            mCtx.font = `bold ${currentFontSize}px ${systemFontStack}`;
            let textMetrics = mCtx.measureText(textToMeasure);

            // Auto-scale font size to fit within the original QR code width
            while (textMetrics.width > originalSize - 20 && currentFontSize > 10) {
              currentFontSize -= 1;
              mCtx.font = `bold ${currentFontSize}px ${systemFontStack}`;
              textMetrics = mCtx.measureText(textToMeasure);
            }

            svgElement.setAttribute("viewBox", `0 0 ${originalSize} ${originalSize + frameHeight}`);
            textY = originalSize + frameHeight / 2;
            const text1 = document.createElementNS("http://www.w3.org/2000/svg", "text");
            Object.assign(text1.style, {
              textAnchor: "middle",
              dominantBaseline: "central",
              fontFamily: systemFontStack,
              fontWeight: "bold",
            });
            text1.setAttribute("x", originalSize / 2);
            text1.setAttribute("y", textY);
            text1.setAttribute("font-size", `${currentFontSize}px`);
            text1.setAttribute("fill", textColor);
            text1.textContent = this.frame.text;
            frameGroup.appendChild(text1);
            break;
          }
          case "scan-me-2": {
            frameHeight = 50;
            fontSize = 22;
            let currentFontSize = fontSize;
            mCtx.font = `bold ${currentFontSize}px ${systemFontStack}`;
            let textMetrics = mCtx.measureText(textToMeasure);

            while (textMetrics.width > originalSize - 50 && currentFontSize > 10) {
              currentFontSize -= 1;
              mCtx.font = `bold ${currentFontSize}px ${systemFontStack}`;
              textMetrics = mCtx.measureText(textToMeasure);
            }
            const textWidth = textMetrics.width + 30;

            svgElement.setAttribute("viewBox", `0 0 ${originalSize} ${originalSize + frameHeight}`);
            textY = originalSize + frameHeight / 2;
            const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
            rect.setAttribute("x", originalSize / 2 - textWidth / 2);
            rect.setAttribute("y", originalSize + 10);
            rect.setAttribute("width", textWidth);
            rect.setAttribute("height", frameHeight - 20);
            rect.setAttribute("rx", "8");
            rect.setAttribute("stroke", textColor);
            rect.setAttribute("stroke-width", "3");
            rect.setAttribute("fill", "none");
            frameGroup.appendChild(rect);
            const text2 = document.createElementNS("http://www.w3.org/2000/svg", "text");
            Object.assign(text2.style, {
              textAnchor: "middle",
              dominantBaseline: "central",
              fontFamily: systemFontStack,
              fontWeight: "bold",
            });
            text2.setAttribute("x", originalSize / 2);
            text2.setAttribute("y", textY);
            text2.setAttribute("font-size", `${currentFontSize}px`);
            text2.setAttribute("fill", textColor);
            text2.textContent = this.frame.text;
            frameGroup.appendChild(text2);
            break;
          }
          case "scan-me-3": {
            frameHeight = 40;
            fontSize = 22;
            let currentFontSize = fontSize;
            mCtx.font = `bold ${currentFontSize}px ${systemFontStack}`;
            let textMetrics = mCtx.measureText(textToMeasure);

            while (textMetrics.width > originalSize - 20 && currentFontSize > 10) {
              currentFontSize -= 1;
              mCtx.font = `bold ${currentFontSize}px ${systemFontStack}`;
              textMetrics = mCtx.measureText(textToMeasure);
            }

            svgElement.setAttribute("viewBox", `0 0 ${originalSize} ${originalSize + frameHeight}`);
            textY = originalSize + frameHeight / 2;
            const bgRect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
            bgRect.setAttribute("x", 0);
            bgRect.setAttribute("y", originalSize);
            bgRect.setAttribute("width", originalSize);
            bgRect.setAttribute("height", frameHeight);
            bgRect.setAttribute("fill", textColor);
            frameGroup.appendChild(bgRect);
            const text3 = document.createElementNS("http://www.w3.org/2000/svg", "text");
            Object.assign(text3.style, {
              textAnchor: "middle",
              dominantBaseline: "central",
              fontFamily: systemFontStack,
              fontWeight: "bold",
            });
            text3.setAttribute("x", originalSize / 2);
            text3.setAttribute("y", textY);
            text3.setAttribute("font-size", `${currentFontSize}px`);
            text3.setAttribute("fill", this.qrOptions.backgroundColor);
            text3.textContent = this.frame.text;
            frameGroup.appendChild(text3);
            break;
          }
        }
        svgElement.appendChild(frameGroup);
      });
    },
    openSceneModal() {
      this.showSceneModal = true;
      this.$nextTick(() => {
        this.$refs.modalQrCanvas.innerHTML = "";
        this.qrCodeInstance.append(this.$refs.modalQrCanvas);
        this.applyFrame();
      });
    },
    closeSceneModal() {
      this.showSceneModal = false;
      this.$nextTick(() => {
        this.$refs.qrCodeCanvas.innerHTML = "";
        this.qrCodeInstance.append(this.$refs.qrCodeCanvas);
        this.applyFrame();
      });
    },
    loadScenePreset(presetName) {
      if (!this.scenePresets[presetName]) return;

      // Free memory if an old Blob URL exists
      if (this.mainSceneBackgroundUrl && this.mainSceneBackgroundUrl.startsWith('blob:')) {
        URL.revokeObjectURL(this.mainSceneBackgroundUrl);
      }

      this.previewScene = presetName;
      const preset = this.scenePresets[presetName];
      this.mainSceneOptions.scale = preset.scale;
      this.mainSceneOptions.x = preset.x;
      this.mainSceneOptions.y = preset.y;
      this.mainSceneOptions.rotation = preset.rotation;
      this.mainSceneBackgroundUrl = preset.backgroundUrl;

      // Reset file input display
      const fileInput = document.getElementById("scene-upload");
      if (fileInput) fileInput.value = "";
    },
    resetSceneOptions() {
      // Free memory if an old Blob URL exists
      if (this.mainSceneBackgroundUrl && this.mainSceneBackgroundUrl.startsWith('blob:')) {
        URL.revokeObjectURL(this.mainSceneBackgroundUrl);
      }

      this.mainSceneOptions = {
        scale: 0.7,
        x: 0,
        y: 0,
        rotation: 0,
      };
      this.previewScene = "custom";
      this.mainSceneBackgroundUrl = this.scenePresets.custom.backgroundUrl;

      // Reset file input display
      const fileInput = document.getElementById("scene-upload");
      if (fileInput) fileInput.value = "";
    },
    handleSceneBackgroundUpload(event) {
      const file = event.target.files[0];
      if (file) {
        if (file.size > 5 * 1024 * 1024) {
          this.showFlashNotification("Please select a background image smaller than 5MB.");
          event.target.value = "";
          return;
        }
        // Free memory if an old Blob URL exists to prevent memory leaks
        if (this.mainSceneBackgroundUrl && this.mainSceneBackgroundUrl.startsWith('blob:')) {
          URL.revokeObjectURL(this.mainSceneBackgroundUrl);
        }
        const newUrl = URL.createObjectURL(file);
        this.mainSceneBackgroundUrl = newUrl;
        this.scenePresets.custom.backgroundUrl = newUrl;
        this.previewScene = "custom";
      }
    },
    resetQrOptions(recordHistory = true) {
      this.qrOptions = JSON.parse(JSON.stringify(defaultQrOptions));
      this.includeQuietZone = true;
      this.frame = {
        style: "none",
        text: "SCAN ME",
      };
      this.logoFileName = "";
      this.updateQrCode(recordHistory);
    },
    async getPreviewSvgUrl(options) {
      const previewInstance = new QRCodeStyling(options);
      const blob = await previewInstance.getRawData("svg");

      return new Promise((resolve, reject) => {
        const textReader = new FileReader();
        textReader.onload = () => {
          let svgString = textReader.result;
          if (!svgString) {
            reject(new Error("Failed to read SVG data"));
            return;
          }
          svgString = svgString.replace(/crossorigin="[^"]*"/gi, "");
          const cleanBlob = new Blob([svgString], { type: "image/svg+xml;charset=utf-8" });
          const dataUrlReader = new FileReader();
          dataUrlReader.onload = () => resolve(dataUrlReader.result);
          dataUrlReader.onerror = reject;
          dataUrlReader.readAsDataURL(cleanBlob);
        };
        textReader.onerror = reject;
        textReader.readAsText(blob);
      });
    },
    resetGenerator() {
      this.editingQRCodeId = null;
      this.saveProjectId = this.currentProjectId !== 'all' ? this.currentProjectId : 'default';
      this.saveName = "";
      this.download.fileName = "grinds-qr-code";
      this.saveMemo = "";
      this.saveTags = "";
      this.selectedType = "url";
      this.formData = JSON.parse(JSON.stringify(defaultFormData));
      this.resetQrOptions(false);
      this.history = [];
      this.historyIndex = -1;
      this.currentStep = "typeSelection";
      this.clearDraft(); // Clear draft when resetting manually
      this.$nextTick(() => {
        this.hasUnsavedEdit = false;
        if (typeof setDirty === 'function') setDirty(false);
      });
    },
    openIdb() {
      return new Promise((resolve, reject) => {
        // Bump database version to 5 for Drafts support
        const request = indexedDB.open('GrindsQRCoderDB_Standalone', 5);
        request.onupgradeneeded = (e) => {
          const db = e.target.result;
          if (!db.objectStoreNames.contains('qrcodes')) {
            db.createObjectStore('qrcodes');
          }
          if (!db.objectStoreNames.contains('qrcodes_v2')) {
            db.createObjectStore('qrcodes_v2', { keyPath: 'id' });
          }
          if (!db.objectStoreNames.contains('templates')) {
            db.createObjectStore('templates', { keyPath: 'id' });
          }
          if (!db.objectStoreNames.contains('projects')) {
            db.createObjectStore('projects', { keyPath: 'id' });
          }
          if (!db.objectStoreNames.contains('drafts')) {
            db.createObjectStore('drafts');
          }
        };
        request.onsuccess = (e) => resolve(e.target.result);
        request.onerror = (e) => reject(e.target.error);
      });
    },

    // --- Auto Draft Fail-safe ---
    async saveDraft() {
      if (!this.hasUnsavedEdit || this.currentView !== 'generator') return;

      const rawOptions = window.Alpine.raw(this.qrOptions);
      const { logo, ...restOptions } = rawOptions;
      const safeOptions = JSON.parse(JSON.stringify(restOptions));
      safeOptions.logo = logo; // Keep large logo intact without JSON deep copy crash

      const draftData = {
        qrOptions: safeOptions,
        formData: JSON.parse(JSON.stringify(window.Alpine.raw(this.formData))),
        frame: JSON.parse(JSON.stringify(window.Alpine.raw(this.frame))),
        selectedType: this.selectedType,
        editingQRCodeId: this.editingQRCodeId,
        timestamp: new Date().getTime()
      };

      try {
        const db = await this.openIdb();
        const tx = db.transaction('drafts', 'readwrite');
        tx.objectStore('drafts').put(draftData, 'current_draft');
      } catch (e) {
        console.warn('Failed to save draft', e);
      }
    },
    async clearDraft() {
      try {
        const db = await this.openIdb();
        if (!db.objectStoreNames.contains('drafts')) return;
        const tx = db.transaction('drafts', 'readwrite');
        tx.objectStore('drafts').delete('current_draft');
      } catch (e) {
        console.warn('Failed to clear draft', e);
      }
    },
    async checkAndRestoreDraft() {
      try {
        const db = await this.openIdb();
        if (!db.objectStoreNames.contains('drafts')) return;

        const draft = await new Promise((resolve) => {
          const tx = db.transaction('drafts', 'readonly');
          const req = tx.objectStore('drafts').get('current_draft');
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => resolve(null);
        });

        if (draft && draft.timestamp) {
          // Only restore if draft is less than 24 hours old
          if (new Date().getTime() - draft.timestamp < 24 * 60 * 60 * 1000) {
            if (confirm("Unsaved QR code data from your last session was found.\nDo you want to restore it?")) {
              this.selectedType = draft.selectedType || 'url';
              this.formData = draft.formData;
              this.qrOptions = draft.qrOptions;
              this.frame = draft.frame;
              this.editingQRCodeId = draft.editingQRCodeId;
              this.hasUnsavedEdit = true;

              this.currentView = 'generator';
              this.currentStep = 'contentEntry';
              this.$nextTick(() => { this.updateQrCode(false); });

              this.showFlashNotification("Draft restored.");
              this.hapticFeedback('success');
            } else {
              this.clearDraft();
            }
          } else {
            this.clearDraft();
          }
        }
      } catch (e) {
        console.warn('Failed to check draft', e);
      }
    },
    async persistSavedQRCodes() {
      try {
        const db = await this.openIdb();
        return new Promise((resolve, reject) => {
          const tx = db.transaction('qrcodes_v2', 'readwrite');
          const store = tx.objectStore('qrcodes_v2');

          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);

          store.clear().onsuccess = () => {
            if (this.savedQRCodes.length === 0) return;
            this.savedQRCodes.forEach(qr => {
              // Dramatic performance improvement: completely eliminate stringification overhead
              store.put(window.Alpine.raw(qr));
            });
          };
        });
      } catch(e) {
        console.error("Failed to save to IndexedDB", e);
        this.showFlashNotification("Could not save to local database due to browser storage limits or private mode.");
      }
    },
    async loadSavedQRCodes() {
      try {
        const db = await this.openIdb();
        const saved = await new Promise((resolve, reject) => {
          let tx;
          const storeNames = [];
          if (db.objectStoreNames.contains('qrcodes_v2')) storeNames.push('qrcodes_v2');
          if (db.objectStoreNames.contains('qrcodes')) storeNames.push('qrcodes');

          if (storeNames.length > 0) {
            tx = db.transaction(storeNames, 'readonly');
          } else {
            return resolve([]);
          }

          if (db.objectStoreNames.contains('qrcodes_v2')) {
            const storeV2 = tx.objectStore('qrcodes_v2');
            const reqV2 = storeV2.getAll();
            reqV2.onsuccess = () => {
              if (reqV2.result && reqV2.result.length > 0) {
                resolve(reqV2.result.sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt)));
              } else if (db.objectStoreNames.contains('qrcodes')) {
                const storeV1 = tx.objectStore('qrcodes');
                const reqV1 = storeV1.get('savedList');
                reqV1.onsuccess = () => resolve(reqV1.result);
              } else {
                resolve([]);
              }
            };
          } else if (db.objectStoreNames.contains('qrcodes')) {
            const storeV1 = tx.objectStore('qrcodes');
            const reqV1 = storeV1.get('savedList');
            reqV1.onsuccess = () => resolve(reqV1.result);
          } else {
            resolve([]);
          }
        });

        let parsedSaved = null;
        if (typeof saved === 'string') {
          try { parsedSaved = JSON.parse(saved); } catch(e) { parsedSaved = []; }
        } else {
          parsedSaved = saved;
        }

        if (parsedSaved && Array.isArray(parsedSaved) && parsedSaved.length > 0) {
          this.savedQRCodes = parsedSaved;
        } else {
          this.savedQRCodes = [];
        }
      } catch(e) {
        console.warn("Failed to load from IndexedDB", e);
        this.savedQRCodes = [];
      }

      // --- Automatic repair migration for old thumbnails (with crossorigin attribute) ---
      let needsSave = false;
      this.savedQRCodes.forEach(qr => {
        if (typeof qr.tags === 'string') {
          qr.tags = qr.tags.split(',').map(t => t.trim()).filter(t => t);
          needsSave = true;
        }

        if (qr.previewSvgUrl && qr.previewSvgUrl.includes("base64,")) {
          try {
            const b64 = qr.previewSvgUrl.split("base64,")[1].replace(/\s/g, '');
            const binStr = atob(b64);
            if (binStr.toLowerCase().includes("crossorigin")) {
              const bytes = Uint8Array.from(binStr, c => c.charCodeAt(0));
              let svgString = new TextDecoder('utf-8').decode(bytes);

              svgString = svgString.replace(/crossorigin="[^"]*"/gi, "");

              const newBytes = new TextEncoder().encode(svgString);
              let newBinStr = "";
              const chunkSize = 8192;
              for (let i = 0; i < newBytes.length; i += chunkSize) {
                newBinStr += String.fromCharCode.apply(null, newBytes.subarray(i, i + chunkSize));
              }
              qr.previewSvgUrl = "data:image/svg+xml;base64," + btoa(newBinStr);
              needsSave = true;
            }
          } catch (e) {
            console.warn("Failed to auto-repair thumbnails.", e);
          }
        }
      });
      if (needsSave) {
        this.persistSavedQRCodes();
      }

      this.currentView = this.savedQRCodes.length > 0 ? "dashboard" : "generator";
    },
    async persistMyTemplates() {
      try {
        const db = await this.openIdb();
        return new Promise((resolve, reject) => {
          const tx = db.transaction('templates', 'readwrite');
          const store = tx.objectStore('templates');
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
          store.clear().onsuccess = () => {
            if (this.myTemplates.length === 0) return;
            this.myTemplates.forEach(t => store.put(window.Alpine.raw(t)));
          };
        });
      } catch(e) {
        console.error("Failed to save templates to IndexedDB", e);
        this.showFlashNotification("Could not save to local database due to browser storage limits.");
      }
    },
    async loadMyTemplates() {
      try {
        const db = await this.openIdb();
        if (!db.objectStoreNames.contains('templates')) {
          this.myTemplates = [];
          return;
        }
        const saved = await new Promise((resolve, reject) => {
          const tx = db.transaction('templates', 'readonly');
          const store = tx.objectStore('templates');
          const req = store.getAll();
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => resolve([]);
        });
        this.myTemplates = saved || [];
      } catch(e) {
        console.warn("Failed to load templates from IndexedDB", e);
        this.myTemplates = [];
      }
    },
    async persistProjects() {
      try {
        const db = await this.openIdb();
        return new Promise((resolve, reject) => {
          const tx = db.transaction('projects', 'readwrite');
          const store = tx.objectStore('projects');
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
          store.clear().onsuccess = () => {
            this.projects.forEach(p => store.put(window.Alpine.raw(p)));
          };
        });
      } catch(e) {
        console.error("Failed to save projects to IndexedDB", e);
        this.showFlashNotification("Could not save to local database due to browser storage limits.");
      }
    },
    async loadProjects() {
      try {
        const db = await this.openIdb();
        if (db.objectStoreNames.contains('projects')) {
          const saved = await new Promise(resolve => {
            const tx = db.transaction('projects', 'readonly');
            const req = tx.objectStore('projects').getAll();
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => resolve([]);
          });
          if (saved && saved.length > 0) {
            this.projects = saved;
            return;
          }
        }
      } catch(e) {
        console.warn("Failed to load projects from IndexedDB", e);
      }
    },
    async createNewProject() {
      const name = await appPrompt("Enter project name:", "text");
      if (!name || !name.trim()) return null;

      const newProject = {
        id: this.generateUniqueId(),
        name: name.trim(),
        createdAt: new Date().toISOString()
      };
      this.projects.push(newProject);
      await this.persistProjects();
      this.currentProjectId = newProject.id;
      this.showFlashNotification("Project created.");
      return newProject.id;
    },
    async renameProject(projectId) {
      if (projectId === 'default') {
        this.showFlashNotification("Default project cannot be renamed.");
        return;
      }
      const project = this.projects.find(p => p.id === projectId);
      if (!project) return;
      const newName = await appPrompt(`Rename project "${project.name}":`, "text");
      if (!newName || !newName.trim() || newName.trim() === project.name) return;
      project.name = newName.trim();
      await this.persistProjects();
      this.showFlashNotification("Project renamed.");
    },
    async deleteProject(projectId) {
      if (projectId === 'default') {
        this.showFlashNotification("Default project cannot be deleted.");
        return;
      }
      const project = this.projects.find(p => p.id === projectId);
      if (!project) return;
      const hasItems = this.savedQRCodes.some(qr => (qr.projectId || 'default') === projectId);
      if (hasItems) {
        if (!confirm(`The project "${project.name}" contains QR codes.\nDeleting it will move them to the Default Project. Continue?`)) return;
        this.savedQRCodes = this.savedQRCodes.map(qr => qr.projectId === projectId ? { ...qr, projectId: 'default' } : qr);
        await this.persistSavedQRCodes();
      } else {
        if (!confirm(`Are you sure you want to delete the project "${project.name}"?`)) return;
      }
      this.projects = this.projects.filter(p => p.id !== projectId);
      await this.persistProjects();
      if (this.currentProjectId === projectId) this.currentProjectId = 'all';
      this.showFlashNotification("Project deleted.");
    },
    async saveCurrentAsTemplate() {
      const templateName = await appPrompt("Enter a name for this template (e.g. My Brand):", "text");
      if (!templateName || !templateName.trim()) return;

      const rawOptions = window.Alpine.raw(this.qrOptions);
      const { logo, ...restOptions } = rawOptions;
      const copiedOptions = JSON.parse(JSON.stringify(restOptions));
      copiedOptions.logo = logo;

      const copiedFrame = JSON.parse(JSON.stringify(window.Alpine.raw(this.frame)));

      const previewOptions = {
        width: 80,
        height: 80,
        data: "https://www.grinds.jp", // Dummy data for preview.
        image: copiedOptions.logo,
        dotsOptions: this.buildDotsOptions(),
        backgroundOptions: { color: copiedOptions.backgroundColor },
        cornersSquareOptions: this.buildCornersSquareOptions(),
        cornersDotOptions: this.buildCornersDotOptions(),
        qrOptions: { errorCorrectionLevel: copiedOptions.errorCorrectionLevel },
        imageOptions: {
          ...copiedOptions.imageOptions,
          margin: copiedOptions.imageOptions.margin ? copiedOptions.imageOptions.margin / 4 : 0,
        },
        margin: copiedOptions.margin ? copiedOptions.margin / 4 : 0,
      };

      let previewSvgUrl = "";
      try {
        previewSvgUrl = await this.getPreviewSvgUrl(previewOptions);
      } catch(e) {
        console.warn("Failed to generate preview for template", e);
      }

      const newTemplate = {
        id: this.generateUniqueId(),
        name: templateName.trim(),
        options: copiedOptions,
        frame: copiedFrame,
        preview: previewSvgUrl,
        createdAt: new Date().toISOString()
      };

      this.myTemplates.unshift(newTemplate);
      await this.persistMyTemplates();
      this.showFlashNotification(`Template "${newTemplate.name}" saved!`);
      this.hapticFeedback('success');
    },
    applyMyTemplate(tpl) {
      const rawOptions = window.Alpine.raw(tpl.options);
      const { logo, ...restOptions } = rawOptions;

      const safeOptions = JSON.parse(JSON.stringify(defaultQrOptions));
      this.qrOptions = {
        ...safeOptions,
        ...restOptions,
        gradient: { ...safeOptions.gradient, ...(restOptions.gradient || {}) },
        imageOptions: { ...safeOptions.imageOptions, ...(restOptions.imageOptions || {}) }
      };
      this.qrOptions.logo = logo;

      if (tpl.frame) {
        this.frame = JSON.parse(JSON.stringify(window.Alpine.raw(tpl.frame)));
      } else {
        this.frame = { style: "none", text: "SCAN ME" };
      }

      this.logoFileName = logo ? "Template Logo" : "";
      this.includeQuietZone = this.qrOptions.margin > 0;
      this.updateQrCode();
      this.showFlashNotification("Applied custom template.");
    },
    async deleteMyTemplate(id) {
      if(window.confirm("Are you sure you want to delete this template?")) {
        this.myTemplates = this.myTemplates.filter(t => t.id !== id);
        await this.persistMyTemplates();
        this.showFlashNotification("Template deleted.");
      }
    },
    isCurrentMyTemplate(tpl) {
      const current = this.qrOptions;
      const tplOpts = tpl.options;

      if (current.colorType !== tplOpts.colorType) return false;
      if (current.colorType === "single") {
        if (current.foregroundColor?.toLowerCase() !== tplOpts.foregroundColor?.toLowerCase() ||
            current.backgroundColor?.toLowerCase() !== tplOpts.backgroundColor?.toLowerCase()) return false;
      } else {
        if (!current.gradient || !tplOpts.gradient) return false;
        if (current.gradient.color1?.toLowerCase() !== tplOpts.gradient.color1?.toLowerCase() ||
            current.gradient.color2?.toLowerCase() !== tplOpts.gradient.color2?.toLowerCase()) return false;
      }
      if (current.dotsStyle !== tplOpts.dotsStyle) return false;
      if (this.frame.style !== (tpl.frame?.style || "none")) return false;

      return true;
    },
    async updateInlineMemo(qr, newMemo) {
      qr.memo = newMemo;
      qr.updatedAt = new Date().toISOString();
      await this.persistSavedQRCodes();
      if (typeof setDirty === 'function') setDirty(true);
      this.showFlashNotification("Memo updated.");
    },
    async updateInlineTags(qr, newTagsStr) {
      qr.tags = newTagsStr.split(',').map(t => t.trim()).filter(t => t);
      qr.updatedAt = new Date().toISOString();
      await this.persistSavedQRCodes();
      if (typeof setDirty === 'function') setDirty(true);
      this.showFlashNotification("Tags updated.");
    },
    editQRCode(id, transitionToGenerator = true) {
      const qrToEdit = this.savedQRCodes.find((qr) => qr.id === id);
      if (qrToEdit) {
        this.editingQRCodeId = id;
        this.saveProjectId = qrToEdit.projectId || 'default';
        this.saveName = qrToEdit.name;
        this.download.fileName = qrToEdit.name;
        this.saveMemo = qrToEdit.memo || "";
        this.saveTags = qrToEdit.tags ? qrToEdit.tags.join(', ') : "";
        this.selectedType = qrToEdit.type;
        // Migration: Initialize and append UTM object if missing in legacy data.
        const loadedFormData = JSON.parse(JSON.stringify(qrToEdit.formData));
        if (loadedFormData.url && !loadedFormData.url.utm) {
          loadedFormData.url.utm = { source: "", medium: "", campaign: "", term: "", content: "" };
        }
        if (loadedFormData.url && !loadedFormData.url.variations) {
          loadedFormData.url.variations = [];
        }
        if (loadedFormData.sns && typeof loadedFormData.sns.message === 'undefined') {
          loadedFormData.sns.message = "";
        }
        if (!loadedFormData.sms) {
          loadedFormData.sms = { phone: "", message: "" };
        }
        if (!loadedFormData.crypto) {
          loadedFormData.crypto = { currency: "bitcoin", address: "", amount: "" };
        }
        if (loadedFormData.wifi && typeof loadedFormData.wifi.hidden === 'undefined') {
          loadedFormData.wifi.hidden = false;
        }
        this.formData = loadedFormData;

        const safeOptions = JSON.parse(JSON.stringify(defaultQrOptions));
        const editOpts = JSON.parse(JSON.stringify(qrToEdit.qrOptions));
        this.qrOptions = {
          ...safeOptions,
          ...editOpts,
          gradient: { ...safeOptions.gradient, ...(editOpts.gradient || {}) },
          imageOptions: { ...safeOptions.imageOptions, ...(editOpts.imageOptions || {}) }
        };
        this.logoFileName = qrToEdit.logoFileName;
        this.frame = JSON.parse(JSON.stringify(qrToEdit.frame));
        if (transitionToGenerator) {
          this.currentView = "generator";
          this.currentStep = "contentEntry";
          this.activeStepTab = "content";
        }
        this.$nextTick(() => {
          this.updateQrCode(false);
          if (transitionToGenerator) {
            this.history = [];
            this.historyIndex = -1;
            this.recordState();
          }
          this.hasUnsavedEdit = false;
          if (typeof setDirty === 'function') setDirty(false);
        });
      }
    },
    async deleteQRCode(id) {
      const isConfirmed = window.confirm("Are you sure you want to delete this QR code?\nThis action cannot be undone.");
      if (isConfirmed) {
        this.savedQRCodes = this.savedQRCodes.filter((qr) => qr.id !== id);
        this.selectedIds = this.selectedIds.filter((selectedId) => selectedId !== id);
        await this.persistSavedQRCodes();
        if (typeof setDirty === 'function') setDirty(true);

        if (this.currentPage > this.totalPages) {
          this.currentPage = Math.max(1, this.totalPages);
        }

        this.showFlashNotification("QR code deleted.");
      }
    },
    async bulkDeleteQRCodes() {
      if (this.selectedIds.length === 0) return;
      const isConfirmed = window.confirm(`Are you sure you want to delete ${this.selectedIds.length} selected QR codes?\nThis action cannot be undone.`);

      if (isConfirmed) {
        this.savedQRCodes = this.savedQRCodes.filter(qr => !this.selectedIds.includes(qr.id));
        await this.persistSavedQRCodes();
        if (typeof setDirty === 'function') setDirty(true);

        if (this.currentPage > this.totalPages) {
          this.currentPage = Math.max(1, this.totalPages);
        }

        this.showFlashNotification(`${this.selectedIds.length} QR codes deleted.`);
        this.selectedIds = [];
      }
    },

    // --- Export Meta Data for CRM (People) Integration ---
    exportSelectedAsCsv() {
      if (this.selectedIds.length === 0) return;

      const targets = this.savedQRCodes.filter(qr => this.selectedIds.includes(qr.id));
      if (targets.length === 0) return;

      const headers = ["QR ID", "Name", "Memo", "Tags", "Type", "Created At", "Data Content"];
      const escapeCSV = (str) => {
        let val = String(str || "");
        if (/^[=\-+\@\t\r]/.test(val)) {
          val = "'" + val;
        }
        return `"${val.replace(/"/g, '""')}"`;
      };

      const csvRows = [headers.map(escapeCSV).join(",")];

      targets.forEach(qr => {
        const dataStringContext = { selectedType: qr.type, formData: qr.formData };
        const dataContent = this.getQrDataString.call(dataStringContext);

        csvRows.push([
          qr.id, qr.name, qr.memo, (qr.tags || []).join(", "),
          this.qrTypes.find(t => t.id === qr.type)?.title || qr.type,
          new Date(qr.createdAt).toISOString(), dataContent
        ].map(escapeCSV).join(","));
      });

      const csvContent = "\uFEFF" + csvRows.join("\r\n");
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      const now = new Date();
      const dateStr = `${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}`;
      link.download = `QR_History_Export_${dateStr}.csv`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      setTimeout(() => URL.revokeObjectURL(url), 1000);

      this.showFlashNotification(`Exported ${targets.length} records as CSV.`);
      this.hapticFeedback('success');
    },

    // --- Bulk Edit Functions ---
    openBulkMoveModal() {
      this.bulkMoveTargetProject = this.currentProjectId !== 'all' ? this.currentProjectId : 'default';
      this.showBulkMoveModal = true;
    },
    async executeBulkMove() {
      if (this.selectedIds.length === 0) return;
      const count = this.selectedIds.length;
      const targetName = this.projects.find(p => p.id === this.bulkMoveTargetProject)?.name || 'Default';

      this.savedQRCodes = this.savedQRCodes.map(qr => {
        if (this.selectedIds.includes(qr.id)) {
          return { ...qr, projectId: this.bulkMoveTargetProject, updatedAt: new Date().toISOString() };
        }
        return qr;
      });

      await this.persistSavedQRCodes();
      if (typeof setDirty === 'function') setDirty(true);

      this.showBulkMoveModal = false;
      this.selectedIds = [];
      this.showFlashNotification(`Moved ${count} items to "${targetName}".`);
      this.hapticFeedback('success');
    },
    openBulkTagModal() {
      this.bulkTagInput = '';
      this.bulkTagMode = 'add';
      this.showBulkTagModal = true;
    },
    async executeBulkTag() {
      if (this.selectedIds.length === 0) return;
      const count = this.selectedIds.length;
      const inputTags = this.bulkTagInput.split(',').map(t => t.trim()).filter(t => t);

      this.savedQRCodes = this.savedQRCodes.map(qr => {
        if (this.selectedIds.includes(qr.id)) {
          let currentTags = qr.tags || [];
          if (this.bulkTagMode === 'add') {
            const newTags = new Set([...currentTags, ...inputTags]);
            qr.tags = Array.from(newTags);
          } else if (this.bulkTagMode === 'replace') {
            qr.tags = [...inputTags];
          } else if (this.bulkTagMode === 'remove') {
            qr.tags = currentTags.filter(t => !inputTags.includes(t));
          }
          qr.updatedAt = new Date().toISOString();
        }
        return qr;
      });

      await this.persistSavedQRCodes();
      if (typeof setDirty === 'function') setDirty(true);

      this.showBulkTagModal = false;
      this.selectedIds = [];
      this.showFlashNotification(`Updated tags for ${count} items.`);
      this.hapticFeedback('success');
    },

    async duplicateQRCode(id) {
      const originalQr = this.savedQRCodes.find((qr) => qr.id === id);
      if (originalQr) {
        // Prevent OOM crashes during deep copy and bypass Proxy
        const rawOriginalQr = window.Alpine.raw(originalQr);
        const { qrOptions, ...restQr } = rawOriginalQr;
        const { logo, ...restOptions } = qrOptions;

        const newQr = JSON.parse(JSON.stringify(restQr));
        newQr.qrOptions = JSON.parse(JSON.stringify(restOptions));
        newQr.qrOptions.logo = logo;

        newQr.id = this.generateUniqueId();
        newQr.name = `${originalQr.name} (Copy)`;
        newQr.memo = originalQr.memo || "";
        newQr.tags = originalQr.tags ? [...originalQr.tags] : [];
        newQr.isFavorite = false; // Unpin duplicated copies
        newQr.createdAt = new Date().toISOString();
        const dataStringContext = {
          selectedType: newQr.type,
          formData: newQr.formData,
          generateUniqueId: this.generateUniqueId,
        };
        const dataString = this.getQrDataString.call(dataStringContext);
        const builderContext = {
          qrOptions: newQr.qrOptions,
          buildDotsOptions: this.buildDotsOptions,
          buildCornersSquareOptions: this.buildCornersSquareOptions,
          buildCornersDotOptions: this.buildCornersDotOptions,
        };
        const thumbnailOptions = {
          width: 80,
          height: 80,
          data: dataString,
          image: newQr.qrOptions.logo,
          dotsOptions: builderContext.buildDotsOptions.call(builderContext),
          backgroundOptions: {
            color: newQr.qrOptions.backgroundColor,
          },
          cornersSquareOptions: builderContext.buildCornersSquareOptions.call(builderContext),
          cornersDotOptions: builderContext.buildCornersDotOptions.call(builderContext),
          qrOptions: {
            errorCorrectionLevel: newQr.qrOptions.errorCorrectionLevel,
          },
          imageOptions: {
            ...newQr.qrOptions.imageOptions,
            margin: newQr.qrOptions.imageOptions.margin ? newQr.qrOptions.imageOptions.margin / 4 : 0,
          },
          margin: newQr.qrOptions.margin ? newQr.qrOptions.margin / 4 : 0,
        };
        newQr.previewSvgUrl = await this.getPreviewSvgUrl(thumbnailOptions);
        this.savedQRCodes.unshift(newQr);
        await this.persistSavedQRCodes();
        if (typeof setDirty === 'function') setDirty(true);
        this.showFlashNotification("QR code duplicated.");
      }
    },
    prepareDownloadFromDashboard(qr) {
      // Step 4: Open QA Modal instead of immediate ZIP download if variations exist
      if (qr.type === 'url' && qr.formData && qr.formData.url && qr.formData.url.variations && qr.formData.url.variations.length > 0) {
        this.qaCurrentQr = qr;
        this.showQaModal = true;
        return;
      }
      this.isBulkDownload = false;
      this.editQRCode(qr.id, false); // Load data and render in background perfectly without screen jump
      this.download.fileName = qr.name;
      this.download.format = 'png';
      this.download.size = 1024;
      this.showDownloadModal = true;
    },
    async openShareModal(qr) {
      this.qrToShare = qr;

      // Directly native share image if Web Share API (File) is supported.
      if (navigator.share && navigator.canShare) {
        try {
          const blob = await this.svgDataUrlToPngBlob(qr.previewSvgUrl, 512);
          const safeShareName = (qr.name || 'qrcode').trim().replace(/[\\/:*?"<>|]/g, "_");
          const file = new File([blob], `${safeShareName}.png`, { type: 'image/png' });

          if (navigator.canShare({ files: [file] })) {
            await navigator.share({
              title: qr.name,
              text: `QR code for "${qr.name}"`,
              files: [file],
            });
            return; // Exit without opening modal upon successful share.
          }
        } catch (error) {
          if (error.name !== 'AbortError') {
             console.error("Image sharing failed", error);
             this.showFlashNotification("Sharing failed. Please try downloading the image instead.");
             this.hapticFeedback('error');
             this.prepareDownloadFromDashboard(qr);
          } else {
             return; // User cancelled
          }
        }
      }

      // Open modal as fallback if API is unsupported or fails.
      this.showShareModal = true;
    },
    getShareDataText(qr) {
      const dataStringContext = {
        selectedType: qr.type,
        formData: qr.formData,
      };
      return this.getQrDataString.call(dataStringContext);
    },
    async bulkDownloadZIP() {
      if (this.selectedIds.length === 0 || this.isExportingBulk) return;

      if (this.selectedIds.length > 100) {
        this.showFlashNotification("For stability, please select up to 100 items for bulk export.");
        this.hapticFeedback('error');
        return;
      }

      this.isExportingBulk = true;
      this.exportProgress = "Preparing...";

      try {
        const zipData = {}; // fflate expects { "filename.png": Uint8Array }
        const nameCountMap = {};

        const targets = this.savedQRCodes.filter(qr => this.selectedIds.includes(qr.id));
        const total = targets.length;
        const format = this.download.format;
        let count = 0;

        // Use for...of to process sequentially, preventing Canvas memory limits/crashes in Safari
        for (const qr of targets) {
          count++;
          this.exportProgress = `Zipping... (${count}/${total})`;

          // Render the full QR code invisibly in the background generator to ensure frames and logos are applied
          this.editQRCode(qr.id, false);

          // Wait briefly for the DOM to render the SVG and apply the frame (which uses setTimeout)
          await new Promise(resolve => setTimeout(resolve, 250));

          const visibleCanvas = this.showSceneModal ? this.$refs.modalQrCanvas : this.$refs.qrCodeCanvas;
          const svgElement = visibleCanvas.querySelector("svg");
          if (!svgElement) continue;

          const svgClone = svgElement.cloneNode(true);
          const svgViewBox = svgElement.viewBox.baseVal;
          const aspectRatio = svgViewBox.height > 0 ? svgViewBox.width / svgViewBox.height : 1;
          const canvasWidth = this.download.size;
          const canvasHeight = this.download.size / Math.max(aspectRatio, 0.0001);

          svgClone.setAttribute("width", `${canvasWidth}px`);
          svgClone.setAttribute("height", `${canvasHeight}px`);
          svgClone.style.width = "";
          svgClone.style.height = "";

          svgClone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
          svgClone.setAttribute("xmlns:xlink", "http://www.w3.org/1999/xlink");

          if (this.download.transparentBg) {
            const bgRect = Array.from(svgClone.children).find(el => el.tagName.toLowerCase() === 'rect');
            if (bgRect) {
              bgRect.setAttribute("fill", "transparent");
              bgRect.style.fill = "transparent";
            }
          }

          // Convert to static array using Array.from for dynamic DOM replacement.
          const imageTags = Array.from(svgClone.querySelectorAll("image, img"));

          for (let img of imageTags) {
            let href = img.getAttribute("href") || img.getAttribute("xlink:href") || img.getAttribute("src");
            if (href) {
              if (!href.startsWith("data:")) {
                img.remove();
              } else if (img.tagName.toLowerCase() === 'img') {
                img.remove();
              } else {
                if (href.startsWith("data:image/svg+xml")) {
                  try {
                    let svgString = "";
                    if (href.includes("base64,")) {
                      const binStr = atob(href.split("base64,")[1].replace(/\s/g, ''));
                      const bytes = Uint8Array.from(binStr, c => c.charCodeAt(0));
                      svgString = new TextDecoder('utf-8').decode(bytes); // Prevent character corruption.
                    } else {
                      svgString = decodeURIComponent(href.slice(href.indexOf(",") + 1));
                    }

                    // Sanitize with DOMPurify
                    const cleanSvgString = DOMPurify.sanitize(svgString, { USE_PROFILES: { svg: true } });

                    const parser = new DOMParser();
                    const doc = parser.parseFromString(cleanSvgString, "image/svg+xml");
                    const innerSvg = doc.documentElement;

                    if (innerSvg && innerSvg.tagName.toLowerCase() === "svg") {
                      ['x', 'y', 'width', 'height'].forEach(attr => {
                        const val = img.getAttribute(attr);
                        if (val) innerSvg.setAttribute(attr, val);
                      });

                      innerSvg.setAttribute("xmlns", "http://www.w3.org/2000/svg");
                      img.parentNode.replaceChild(innerSvg, img);
                      continue;
                    }
                  } catch (e) {
                    console.warn("Failed to inline vector SVG. Falling back.", e);
                  }
                }
                img.removeAttribute("href");
                img.removeAttribute("xlink:href");
                img.setAttributeNS("http://www.w3.org/1999/xlink", "xlink:href", href);
              }
            } else {
              img.remove();
            }
          }

          const finalSvgStr = new XMLSerializer().serializeToString(svgClone);
          const svgBlob = new Blob([finalSvgStr], { type: "image/svg+xml;charset=utf-8" });
          const safeSvgUrl = URL.createObjectURL(svgBlob);

          let fileBytes;
          try {
            if (format === 'svg') {
              const arrayBuffer = await svgBlob.arrayBuffer();
              fileBytes = new Uint8Array(arrayBuffer);
            } else {
              const pngBlob = await this.svgDataUrlToPngBlob(safeSvgUrl, this.download.size);
              const arrayBuffer = await pngBlob.arrayBuffer();
              fileBytes = new Uint8Array(arrayBuffer);
            }
          } finally {
            URL.revokeObjectURL(safeSvgUrl);
          }

          // Yield thread for a few milliseconds to prompt browser garbage collection (GC)
          await new Promise(resolve => setTimeout(resolve, 50));

          let baseName = qr.name ? qr.name.trim() : "";
          // If name is empty, use project name + Image as default
          if (!baseName) {
            const projName = this.projects.find(p => p.id === (qr.projectId || 'default'))?.name || "QR";
            baseName = `${projName}_Image`;
          }
          let safeName = baseName.replace(/[\\/:*?"<>|]/g, "-").replace(/[\s.]+$/, "");

          let finalName = safeName;
          if (nameCountMap[safeName] !== undefined) {
            let counter = ++nameCountMap[safeName];
            finalName = `${safeName}(${counter})`;
            while (zipData[`${finalName}.${format}`] !== undefined) {
              counter++;
              finalName = `${safeName}(${counter})`;
            }
            nameCountMap[safeName] = counter;
          } else {
            nameCountMap[safeName] = 0;
          }
          zipData[`${finalName}.${format}`] = fileBytes;
        }

        this.exportProgress = "Compressing...";
        await new Promise(resolve => setTimeout(resolve, 50)); // Allow UI to render

        const zipped = await new Promise((resolve, reject) => {
          fflate.zip(zipData, { level: 0 }, (err, data) => {
            if (err) reject(err);
            else resolve(data);
          });
        });
        const zipBlob = new Blob([zipped], { type: 'application/zip' });
        const url = URL.createObjectURL(zipBlob);

        const a = document.createElement('a');
        a.href = url;

        let rawZipName = (this.download.zipName || "QR_Export").trim();
        if (rawZipName.toLowerCase().endsWith('.zip')) {
          rawZipName = rawZipName.slice(0, -4);
        }
        let finalZipName = rawZipName.replace(/[\\/:*?"<>|]/g, "-").replace(/[\s.]+$/, "") + '.zip';

        a.download = finalZipName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);

        setTimeout(() => URL.revokeObjectURL(url), 10000); // Safari fix

        this.exportProgress = "Completed!";
        await new Promise(resolve => setTimeout(resolve, 400));
        this.showFlashNotification(`${total} QR codes exported successfully!`);
        this.hapticFeedback('success');
        this.selectedIds = [];

      } catch (error) {
        console.error("Bulk export failed:", error);
        this.showFlashNotification("Failed to create ZIP file.");
        this.hapticFeedback('error');
      } finally {
        this.isExportingBulk = false;
        this.exportProgress = "";
        this.resetGenerator();
        this.currentView = "dashboard";
      }
    },
    async svgDataUrlToPngBlob(svgDataUrl, size = 512) {
      return new Promise(async (resolve, reject) => {
        let imageElement = null;
        const timeoutId = setTimeout(() => {
          if (svgDataUrl && svgDataUrl.startsWith("blob:")) {
            URL.revokeObjectURL(svgDataUrl);
          }
          if (imageElement) imageElement.src = "";
          reject(new Error("Image rendering timeout"));
        }, 5000);

        try {
          if (svgDataUrl && svgDataUrl.startsWith("data:image/svg+xml")) {
            let decodedSvgText = "";
            const isBase64Encoded = svgDataUrl.includes("base64,");

            if (isBase64Encoded) {
              const base64Data = svgDataUrl.split("base64,")[1];
              const binaryString = atob(base64Data);
              const uint8Array = Uint8Array.from(binaryString, char => char.charCodeAt(0));
              decodedSvgText = new TextDecoder('utf-8').decode(uint8Array);
            } else if (svgDataUrl.includes(",")) {
              decodedSvgText = decodeURIComponent(svgDataUrl.split(",")[1]);
            }

            // Safe fallback: strip legacy attributes to prevent Canvas tainting
            if (decodedSvgText.includes("crossorigin")) {
              decodedSvgText = decodedSvgText.replace(/\s*crossorigin=(?:"[^"]*"|'[^']*')/gi, "");
            }

            const cleanSvgBlob = new Blob([decodedSvgText], { type: "image/svg+xml;charset=utf-8" });
            svgDataUrl = URL.createObjectURL(cleanSvgBlob);
          }

          const image = new Image();
          imageElement = image;
          image.onload = () => {
            clearTimeout(timeoutId);
            const renderCanvas = document.createElement("canvas");
            renderCanvas.width = size;
            renderCanvas.height = size;
            const renderCtx = renderCanvas.getContext("2d");
            renderCtx.clearRect(0, 0, size, size);

            if (!this.download?.transparentBg) {
              renderCtx.fillStyle = this.qrOptions?.backgroundColor || "#ffffff";
              renderCtx.fillRect(0, 0, size, size);
            }

            renderCtx.drawImage(image, 0, 0, size, size);
            renderCanvas.toBlob((blobData) => {
              if (svgDataUrl.startsWith("blob:")) URL.revokeObjectURL(svgDataUrl);

              renderCanvas.width = 0;
              renderCanvas.height = 0;

              if (blobData) resolve(blobData);
              else reject(new Error("Blob conversion failed"));
            }, "image/png");
          };
          image.onerror = () => {
            clearTimeout(timeoutId);
            if (svgDataUrl.startsWith("blob:")) URL.revokeObjectURL(svgDataUrl);
            reject(new Error("SVG Rendering Error"));
          };
          image.src = svgDataUrl;
        } catch (e) {
          clearTimeout(timeoutId);
          reject(e);
        }
      });
    },

    // --- CSV upload and parsing ---
    openImportModal() {
      this.importTargetProject = this.currentProjectId !== 'all' ? this.currentProjectId : 'default';
      this.resetImportState();
      this.showImportModal = true;
    },
    resetImportState() {
      this.csvFile = null;
      this.csvHeaders = [];
      this.csvData = [];
      this.csvMapping = { name: "", memo: "", tags: "", dynamic: {} };
      this.reMapCsvHeaders();
      this.isImporting = false;
      this.importProgress = 0;
      const fileInput = document.getElementById("csv-upload-input");
      if (fileInput) fileInput.value = "";
    },
    downloadSampleCSV() {
      // Common field headers and sample data
      const headers = ["Name", "Memo", "Tags"];
      const sampleRow = [`Sample ${this.getActiveType().title} QR`, "Generated from sample", "sample, grinds"];

      // Add dynamic fields required for the currently selected QR type
      this.activeTypeFields.forEach(field => {
        headers.push(field.label); // Use the label name (display name on UI) as the header

        // Generate appropriate dummy data based on field type
        const key = field.key.toLowerCase();
        if (key.includes('url') || key === 'address') {
          sampleRow.push("https://example.com");
        } else if (key.includes('phone')) {
          sampleRow.push("+1234567890");
        } else if (key.includes('email') || key === 'to') {
          sampleRow.push("sample@example.com");
        } else if (key === 'latitude') {
          sampleRow.push("35.681236");
        } else if (key === 'longitude') {
          sampleRow.push("139.767125");
        } else if (key === 'start' || key === 'end') {
          sampleRow.push("2026-07-01T10:00");
        } else {
          sampleRow.push(`Sample ${field.label}`);
        }
      });

      // Function to escape CSV cells with double quotes
      const escapeCSV = (str) => `"${String(str).replace(/"/g, '""')}"`;

      const csvContent = [
        headers.map(escapeCSV).join(","),
        sampleRow.map(escapeCSV).join(",")
      ].join("\r\n");

      // Add BOM (Byte Order Mark) to prevent character corruption in Excel
      const blob = new Blob(["\uFEFF" + csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);

      const link = document.createElement("a");
      link.href = url;
      link.download = `grinds_${this.selectedType}_sample.csv`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      setTimeout(() => URL.revokeObjectURL(url), 1000);
      this.showFlashNotification("Sample CSV downloaded.");
      this.hapticFeedback('light');
    },
    reMapCsvHeaders() {
      const newDynamic = {};
      this.activeTypeFields.forEach(f => {
        newDynamic[f.key] = "";
      });
      this.csvMapping.dynamic = newDynamic;

      if (this.csvHeaders.length === 0) return;

      this.activeTypeFields.forEach((f, index) => {
         let regex;
         if (f.key === 'url') regex = /url|link|address/i;
         else if (f.key === 'content') regex = /content|text/i;
         else if (f.key === 'ssid') regex = /ssid|wifi|network/i;
         else if (f.key === 'password') regex = /pass|pw/i;
         else if (f.key === 'lastName') regex = /last[\s_]*name|surname/i;
         else if (f.key === 'firstName') regex = /first[\s_]*name|given[\s_]*name/i;
         else if (f.key === 'phone') regex = /phone|tel/i;
         else if (f.key === 'email' || f.key === 'to') regex = /mail/i;
         else if (f.key === 'summary') regex = /event|summary/i;
         else if (f.key === 'start') regex = /start/i;
         else if (f.key === 'end') regex = /end/i;
         else regex = new RegExp(f.key, 'i');

         this.csvMapping.dynamic[f.key] = this.csvHeaders.find(h => regex.test(h)) || (f.required ? (this.csvHeaders[index] || "") : "");
      });
    },
    handleCsvDrop(event) {
      const file = event.dataTransfer?.files[0] || event.target.files[0];
      if (!file || !file.name.endsWith('.csv')) {
        this.showFlashNotification("Please select a valid .csv file.");
        return;
      }

      if (file.size > 2 * 1024 * 1024) {
        this.showFlashNotification("File is too large. Please select a CSV smaller than 2MB.");
        this.hapticFeedback('error');
        if (event.target) event.target.value = "";
        return;
      }

      this.csvFile = file;
      const reader = new FileReader();
      reader.onload = (e) => {
        const buffer = e.target.result;
        let text = '';
        try {
          // First, try decoding as strict UTF-8
          const utf8Decoder = new TextDecoder('utf-8', { fatal: true });
          text = utf8Decoder.decode(buffer);
        } catch (err) {
          // If UTF-8 decoding fails (fatal error), fallback to Shift_JIS (Japanese Excel CSVs)
          const sjisDecoder = new TextDecoder('shift_jis');
          text = sjisDecoder.decode(buffer);
        }

        const cleanText = text.replace(/^\uFEFF/, '');
        const parsed = this.parseCSV(cleanText);
        if (parsed.length < 2) {
          this.showFlashNotification("CSV must contain headers and at least one data row.");
          this.resetImportState();
          return;
        }

        if (parsed.length > 501) {
          this.showFlashNotification("Cannot import more than 500 records at once to prevent browser crash.");
          this.resetImportState();
          return;
        }

        this.csvHeaders = parsed[0].map(h => h.trim());
        this.csvData = parsed.slice(1);

        // Header name inference (Smart UX)
        this.csvMapping.name = this.csvHeaders.find(h => /name|title/i.test(h)) || "";
        this.csvMapping.memo = this.csvHeaders.find(h => /memo|desc|note/i.test(h)) || "";
        this.csvMapping.tags = this.csvHeaders.find(h => /tag|category/i.test(h)) || "";

        this.reMapCsvHeaders();
      };
      reader.onerror = () => {
        this.showFlashNotification("Failed to read the file. It may be locked or corrupted.");
        this.hapticFeedback('error');
        this.resetImportState();
      };
      reader.readAsArrayBuffer(file);
    },
    // Robust simple CSV parser that also handles commas enclosed in double quotes
    parseCSV(text) {
      const result = [];
      let row = [], inQuotes = false, val = '';
      for (let i = 0; i < text.length; i++) {
        let char = text[i], nextChar = text[i+1];
        if (inQuotes) {
          if (char === '"' && nextChar === '"') { val += '"'; i++; }
          else if (char === '"') inQuotes = false;
          else val += char;
        } else {
          if (char === '"') inQuotes = true;
          else if (char === ',') { row.push(val); val = ''; }
          else if (char === '\n' || char === '\r') {
            if (char === '\r' && nextChar === '\n') i++;
            row.push(val); result.push(row); row = []; val = '';
          } else val += char;
        }
      }
      if (val || row.length > 0) { row.push(val); result.push(row); }
      return result.filter(r => r.some(c => c.trim() !== '')); // Exclude empty rows
    },

    // --- Execute bulk generation (bulk import) ---
    async executeBulkImport() {
      const requiredFields = this.activeTypeFields.filter(f => f.required);
      for (const f of requiredFields) {
        if (!this.csvMapping.dynamic[f.key]) {
          this.showFlashNotification(`${f.label} mapping is required.`);
          this.hapticFeedback('error');
          return;
        }
      }

      this.isImporting = true;
      this.importProgress = 0;

      const total = this.csvData.length;
      let count = 0;
      const newQRCodes = [];

      const idxName = this.csvMapping.name ? this.csvHeaders.indexOf(this.csvMapping.name) : -1;
      const idxMemo = this.csvMapping.memo ? this.csvHeaders.indexOf(this.csvMapping.memo) : -1;
      const idxTags = this.csvMapping.tags ? this.csvHeaders.indexOf(this.csvMapping.tags) : -1;

      // Get "current editor design settings" as a template
      const rawOptions = window.Alpine.raw(this.qrOptions);
      const { logo, ...restOptions } = rawOptions;
      const baseFrame = JSON.parse(JSON.stringify(window.Alpine.raw(this.frame)));
      const baseFormData = JSON.parse(JSON.stringify(window.Alpine.raw(this.formData)));

      const fixHex = (c) => {
        if (!c) return "#ffffff";
        let hex = c.trim().toUpperCase();
        if (!hex.startsWith('#')) hex = '#' + hex;
        if (/^#(?:[0-9A-F]{3}){1,2}$|^#(?:[0-9A-F]{4}){1,2}$/i.test(hex)) {
          if (hex.length === 4 || hex.length === 5) {
            hex = '#' + hex.split('').slice(1).map(x => x + x).join('');
          }
          return hex;
        }
        return "#ffffff";
      };

      for (const row of this.csvData) {
        count++;
        // Periodically release the main thread to reflect progress in the UI
        if (count % 10 === 0) await new Promise(r => setTimeout(r, 10));
        this.importProgress = Math.round((count / total) * 100);

        const specificFormData = JSON.parse(JSON.stringify(baseFormData));
        let hasData = false;

        this.activeTypeFields.forEach(f => {
            const h = this.csvMapping.dynamic[f.key];
            // Overwrite only if the field is mapped (inherit editor's fixed value if unmapped)
            if (h) {
              const idx = this.csvHeaders.indexOf(h);
              const val = (idx !== -1 && row[idx]) ? row[idx].trim() : "";

              if (val) hasData = true;

              if (this.selectedType === 'url') specificFormData.url.address = val;
              else if (this.selectedType === 'text') specificFormData.text.content = val;
              else if (this.selectedType === 'wifi') {
                if (f.key === 'hidden') {
                  specificFormData.wifi[f.key] = (val.toLowerCase() === 'true' || val === '1');
                } else {
                  specificFormData.wifi[f.key] = val;
                }
              }
              else if (this.selectedType === 'vcard') specificFormData.vcard[f.key] = val;
              else if (this.selectedType === 'event') specificFormData.event[f.key] = val;
              else if (this.selectedType === 'email') specificFormData.email[f.key] = val;
              else if (this.selectedType === 'sms') specificFormData.sms[f.key] = val;
              else if (this.selectedType === 'crypto') specificFormData.crypto[f.key] = val;
              else if (this.selectedType === 'geo') specificFormData.geo[f.key] = val;
              else if (this.selectedType === 'sns') specificFormData.sns[f.key] = val;
              else if (this.selectedType === 'images') specificFormData.images.url = val;
              else if (this.selectedType === 'video') specificFormData.video.url = val;
            }
        });

        if (!hasData) continue; // Skip if data is empty

        const nameStr = idxName !== -1 && row[idxName] ? row[idxName].trim() : `Bulk QR ${count}`;
        const memoStr = idxMemo !== -1 && row[idxMemo] ? row[idxMemo].trim() : "";
        const tagsStr = idxTags !== -1 && row[idxTags] ? row[idxTags].trim() : "";
        const tagsArray = tagsStr ? tagsStr.split(',').map(t => t.trim()).filter(t => t) : [];

        // Deep copy of design options (to break reference)
        const specificOptions = JSON.parse(JSON.stringify(restOptions));
        specificOptions.logo = logo;

        const dataStringContext = { selectedType: this.selectedType, formData: specificFormData };
        const dataString = this.getQrDataString.call(dataStringContext);

        if (!dataString || dataString.trim() === "") continue;

        const builderContext = {
          qrOptions: specificOptions,
          buildDotsOptions: this.buildDotsOptions,
          buildCornersSquareOptions: this.buildCornersSquareOptions,
          buildCornersDotOptions: this.buildCornersDotOptions,
        };

        const previewOptions = {
          width: 80, height: 80,
          data: dataString,
          image: specificOptions.logo,
          dotsOptions: builderContext.buildDotsOptions.call(builderContext),
          backgroundOptions: { color: fixHex(specificOptions.backgroundColor) },
          cornersSquareOptions: builderContext.buildCornersSquareOptions.call(builderContext),
          cornersDotOptions: builderContext.buildCornersDotOptions.call(builderContext),
          qrOptions: { errorCorrectionLevel: specificOptions.errorCorrectionLevel },
          imageOptions: {
            ...specificOptions.imageOptions,
            margin: specificOptions.imageOptions.margin ? specificOptions.imageOptions.margin / 4 : 0,
          },
          margin: specificOptions.margin ? specificOptions.margin / 4 : 0,
        };

        let previewSvgUrl = "";
        try {
          previewSvgUrl = await this.getPreviewSvgUrl(previewOptions);
        } catch(e) {
          console.warn("Skipped row due to capacity error", e);
          continue;
        }

        newQRCodes.push({
          id: this.generateUniqueId(),
          projectId: this.importTargetProject,
          name: nameStr,
          memo: memoStr,
          tags: tagsArray,
          type: this.selectedType,
          isFavorite: false,
          formData: specificFormData,
          qrOptions: specificOptions,
          logoFileName: this.logoFileName,
          frame: JSON.parse(JSON.stringify(baseFrame)),
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          previewSvgUrl: previewSvgUrl,
        });
      }

      // Reflect generated data to dashboard and save
      if (newQRCodes.length > 0) {
        this.savedQRCodes = [...newQRCodes, ...this.savedQRCodes];
        await this.persistSavedQRCodes();
        this.currentProjectId = this.importTargetProject;
        this.currentPage = 1;
        if (typeof setDirty === 'function') setDirty(true);
        this.importProgress = 100;
        await new Promise(resolve => setTimeout(resolve, 400));

        let msg = `Successfully generated ${newQRCodes.length} QR codes.`;
        if (newQRCodes.length < this.csvData.length) {
          const skipped = this.csvData.length - newQRCodes.length;
          msg += ` (${skipped} row${skipped > 1 ? 's' : ''} skipped due to data limit)`;
          this.hapticFeedback('error');
        } else {
          this.hapticFeedback('success');
        }
        this.showFlashNotification(msg);
      } else {
        this.showFlashNotification("No valid URLs found in the CSV.");
        this.hapticFeedback('error');
      }

      this.isImporting = false;
      this.showImportModal = false;
    },
    async copyShareImage(qr) {
      if (!navigator.clipboard || !window.ClipboardItem) {
        this.showFlashNotification("Your browser does not support copying images (HTTPS required).");
        return;
      }
      try {
        const blobPromise = this.svgDataUrlToPngBlob(qr.previewSvgUrl, 512);
        const clipboardItem = new window.ClipboardItem({
          "image/png": blobPromise
        });
        await navigator.clipboard.write([clipboardItem]);
        this.showFlashNotification("Copied the image to the clipboard!");
        this.hapticFeedback('success');
      } catch (e) {
        console.error("Image copy failed", e);
        this.showFlashNotification("Failed to copy the image.");
      }
    },
    toggleQuietZone() {
      this.includeQuietZone = !this.includeQuietZone;
      this.qrOptions.margin = this.includeQuietZone ? 20 : 0;
      this.updateQrCode();
    },
    getActiveBrandKit() {
      return this.brandKits.find(b => b.id === this.activeBrandKitId) || null;
    },
    async createNewBrandKit() {
      const name = await appPrompt("Enter brand name (e.g. Client A):", "text");
      if (!name || !name.trim()) return;

      const newKit = {
        id: this.generateUniqueId(),
        name: name.trim(),
        logo: null,
        colors: ["#000000", "#ffffff"]
      };
      this.brandKits.push(newKit);
      this.activeBrandKitId = newKit.id;
      this.saveBrandKits();
      this.applyBrandKit(); // 新規作成時は自動適用
      this.showFlashNotification(`Brand "${newKit.name}" created.`);
    },
    async renameBrandKit() {
      const kit = this.getActiveBrandKit();
      if (!kit) return;
      const newName = await appPrompt(`Rename "${kit.name}":`, "text");
      if (!newName || !newName.trim()) return;
      kit.name = newName.trim();
      this.saveBrandKits();
    },
    async deleteBrandKit() {
      if (!this.activeBrandKitId) return;
      const kit = this.getActiveBrandKit();
      if (!confirm(`Are you sure you want to delete "${kit.name}"?`)) return;

      this.brandKits = this.brandKits.filter(b => b.id !== this.activeBrandKitId);
      this.activeBrandKitId = this.brandKits.length > 0 ? this.brandKits[0].id : null;
      this.saveBrandKits();
      if (this.activeBrandKitId) this.applyBrandKit(); // 削除後は次のものを自動適用
      this.showFlashNotification("Brand kit deleted.");
    },
    async selectBrandLogo(logoUrl) {
      const kit = this.getActiveBrandKit();
      if (!kit) return;
      try {
        const response = await fetch(logoUrl);
        const blob = await response.blob();
        const reader = new FileReader();
        reader.onloadend = () => {
          kit.logo = reader.result;
          this.qrOptions.logo = reader.result;
          this.logoFileName = logoUrl.split('/').pop();
          this.updateQrCode();
          this.saveBrandKits(false);
        };
        reader.readAsDataURL(blob);
      } catch (error) {
        console.error("Failed to fetch logo", error);
        this.showFlashNotification("Failed to load the logo.");
      }
    },
    removeBrandLogo() {
      const kit = this.getActiveBrandKit();
      if (!kit) return;
      kit.logo = null;
      this.saveBrandKits(false);

      const fileInput = document.getElementById("brand-logo-upload");
      if (fileInput) fileInput.value = "";
    },
    handleBrandLogoUpload(event) {
      const kit = this.getActiveBrandKit();
      if (!kit) return;
      const file = event.target.files[0];
      if (!file) return;

      if (file.type === "image/svg+xml" && file.size > 500 * 1024) {
        this.showFlashNotification("SVG logos can be heavy to process. Please select a file smaller than 500KB.");
        event.target.value = "";
        return;
      }
      if (file.size > 500 * 1024) {
        this.showFlashNotification("To save in the brand kit, please select a logo smaller than 500KB.");
        event.target.value = "";
        return;
      }

      const reader = new FileReader();
      reader.onload = (e) => {
        kit.logo = e.target.result;
        this.qrOptions.logo = e.target.result;
        this.logoFileName = file.name;
        this.updateQrCode();
        this.saveBrandKits(false);
        event.target.value = "";
      };
      reader.onerror = () => {
        this.showFlashNotification("Failed to read the file. It may be locked or corrupted.");
        this.hapticFeedback('error');
      };
      reader.readAsDataURL(file);
    },
    saveBrandKits(showNotification = true) {
      try {
        localStorage.setItem("qrBrandKits", JSON.stringify(this.brandKits));
        if (showNotification) {
          this.showFlashNotification("Brand kit saved.");
        }
      } catch(e) {
        this.showFlashNotification("Could not save brand settings due to storage limits.");
      }
    },
    loadBrandKit() {
      try {
        const kits = localStorage.getItem("qrBrandKits");
        if (kits) {
          this.brandKits = JSON.parse(kits);
          this.brandKits.forEach(kit => {
            if (kit.logo && !kit.logo.startsWith("data:")) kit.logo = null;
          });
          if (this.brandKits.length > 0) this.activeBrandKitId = this.brandKits[0].id;
        } else {
          // Automatic migration from v1 (Single object)
          const oldKit = localStorage.getItem("qrBrandKit");
          if (oldKit) {
            const parsed = JSON.parse(oldKit);
            if (parsed.logo && !parsed.logo.startsWith("data:")) parsed.logo = null;
            const migratedKit = {
              id: this.generateUniqueId(),
              name: "My Brand",
              logo: parsed.logo,
              colors: parsed.colors || ["#000000", "#ffffff"]
            };
            this.brandKits = [migratedKit];
            this.activeBrandKitId = migratedKit.id;
            localStorage.removeItem("qrBrandKit"); // Delete old data
            this.saveBrandKits(false);
          } else {
            this.brandKits = [];
          }
        }
      } catch (e) {
        console.warn("Failed to load brand kits", e);
        this.brandKits = [];
      }
    },
    applyBrandKit() {
      const kit = this.getActiveBrandKit();
      if (!kit) return;

      if (kit.logo) {
        this.qrOptions.logo = kit.logo;
        this.logoFileName = kit.name + " Logo";
      } else {
        this.qrOptions.logo = null;
        this.logoFileName = "";
      }
      this.qrOptions.colorType = "single";
      this.qrOptions.foregroundColor = kit.colors[0];
      this.qrOptions.cornerColor = kit.colors[0];
      this.qrOptions.cornerDotColor = kit.colors[0];
      this.qrOptions.backgroundColor = kit.colors[1];
      this.updateQrCode();

      this.showFlashNotification(`Applied ${kit.name} settings.`);
      this.hapticFeedback('light');
    },
    hexToRgb(hex) {
      let shorthandRegex = /^#?([a-f\d])([a-f\d])([a-f\d])$/i;
      hex = hex.replace(shorthandRegex, function(m, r, g, b) {
        return r + r + g + g + b + b;
      });
      let result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
      return result
        ? {
            r: parseInt(result[1], 16),
            g: parseInt(result[2], 16),
            b: parseInt(result[3], 16),
          }
        : null;
    },
    getLuminance(r, g, b) {
      const a = [r, g, b].map((v) => {
        v /= 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
      });
      return a[0] * 0.2126 + a[1] * 0.7152 + a[2] * 0.0722;
    },
    getContrast(rgb1, rgb2) {
      const lum1 = this.getLuminance(rgb1.r, rgb1.g, rgb1.b);
      const lum2 = this.getLuminance(rgb2.r, rgb2.g, rgb2.b);
      return (Math.max(lum1, lum2) + 0.05) / (Math.min(lum1, lum2) + 0.05);
    },
    isDotColorBright() {
      if (this.qrOptions.colorType === "gradient") {
        const rgb1 = this.hexToRgb(this.qrOptions.gradient.color1);
        const rgb2 = this.hexToRgb(this.qrOptions.gradient.color2);
        if (!rgb1 || !rgb2) return false;
        const avgLum = (this.getLuminance(rgb1.r, rgb1.g, rgb1.b) + this.getLuminance(rgb2.r, rgb2.g, rgb2.b)) / 2;
        return avgLum > 0.5;
      } else {
        const rgb = this.hexToRgb(this.qrOptions.foregroundColor);
        if (!rgb) return false;
        return this.getLuminance(rgb.r, rgb.g, rgb.b) > 0.5;
      }
    },
  };
}

// --- PWA Installation Prompt ---
let deferredPrompt;

window.addEventListener("beforeinstallprompt", (e) => {
  // Prevent the mini-infobar from appearing on mobile
  e.preventDefault();
  // Stash the event so it can be triggered later
  deferredPrompt = e;
  // Update UI notify the user they can install the PWA
  const installBtn = document.getElementById("install-button");
  if (installBtn) {
    installBtn.classList.remove("hidden");
    installBtn.onclick = async () => {
      if (deferredPrompt) {
        deferredPrompt.prompt();
        const { outcome } = await deferredPrompt.userChoice;
        console.log(`User response to the install prompt: ${outcome}`);
        deferredPrompt = null;
        if (outcome === 'accepted') {
          installBtn.classList.add("hidden");
        }
      } else {
        const app = window.$app;
        if (app && typeof app.showFlashNotification === 'function') {
          app.showFlashNotification("💡 Please install the app from your browser's menu (⋮) or the address bar.");
          app.hapticFeedback('light');
        } else {
          alert("Please install the app from your browser's menu.");
        }
      }
    };
  }
});

window.addEventListener("appinstalled", () => {
  const installBtn = document.getElementById("install-button");
  if (installBtn) installBtn.classList.add("hidden");
  deferredPrompt = null;
  console.log("PWA was installed");
});

// --- Prevent multiple tabs (Data conflict prevention) ---
let hasAlertedMultiTab = false;

if (typeof BroadcastChannel !== "undefined") {
  const bc = new BroadcastChannel("grindqrcoder_app_channel");

  bc.onmessage = async (e) => {
    if (e.data === "ping") {
      bc.postMessage("pong"); // Tab already open responds
    } else if (e.data === "pong") {
      // If this tab was opened later
      if (!hasAlertedMultiTab) {
        hasAlertedMultiTab = true;
        alert("QR Coder is already open in another tab or window.\n\nTo prevent data conflicts and overwriting, please close this tab and use the originally opened one.");
        document.body.style.opacity = "0.5";
        document.body.style.pointerEvents = "none";
      }
    } else if (e.data === "closed") {
      // Original tab was closed, unlock this tab
      if (hasAlertedMultiTab) {
        hasAlertedMultiTab = false;
        document.body.style.opacity = "";
        document.body.style.pointerEvents = "";
        if (window.$app) window.$app.showFlashNotification("The other tab was closed. You can now use the app here.");
      }
    }
  };
  bc.postMessage("ping");

  window.addEventListener("beforeunload", () => bc.postMessage("closed"));
}

// --- Register Service Worker (Required for full offline PWA) ---
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('sw.js').then(registration => {
      console.log('ServiceWorker registration successful with scope: ', registration.scope);

      // Detect updates
      registration.addEventListener('updatefound', () => {
        const newWorker = registration.installing;
        newWorker.addEventListener('statechange', () => {
          // Prompt reload when a new SW is installed and an old SW already exists (an update)
          if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
            // Safely wait for Alpine.js app to be mounted
            let attempts = 0;
            const tryNotify = setInterval(() => {
              attempts++;
              if (window.$app) {
                clearInterval(tryNotify);
                if (window.$app.hasUnsavedEdit) {
                  // Tell user about update but don't force reload
                  window.$app.showFlashNotification("✨ App update ready. Reload the page when you are done.");
                } else {
                  // Trigger reactive Alpine click handler inside the component
                  window.$app.showFlashNotification("✨ App updated! Tap here to reload.", true);
                }
              } else if (attempts > 50) {
                clearInterval(tryNotify); // Give up after 5 seconds
              }
            }, 100);
          }
        });
      });
    }).catch(err => {
      console.log('ServiceWorker registration failed: ', err);
    });
  });
}
})();
