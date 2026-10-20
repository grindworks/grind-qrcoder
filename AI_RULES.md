# QR Coder AI Rules

> Product type: PWA. Shared rules: [`../AGENTS.md`](../AGENTS.md) §1, §2, §4, §6 and the PWA rules in §7. This file adds QR Coder rules and wins where the two differ.

## 1. Stack

- Alpine.js app: the root is `x-data="qrCodeGenerator()"` (factory in `main.js`), with the `collapse` and `focus` plugins. Load `alpine.min.js` last among the deferred scripts; `init()` needs the libraries before it.
- Vendored libraries in `assets/`: `qr-code-styling`, `html5-qrcode`, `fflate`, `DOMPurify`.
  - `qr-code-styling` is patched to encode text as UTF-8 by default (`stringToBytesFuncs.default`). Keep that patch when updating the library, then re-check that Japanese and emoji payloads decode correctly.
  - `html5-qrcode` loads on first use of the Verify tab (`loadScannerLibrary()`). It stays in the `sw.js` precache.
- Tailwind CSS v4.2.4. `./build.sh` downloads the standalone binary for the current OS on first run and checks its pinned SHA-256. The binary is git-ignored.

## 2. Data and files

- Storage: IndexedDB `GrindQRCoderDB_Standalone`. Saved QR codes are written as a diff (changed records only); projects, templates and brand kits are rewritten whole.
- Backups: `.qrcoder` (JSON) and `.qrcoder-theme` (design assets). Opened via the File System Access API, drag and drop, or `launchQueue`. Optional `GRINDEN2` encryption: minimum 8 characters, passwords normalized to NFC.
- Imports go through the `sanitizeImported*` helpers. Image fields accept `data:image/...` URLs only, so imported files cannot make the app load remote URLs.
- Two unsaved-state flags:
  - `isDirty` (`setDirty()`): the library changed since the last `.qrcoder` save or load. Drives the unsaved badge and the warning when the tab closes.
  - `hasUnsavedEdit`: the editor holds unsaved changes. Drives confirmations when leaving the editor and the auto-draft.
- Auto-drafts never store the Wi-Fi password. When an edit of a saved QR code is restored, the password comes back from the saved record.
- Every path that saves, downloads or copies a QR code must check the payload first (`canExportQr` for buttons, `getQrPayloadBlockReason()` for code paths).
- Saved QR codes, including Wi-Fi passwords, are stored in plaintext in IndexedDB; encryption applies only to exported backups.
- Media types (image gallery, video) are links only (YouTube, Google Photos and similar). Never imply that a local file is hosted online.

## 3. UI

- Look, top bar, shortcuts, toasts, dialogs, wording and languages follow shared §7 UI. Do not restate them here; add only what differs.
- Exempt from the shared shape and toast rules: qrcoder keeps its own layout (tabs and cards), corner radius and shadows, and its own toast (`flash-toast`, placed by the app) next to the update prompt. Do not migrate it to `rounded-md` or `showToast`.
- Use `@input.debounce`, never `x-model.debounce`.
- Dialogs: `appAlert()`, `appConfirm()` and `appPrompt()` follow the shared §7 signatures. They are Alpine modals; in Alpine handlers use `await appConfirm(...)`.
- Product-specific top-bar controls: none. QR Coder has no Alt+N; it has Undo and Redo (Cmd/Ctrl+Z, Cmd/Ctrl+Y) instead.
- The update prompt (`notifyAppUpdate()` and `window.applyAppUpdate()`) is the reference implementation of the shared update toast.
- UI language: English only, for overseas users. Strings stay inline in `index.html` and `main.js`; qrcoder has no `lang/` folder or `i18n.js`, and no language choice.

## 4. Known gaps against shared §7

- Hard-coded hex colors remain in the `<style>` block of `index.html` (scrollbar, tooltip and swatch borders); move them to Tailwind palette variables.
- Tailwind is 4.2.4 with SHA-256 pins in `build.sh`; move to 4.3.1 and update the pins.
- `.gitattributes` has a Japanese comment.
