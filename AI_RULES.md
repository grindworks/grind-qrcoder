# QR Coder AI Rules

## 1. Environment & Architecture

- **Serverless & Offline-First (PWA):** No Backend (No PHP, No Node.js). The application MUST run entirely in the browser using HTML, Vanilla JavaScript, Alpine.js, and Tailwind CSS.
- **IndexedDB & JSON Storage:** Database operations are performed in the browser's IndexedDB for local persistence. Exported data is saved as `.qrcoder` files (JSON format).
- **Local File Management:** Read/Write operations are strictly handled via the **File System Access API** (with fallbacks) and the **File Handling API** (`launchQueue`). Never suggest uploading files to a server.
- **Strong Security:** Data saving must pass through Web Crypto API (`AES-256-GCM`) when a password is provided.
- **Absolute Portability (CRITICAL):**
  - **Zero Build Tools:** Do NOT suggest adding `npm`, `Webpack`, `Vite`, or ES Modules that require a build step. The system MUST work instantly by just opening `index.html` in a modern browser.
  - **Offline Asset Management:** Ensure all UI assets and external scripts (e.g., `@alpinejs/collapse`, `qr-code-styling`) are explicitly added to the Service Worker (`sw.js`) cache list to guarantee 100% offline functionality.

## 2. Coding Standards & Data Handling

- **JavaScript (Modern ES6+ & Alpine.js):** Use modern features (arrow functions, template literals, destructuring, Optional Chaining). Use Alpine.js (`x-data`, `x-bind`, `x-transition`, `x-collapse`) for UI state management.
- **Data Persistence & Safety:**
  - Data modifications (creating, editing, deleting) update the Alpine.js state and persist to IndexedDB.
  - Any operation that modifies the unsaved configuration MUST set a flag (`isDirty = true` via `setDirty()`) to warn the user before they close the tab or switch views.
  - **Memory Management:** Clean up object URLs (`URL.revokeObjectURL()`) and avoid deep copying massive Base64 strings to prevent memory leaks and UI stuttering.
- **Error Handling (FAIL-SAFE):**
  - Assume files selected by the user might be corrupted or manipulated. Always wrap decryption and `JSON.parse` in robust `try...catch` blocks.
  - Fail gracefully with user-friendly alerts or toast notifications (`showFlashNotification`), allowing the user to retry without reloading the app.

## 3. Frontend (S-Rank UI & Hacker Aesthetic)

- **Tailwind CSS:** Use Tailwind utility classes for all styling. The app strictly uses a light theme (do not use `dark:` classes). Avoid custom CSS in `<style>` blocks unless absolutely necessary (e.g., custom scrollbars).
- **Icons (SVG Sprites):** Icons are loaded via external SVG sprites (`<use href="icons-sprite.svg#icon-name"></use>`).
- **Micro-Interactions & UX:**
  - Enhance the "Grind (fast input)" experience. Ensure form submissions do not cause page reloads (`@submit.prevent`).
  - Use `@input.debounce` instead of `x-model.debounce` to prevent input lag.
  - Maintain focus on input fields programmatically after actions.
  - Ensure UI transitions do not cause layout shifts (CLS). Use Alpine.js `x-transition` and `@alpinejs/collapse` for smooth animations.
- **Minimalist Hacker Vibe:** Keep the UI clean. Hide complex actions in the Command Palette (`Cmd+K`).

## 4. AI Directives

- **Deep Contextual Analysis:** Do not act like a naive static analysis tool. Analyze actual data flow in the browser memory (e.g., Alpine.js component scope vs. window scope) before suggesting "optimizations."
- **Respect Design Philosophy:** Maintain the "Serverless & Subscription-free" nature of the tool. Do NOT suggest features that require external hosting for user media. Media features (like Video or Image Galleries) MUST strictly be URL-based (e.g., YouTube links, Google Photos links). Do not implement local file uploads that mislead users into thinking their files are hosted online.
- **Language:** Output chat explanations in **Japanese**. Code & comments strictly in **English**.
