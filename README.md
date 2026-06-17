# QR Coder 📱

**A privacy-first, highly functional QR code generator that works completely offline.**

[![Demo](https://img.shields.io/badge/Demo-Play_Now-blue?style=for-the-badge)](https://grindsite.com/tools/qrcoder/)

> **Note:** The official and most up-to-date version of this application is available at [https://grindsite.com/tools/qrcoder/](https://grindsite.com/tools/qrcoder/). Please be wary of unauthorized copies.

<img src="./grind-qrcoder.jpg" width="800" alt="QR Coder Hero Image" />

**QR Coder** is a PWA (Progressive Web App) that instantly converts any shared link—such as URLs, Wi-Fi settings, and SNS profiles—into high-quality QR codes.
All entered data and configuration history are saved locally in the browser's IndexedDB. Therefore, it requires no external data communication and operates in a completely offline environment.

## Philosophy & Features

### 1. Privacy by Design (No SaaS, No Subscriptions)
This application does not send user data to any external servers.
By strictly specializing in QR code generation, it provides a secure, lightweight operating environment and perfectly protects user data privacy.
**The source code is published as open-source, ensuring high transparency and security.**

### 2. Offline-First Architecture (PWA)
There are no server-side processes or dependencies on external databases.
Once you "Install as App" from your browser, all necessary resources are cached on your device. It launches and operates instantly without any delay, even in an environment with absolutely no network connection.

### 3. Advanced Design & Quality Control
- **Advanced Customization:** You can apply gradient colors, change dot and corner shapes, place logos, and add custom frames like "SCAN ME".
- **Brand Kit & Preset Templates:** Save your frequently used logos and brand colors to apply them instantly. Alternatively, choose from a wide variety of beautifully crafted, one-click preset templates (including styles tailored for popular social media and services).
- **QR Code Quality Score:** It evaluates inadequate contrast ratios, data loss rates due to logos, and URL lengths in real time to prevent scanning errors (accidents) before they happen.
- **Refined UX:** It prevents device-specific behaviors (such as the iOS zoom bug) and offers an operational feel comparable to native apps, featuring high-quality focus rings and smooth animations.

### 4. Smart Dashboard Management
- **Local Persistence:** Manage all generated QR codes seamlessly in the built-in dashboard.
- **Organize & Search:** Add tags and memos to your QR codes. Click on any tag to instantly filter your list, and seamlessly update details using inline editing.
- **Smart Paste & UTM Manager:** Paste multiple URLs or links with UTM parameters to automatically parse and organize them as variants under a single design.
- **Bulk Import (CSV):** Instantly generate massive amounts of QR codes by dropping a CSV file. The current design in the editor is automatically applied to all of them.
- **Export Campaign URLs:** Extract and export your generated base and variant URLs as a CSV or Markdown list for easy ad campaign management.
- **Diverse Formats:** Supports a wide range of data types including URLs, Wi-Fi, vCards, Calendar Events, Geo-locations, Email, SMS, Cryptocurrency, SNS profiles, and media links.

### 5. Built-in Scanner & Verifier
- **Secure Offline Scanning:** Verify the contents of any QR code securely without sending data to external servers.
- **Camera & Image Support:** Use your device's camera or upload image files to quickly decode and safely verify the encoded information.

### 6. Strong Encryption & Seamless File Management
Directly read and write local database files (`.qrcoder`) on your OS from the browser. Simply double-click the file on your OS to launch the app and automatically load the data (File Handling API).
Alternatively, just **drag and drop** a `.qrcoder` backup file anywhere on the screen to instantly restore your workspace.
When saving, strong encryption via `AES-256-GCM` using the Web Crypto API can be applied. Even if the file is leaked, it can never be decrypted without the password.

- **🚨 Warning:** If you forget your password, due to the nature of encryption, data recovery is technically 100% impossible. Please manage your password carefully.
- **💡 Recommended Browsers:** We strongly recommend using **Chrome** or **Edge**, which fully support direct overwrite saving (File System Access API). (In Safari/Firefox, it will be downloaded and saved as a new file each time).

### 7. Refined Keyboard Navigation (Grind & Polish)
- **Command Palette (Cmd+K / Ctrl+K):** Instantly access data saving, loading, and various setting functions without using a mouse.
- **Robust Fail-Safe & Auto Draft:** It instantly detects unsaved editing states and automatically saves drafts in the background to prevent data loss caused by accidental tab closures, browser crashes, or operational mistakes.

## How to Use

1. For security reasons, be sure to access `index.html` in an **HTTPS environment** (GitHub Pages, Vercel, etc.) or locally via `localhost`.
2. Click the icon in the address bar or the button on the screen to "Install App" as a PWA.
3. From then on, you can use it completely offline as a standalone application on your PC or smartphone.

## File Structure

- `index.html`: The main file including UI and application logic (Alpine.js, IndexedDB control, encryption features).
- `styles.css`: The style file generated by Tailwind CSS.
- `sw.js`: Service Worker for the PWA (Full offline capability, cache control).
- `manifest.json`: PWA Manifest.

## Disclaimer

This software adopts a "local-first" architecture, and all data is stored within your PC (or your browser's IndexedDB).
Since automatic backups to external servers are not performed, there is a risk of data loss due to PC failure, browser cache clearance, or unexpected errors.

**The author (Grind Works Inc.) takes no responsibility for any data loss or damages caused by using this software.**

We strongly recommend saving frequently (Cmd+S / Ctrl+S) when your daily entries are complete, and backing up the output `.qrcoder` file to external storage such as Google Drive or Dropbox.

## ライセンス

MIT License
