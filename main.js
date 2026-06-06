// --- グローバル関数・変数 (ファイル保存・読み込み・コマンドパレット) ---
let isDirty = false;
let fileHandle = null;

// --- 暗号化・復号化ロジック ---
const MAGIC_BYTES = new TextEncoder().encode("GRINDEN2");
const MAGIC_BYTES_LEGACY = new TextEncoder().encode("GRINDENC");

function appPrompt(message) {
  return new Promise((resolve) => {
    const app = window.$app;
    app.promptMessage = message;
    app.promptInput = "";
    app.resolvePrompt = resolve;
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
    throw new Error("パスワードが間違っているか、ファイルが破損しています。");
  }
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
  const fileName = fileHandle && fileHandle.name ? fileHandle.name : "Backup.json";
  const filenameBadge = document.getElementById("current-filename");
  if (filenameBadge) {
    filenameBadge.textContent = fileName;
    filenameBadge.classList.remove("hidden");
  }
}

async function processQRCoderFile(file) {
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
          }
        } catch (err) {
          const msg = attempt > 0 ? "❌ パスワードが間違っています。もう一度入力してください:" : "ファイルは暗号化されています。解除パスワードを入力してください:";
          password = await appPrompt(msg);
          if (password === null) return;
          attempt++;
        }
      }
      text = new TextDecoder().decode(Uints);
    } else {
      text = new TextDecoder().decode(Uints);
    }

    const data = JSON.parse(text);

    const component = window.$app;
    component.savedQRCodes = data;
    await component.persistSavedQRCodes();

    setDirty(false);
    component.showFlashNotification(`ファイル "${file.name}" を読み込みました`);
    component.currentView = 'dashboard';
  } catch (err) {
    console.error(err);
    alert("ファイルの読み込みに失敗しました。ファイルが破損しているか形式が違います。");
  }
}

async function loadQRCoderFile() {
  if (isDirty) {
    if (!confirm("未保存の変更（ダッシュボード）があります。変更を破棄して別のバックアップを読み込みますか？")) return;
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
    console.error(err);
    alert("ファイルの読み込みに失敗しました。ファイルが破損しているか形式が違います。");
  }
}

async function saveQRCoderFile() {
  const component = window.$app;
  if (component.hasUnsavedEdit) {
    alert("未保存の編集データがあります。\n先に画面下部の「ダッシュボードにQRデータを保存」を行ってから、バックアップを実行してください。");
    return;
  }

  try {
    const dataString = JSON.stringify(component.savedQRCodes, null, 2);

    let fileData = dataString;
    const pwInput = document.getElementById("file-password");

    const saveBtn = document.getElementById("btn-save");
    let originalHtml = "";
    if (saveBtn) {
      originalHtml = saveBtn.innerHTML;
      saveBtn.innerHTML = '<svg class="w-4 h-4 animate-spin" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>';
      saveBtn.disabled = true;
    }

    // UIの再描画を待つための遅延（メインスレッドの解放）
    await new Promise(resolve => setTimeout(resolve, 50));

    if (pwInput && pwInput.value) {
      const encoder = new TextEncoder();
      const uint8Data = encoder.encode(dataString);
      const encryptedUints = await encryptData(uint8Data, pwInput.value);
      fileData = encryptedUints;
    }

    if ("showSaveFilePicker" in window) {
      try {
        fileHandle = await window.showSaveFilePicker({
          suggestedName: fileHandle && fileHandle.name ? fileHandle.name : "Data.qrcoder",
          types: [{ description: "QR Coder Database", accept: { "application/json": [".qrcoder"] } }]
        });
        const writable = await fileHandle.createWritable();
        await writable.write(fileData);
        await writable.close();
      } catch (err) {
        console.log("Save cancelled.", err);
        return;
      }
    } else {
      const blob = new Blob([fileData], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = fileHandle && fileHandle.name ? fileHandle.name : "Data.qrcoder";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      fileHandle = { name: a.download };
    }

    setDirty(false);

    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.innerHTML = originalHtml;
      const iconSvg = saveBtn.querySelector("svg");
      if (iconSvg) {
        const originalUse = iconSvg.innerHTML;
        // 保存成功時のアイコン切り替え
        iconSvg.innerHTML = '<use href="icons-sprite.svg#outline-check"></use>';
        iconSvg.classList.add("text-green-500", "scale-125");
        setTimeout(() => {
          iconSvg.innerHTML = originalUse;
          iconSvg.classList.remove("text-green-500", "scale-125");
        }, 1500);
      }
    }
    component.showFlashNotification("バックアップを保存しました。");
  } catch (err) {
    console.error(err);
    alert("保存に失敗しました。");
  }
}

let isCommandPaletteOpen = false;
let selectedCommandIndex = 0;
const commandsList = [
  { id: "save", icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="1.5"><use href="icons-sprite.svg#outline-arrow-down-tray"></use></svg>', title: "バックアップを保存 (Save)", action: () => saveQRCoderFile() },
  { id: "open", icon: '<svg class="w-5 h-5"><use href="icons-sprite.svg#outline-folder"></use></svg>', title: "バックアップを読み込む (Open)", action: () => loadQRCoderFile() }
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

function toggleCommandPalette() {
  const palette = document.getElementById("cmd-palette");
  const input = document.getElementById("cmd-input");
  if (!palette) return;

  isCommandPaletteOpen = !isCommandPaletteOpen;
  if (isCommandPaletteOpen) {
    palette.classList.remove("hidden");
    palette.classList.add("flex");
    input.value = "";
    selectedCommandIndex = 0;
    renderCommandList();
    setTimeout(() => input.focus(), 50);
  } else {
    palette.classList.add("hidden");
    palette.classList.remove("flex");
  }
}

function renderCommandList(query = "") {
  const list = document.getElementById("cmd-list");
  if(!list) return;
  list.innerHTML = "";
  const terms = query.toLowerCase().split(/[\s　]+/).filter(Boolean);
  const filtered = commandsList.filter(c => terms.every(term => c.title.toLowerCase().includes(term) || c.id.includes(term)));

  if (filtered.length === 0) {
    list.innerHTML = `<div class="px-4 py-8 text-center text-slate-400 text-sm">見つかりませんでした</div>`;
    return;
  }

  if (selectedCommandIndex >= filtered.length) selectedCommandIndex = 0;

  filtered.forEach((cmd, i) => {
    const div = document.createElement("div");
    const isSelected = i === selectedCommandIndex;
    div.className = `px-4 py-3 my-1 flex justify-between items-center rounded-md cursor-pointer transition-colors ${isSelected ? "bg-primary-50 text-primary" : "text-slate-600 hover:bg-slate-100"}`;
    div.innerHTML = `<div class="flex items-center gap-3"><span class="text-xl">${cmd.icon}</span><span class="font-medium tracking-wide">${cmd.title}</span></div>`;
    div.onclick = () => {
      toggleCommandPalette();
      cmd.action();
    };
    list.appendChild(div);
  });
}

document.addEventListener("keydown", (e) => {
  const target = e.target;
  const isInputFocused = target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable;

  // コマンドパレットが開いている時のリスト操作
  if (isCommandPaletteOpen) {
    if (e.key === "Escape") {
      toggleCommandPalette();
      return;
    }
    const input = document.getElementById("cmd-input");
    const filtered = commandsList.filter(c => input.value.toLowerCase().split(/[\s　]+/).filter(Boolean).every(term => c.title.toLowerCase().includes(term) || c.id.includes(term)));

    if (e.key === "ArrowDown") {
      e.preventDefault();
      selectedCommandIndex = (selectedCommandIndex + 1) % filtered.length;
      renderCommandList(input.value);
      return;
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      selectedCommandIndex = (selectedCommandIndex - 1 + filtered.length) % filtered.length;
      renderCommandList(input.value);
      return;
    } else if (e.key === "Enter" && filtered[selectedCommandIndex]) {
      e.preventDefault();
      toggleCommandPalette();
      filtered[selectedCommandIndex].action();
      return;
    }
    return; // コマンドパレットが開いている時は他のショートカットは無視
  }

  // 入力フォームにフォーカスがある場合はショートカットを無効化（Escapeは除く）
  if (isInputFocused && e.key !== "Escape") {
    return;
  }

  if ((e.metaKey || e.ctrlKey) && e.key === "k") {
    e.preventDefault();
    toggleCommandPalette();
    return;
  }
  if ((e.metaKey || e.ctrlKey) && e.key === "s") {
    e.preventDefault();
    saveQRCoderFile();
    return;
  }
  if ((e.metaKey || e.ctrlKey) && e.key === "o") {
    e.preventDefault();
    loadQRCoderFile();
    return;
  }
  if (e.key === "Escape") {
    const app = window.$app;
    if (app && (app.showSaveModal || app.showShareModal || app.showDownloadModal || app.showSceneModal || app.showPromptModal)) {
      return;
    }
  }
});

document.getElementById("cmd-input")?.addEventListener("input", (e) => {
  selectedCommandIndex = 0;
  renderCommandList(e.target.value);
});

document.addEventListener("DOMContentLoaded", () => {
  const isMac = navigator.userAgent.toLowerCase().includes("mac") || navigator.platform.toLowerCase().includes("mac");
  const shortcutEl = document.getElementById("cmd-shortcut-key");
  if (shortcutEl) {
    shortcutEl.textContent = isMac ? "⌘K" : "Ctrl+K";
  }

  // 画面外への誤ドロップによる強制画面遷移（データロスト）を防止
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => e.preventDefault());

  // PWA File Handling API (ファイルをダブルクリックして起動した時の処理)
  if ('launchQueue' in window) {
    window.launchQueue.setConsumer(async (launchParams) => {
      if (!launchParams.files || launchParams.files.length === 0) return;
      const fileHandleParams = launchParams.files[0];

      try {
        const file = await fileHandleParams.getFile();
        window.fileHandle = fileHandleParams; // グローバルにセット (上書き保存を可能にするため)

        // Alpineコンポーネントが初期化されるのを少し待ってから読み込む
        setTimeout(() => {
          if(window.$app && typeof processQRCoderFile === 'function') {
            processQRCoderFile(file);
          }
        }, 300);
      } catch (e) {
        console.error("ファイルの自動ロードに失敗しました", e);
      }
    });
  }

  // タブやブラウザを閉じる際の未保存警告 (Fail-safe)
  window.addEventListener("beforeunload", (e) => {
    if (isDirty || (window.$app && window.$app.hasUnsavedEdit)) {
      e.preventDefault();
      e.returnValue = "";
    }
  });
});

// QRコードジェネレーターの全機能を管理するAlpine.jsコンポーネント
function qrCodeGenerator() {
  // QRコードの初期デザイン設定
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
    margin: 4,
    imageOptions: {
      hideBackgroundDots: true,
      imageSize: 0.4, // 初期値は少し大きめに
      margin: 10, // 初期値は少し広めに
      crossOrigin: "anonymous",
    },
  };

  // 各QRコードタイプの初期データ構造
  const defaultFormData = {
    url: {
      address: "https://www.grinds.jp",
    },
    text: {
      content: "",
    },
    wifi: {
      ssid: "",
      password: "",
      encryption: "WPA/WPA2",
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
    },
    images: {
      url: "",
    },
    video: {
      url: "",
    },
  };

  return {
    // --- 画面の表示状態を管理する変数 ---
    subOpen: true, // サイドメニューの開閉状態
    currentView: "generator", // 'generator' (作成画面) or 'dashboard' (管理画面)
    hasUnsavedEdit: false, // 編集中のフォーム未保存状態
    currentStep: "typeSelection", // 作成画面のステップ
    selectedType: "url", // 選択中のQRコードタイプ
    activeStepTab: "content", // 作成画面のタブ ('content', 'design', 'logo')
    showNotification: false, // お知らせの表示状態
    notificationMessage: "", // お知らせメッセージ
    showDownloadModal: false, // 各種モーダルの表示状態
    showSaveModal: false,
    showShareModal: false,
    showSceneModal: false,
    showPromptModal: false,
    promptMessage: "",
    promptInput: "",
    resolvePrompt: null,
    copied: false, // コピーボタンの状態
    notificationTimeout: null, // 通知のタイマー管理
    includeQuietZone: true, // 余白(クワイエットゾーン)の有無
    editingQRCodeId: null, // 編集中のQRコードID
    saveName: "", // 保存時のQRコード名
    qrToShare: {}, // 共有モーダルで使うデータ

    // --- QRコードやアプリケーションのデータを管理する変数 ---
    qrCodeInstance: null, // QRコード生成ライブラリのインスタンス
    logoFileName: "", // アップロードしたロゴのファイル名
    qrQuality: {
      score: 100,
      issues: [],
    }, // QRコード品質スコア
    urlError: "", // URL入力時のエラーメッセージ
    isUrlLong: false, // URLが長いかどうかの判定
    brandKit: {
      logo: null,
      colors: ["#000000", "#ffffff"],
    }, // ブランドキットの設定
    history: [], // 操作履歴（元に戻す/やり直し用）
    historyIndex: -1,
    savedQRCodes: [], // 保存されたQRコードのリスト

    // --- 管理画面のページネーションとソート関連 ---
    sortKey: "createdAt",
    sortOrder: "desc",
    itemsPerPage: 5,
    currentPage: 1,

    // --- アプリケーション内で使用する固定データ ---
    presetLogos: ["ICON_EMAIL.png", "ICON_FACEBOOK.png", "ICON_INSTAGRAM.png", "ICON_TIKTOK.png", "ICON_X.png", "ICON_ZOOM.png"],
    qrTypes: [
      {
        id: "url",
        title: "ウェブサイトURL",
        description: "任意のウェブサイトにリンクします。",
        icon: "link",
      },
      {
        id: "text",
        title: "テキスト",
        description: "プレーンテキストを表示します。",
        icon: "bars-3-bottom-left",
      },
      {
        id: "wifi",
        title: "Wi-Fi",
        description: "ネットワークに接続します。",
        icon: "wifi",
      },
      {
        id: "vcard",
        title: "連絡先 (vCard)",
        description: "連絡先情報を共有します。",
        icon: "user-circle",
      },
      {
        id: "event",
        title: "カレンダー",
        description: "イベントを共有します。",
        icon: "calendar-days",
      },
      {
        id: "email",
        title: "Eメール",
        description: "メール作成を促します。",
        icon: "envelope",
      },
      {
        id: "geo",
        title: "位置情報",
        description: "特定の場所を共有します。",
        icon: "map-pin",
      },
      {
        id: "sns",
        title: "SNS",
        description: "SNSプロフィールを共有します。",
        icon: "share",
      },
      {
        id: "images",
        title: "画像ギャラリー",
        description: "複数の画像をアップロードして専用ページを作成します。",
        icon: "photo",
      },
      {
        id: "video",
        title: "ビデオ",
        description: "動画をアップロード、またはURLを指定して共有します。",
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
      transparentBg: false,
    },
    frameStyles: [
      {
        id: "scan-me-1",
        name: "テキスト",
        preview: "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTgwIiBoZWlnaHQ9IjIwMCIgdmlld0JveD0iMCAwIDE4MCAyMDAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHJlY3Qgd2lkdGg9IjE4MCIgaGVpZ2h0PSIxODAiIGZpbGw9IiNmMmY0ZjkiLz48dGV4dCB4PSI5MCIgeT0iMTkwIiBkb21pbmFudC1iYXNlbGluZT0iY2VudHJhbCIgZm9udC1mYW1pbHk9InNhbnMtc2VyaWYiIGZvbnQtc2l6ZT0iMTYiIGZvbnQtd2VpZ2h0PSJib2xkIiBmaWxsPSIjMWUyOTNiIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5DVEFURVhUPC90ZXh0Pjwvc3ZnPg==",
      },
      {
        id: "scan-me-2",
        name: "ボックス",
        preview: "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTgwIiBoZWlnaHQ9IjIyMCIgdmlld0JveD0iMCAwIDE4MCAyMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHJlY3Qgd2lkdGg9IjE4MCIgaGVpZ2h0PSIxODAiIGZpbGw9IiNmMmY0ZjkiLz48cmVjdCB4PSIzMCIgeT0iMTgwIiB3aWR0aD0iMTIwIiBoZWlnaHQ9IjMwIiByeD0iOCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMWUyOTNiIiBzdHJva2Utd2lkdGg9IjIiLz48dGV4dCB4PSI5MCIgeT0iMTk1IiBkb21pbmFudC1iYXNlbGluZT0iY2VudHJhbCIgZm9udC1mYW1pbHk9InNhbnMtc2VyaWYiIGZvbnQtc2l6ZT0iMTYiIGZvbnQtd2VpZ2h0PSJib2xkIiBmaWxsPSIjMWUyOTNiIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIj5DVEFURVhUPC90ZXh0Pjwvc3ZnPg==",
      },
      {
        id: "scan-me-3",
        name: "背景付き",
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
    backupSceneState: {},
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
        backgroundUrl: `data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' width='400' height='400' viewBox='0 0 400 400'%3e%3crect width='380' height='380' x='10' y='10' fill='%23f1f5f9' stroke='%239ca3af' stroke-width='2' stroke-dasharray='8 8' rx='15'/%3e%3ctext x='50%25' y='50%25' dominant-baseline='middle' text-anchor='middle' font-family='sans-serif' font-size='20px' fill='%2364748b'%3eここに写真をアップロード%3c/text%3e%3c/svg%3e`,
      },
    },
    dotStyles: [
      {
        id: "square",
        name: "四角",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><rect width="100" height="100" fill="currentColor"/></svg>',
      },
      {
        id: "rounded",
        name: "角丸",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><rect width="100" height="100" rx="30" fill="currentColor"/></svg>',
      },
      {
        id: "dots",
        name: "ドット",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><circle cx="50" cy="50" r="50" fill="currentColor"/></svg>',
      },
      {
        id: "classy",
        name: "クラシック",
        svg: '<svg width="42" height="42" viewBox="0 0 100 100"><path d="M50 0A50 50 0 0 0 0 50A50 50 0 0 0 50 100A50 50 0 0 0 100 50A50 50 0 0 0 50 0M50 15A35 35 0 0 1 85 50A35 35 0 0 1 50 85A35 35 0 0 1 15 50A35 35 0 0 1 50 15" fill-rule="evenodd" fill="currentColor"/></svg>',
      },
      {
        id: "classy-rounded",
        name: "クラシック(丸)",
        svg: '<svg width="42" height="42" viewBox="0 0 100 100"><path d="M50 0A50 50 0 0 0 0 50A50 50 0 0 0 50 100A50 50 0 0 0 100 50A50 50 0 0 0 50 0M50 25A25 25 0 0 1 75 50A25 25 0 0 1 50 75A25 25 0 0 1 25 50A25 25 0 0 1 50 25" fill-rule="evenodd" fill="currentColor"/></svg>',
      },
      {
        id: "extra-rounded",
        name: "丸",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><rect width="100" height="100" rx="50" fill="currentColor"/></svg>',
      },
    ],
    cornerStyles: [
      {
        id: "square",
        name: "四角",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><rect width="90" height="90" x="5" y="5" stroke-width="10" stroke="currentColor" fill="none"/></svg>',
      },
      {
        id: "dot",
        name: "ドット",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><rect width="90" height="90" x="5" y="5" stroke-width="10" stroke="currentColor" fill="none" rx="45"/></svg>',
      },
      {
        id: "extra-rounded",
        name: "丸",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><rect width="90" height="90" x="5" y="5" stroke-width="10" stroke="currentColor" fill="none" rx="25"/></svg>',
      },
    ],
    cornerDotStyles: [
      {
        id: "square",
        name: "四角",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><rect width="50" height="50" x="25" y="25" fill="currentColor"/></svg>',
      },
      {
        id: "extra-rounded",
        name: "角丸",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><rect width="50" height="50" x="25" y="25" rx="15" fill="currentColor"/></svg>',
      },
      {
        id: "dot",
        name: "ドット",
        svg: '<svg width="32" height="32" viewBox="0 0 100 100"><circle cx="50" cy="50" r="25" fill="currentColor"/></svg>',
      },
    ],
    colorPalettes: [
      {
        name: "標準",
        fg: "#000000",
        bg: "#ffffff",
      },
      {
        name: "スレート",
        fg: "#475569",
        bg: "#ffffff",
      },
      {
        name: "ダーク",
        fg: "#ffffff",
        bg: "#1e293b",
      },
      {
        name: "インディゴ",
        fg: "#3c366b",
        bg: "#f5f3ff",
      },
      {
        name: "ローズ",
        fg: "#9f1239",
        bg: "#fff1f2",
      },
      {
        name: "グリーン",
        fg: "#065f46",
        bg: "#ecfdf5",
      },
    ],
    presetTemplates: [],

    // --- Computed Properties (算出プロパティ) ---
    // 表示するアイテムをソート・ページネーションして計算
    get displayedItems() {
      if (!this.savedQRCodes) return [];
      const sorted = [...this.savedQRCodes].sort((a, b) => {
        const valA = a[this.sortKey];
        const valB = b[this.sortKey];
        let comparison = 0;
        if (valA > valB) {
          comparison = 1;
        } else if (valA < valB) {
          comparison = -1;
        }
        return this.sortOrder === "asc" ? comparison : -comparison;
      });
      const start = (this.currentPage - 1) * this.itemsPerPage;
      const end = start + this.itemsPerPage;
      return sorted.slice(start, end);
    },
    // 全ページ数を計算
    get totalPages() {
      return Math.ceil(this.savedQRCodes.length / this.itemsPerPage);
    },
    // ページネーションに表示するページ番号の配列を計算
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

    // --- 初期化と主要な関数 ---
    // ページ読み込み時に実行される初期化処理
    async init() {
      window.$app = this;

      // Web Share Target API または URLパラメータからの受信処理
      const params = new URLSearchParams(window.location.search);
      const sharedUrl = params.get('url') || params.get('text');
      if (sharedUrl) {
        if (/^https?:\/\//i.test(sharedUrl.trim())) {
          this.selectedType = 'url';
          this.formData.url.address = sharedUrl.trim();
        } else {
          this.selectedType = 'text';
          this.formData.text.content = sharedUrl.trim();
        }
        window.history.replaceState({}, document.title, window.location.pathname);
      }

      this.$watch('showSaveModal', val => { document.body.style.overflow = val ? 'hidden' : ''; });
      this.$watch('showShareModal', val => { document.body.style.overflow = val ? 'hidden' : ''; });
      this.$watch('showDownloadModal', val => { document.body.style.overflow = val ? 'hidden' : ''; });
      this.$watch('showSceneModal', val => { document.body.style.overflow = val ? 'hidden' : ''; });
      this.generatePresetTemplates();
      this.loadBrandKit();
      await this.loadSavedQRCodes();
      this.initQrCode();
      this.validateUrl();
      this.recordState();

      // History APIによるブラウザバック（スワイプバック）離脱の防止と制御
      window.addEventListener('popstate', (e) => {
        // モーダルが開いている場合は閉じる処理を優先
        if (this.showSaveModal || this.showShareModal || this.showDownloadModal || this.showSceneModal || this.showPromptModal) {
          this.showSaveModal = false;
          this.showShareModal = false;
          this.showDownloadModal = false;
          this.showSceneModal = false;
          this.showPromptModal = false;
          history.pushState(null, '', location.href); // 履歴を再度追加して離脱を防ぐ
          return;
        }

        // 画面遷移の戻る処理
        if (this.currentView === 'generator' && this.currentStep === 'contentEntry') {
          this.currentStep = 'typeSelection';
        } else if (this.currentView === 'dashboard') {
          this.currentView = 'generator';
          this.currentStep = 'typeSelection';
        }
      });

      this.$watch('currentStep', val => {
        if (val === 'contentEntry') history.pushState({ step: 'contentEntry' }, '', '');
      });
      this.$watch('currentView', val => {
        if (val === 'dashboard') history.pushState({ view: 'dashboard' }, '', '');
      });

      // 初回生成の完了後に未保存フラグをリセットする
      this.$nextTick(() => {
        setTimeout(() => {
          if (typeof setDirty === 'function') setDirty(false);
        }, 100);
      });
    },

    // QRコードのインスタンスを生成し、プレビューに表示
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
        this.checkQrQuality();
      });
    },

    normalizeColors() {
      const fixColor = (color) => {
        if (!color) return "#000000";
        return /^[0-9A-F]{3,6}$/i.test(color) ? '#' + color : color;
      };
      this.qrOptions.foregroundColor = fixColor(this.qrOptions.foregroundColor);
      this.qrOptions.backgroundColor = fixColor(this.qrOptions.backgroundColor);
      this.qrOptions.cornerColor = fixColor(this.qrOptions.cornerColor);
      this.qrOptions.cornerDotColor = fixColor(this.qrOptions.cornerDotColor);
      if (this.qrOptions.gradient) {
        this.qrOptions.gradient.color1 = fixColor(this.qrOptions.gradient.color1);
        this.qrOptions.gradient.color2 = fixColor(this.qrOptions.gradient.color2);
      }
    },

    // 設定が変更されたときにQRコードのプレビューを更新
    updateQrCode(recordHistory = true) {
      if (!this.qrCodeInstance) return;

      this.hasUnsavedEdit = true;

      this.normalizeColors();
      this.checkQrQuality();

      // 【重要】Alpine.jsの監視データ(Proxy)を解除して、純粋なデータに変換します
      // これにより「設定が変わったこと」をライブラリに強制的に認識させます
      const plainOptions = JSON.parse(JSON.stringify(this.qrOptions));

      // ライブラリに渡す設定オブジェクトを作成
      const updateConfig = {
        data: this.getQrDataString(),

        // 画像データ
        image: plainOptions.logo,

        // 画像のサイズや余白の設定（ここが以前はうまく伝わっていませんでした）
        imageOptions: {
          hideBackgroundDots: plainOptions.imageOptions.hideBackgroundDots,
          imageSize: plainOptions.imageOptions.imageSize,
          margin: plainOptions.imageOptions.margin,
          crossOrigin: "anonymous",
        },

        // その他の設定
        dotsOptions: this.buildDotsOptions(),
        backgroundOptions: { color: plainOptions.backgroundColor },
        cornersSquareOptions: this.buildCornersSquareOptions(),
        cornersDotOptions: this.buildCornersDotOptions(),
        qrOptions: {
          errorCorrectionLevel: plainOptions.errorCorrectionLevel,
        },
        // 全体の余白
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
          message: "データ量がQRコードの限界を超えています。テキストを減らすか、動的QR（短縮URL）をご利用ください。"
        });
        return;
      }

      // フレームの再描画処理
      this.applyFrame();
      if (this.qrOptions.logo) {
        // 描画のタイミングズレを防ぐため、少し待ってから再度フレームを描画
        setTimeout(() => this.applyFrame(), 50);
      }

      if (recordHistory) this.recordState();
    },

    // --- ユーザー操作に応じた処理 ---
    // QRコードのタイプを選択したときの処理
    selectType(typeId) {
      this.selectedType = typeId;
      this.currentStep = "contentEntry";
      this.$nextTick(() => this.updateQrCode());
    },

    // ダッシュボードのリストをソート
    sortBy(key) {
      if (this.sortKey === key) {
        this.sortOrder = this.sortOrder === "asc" ? "desc" : "asc";
      } else {
        this.sortKey = key;
        this.sortOrder = "desc";
      }
      this.currentPage = 1;
    },

    // ページネーションでページを切り替え
    changePage(page) {
      if (page >= 1 && page <= this.totalPages) {
        this.currentPage = page;
      }
    },

    // デザインテンプレートを適用
    applyPreset(template) {
      this.qrOptions = JSON.parse(JSON.stringify(template.options));
      this.includeQuietZone = this.qrOptions.margin > 0;
      this.logoFileName = "";
      this.updateQrCode();
    },

    // --- ファイルアップロード関連 ---
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
      if (file.size > 2 * 1024 * 1024) {
        this.showFlashNotification("ロゴ画像は2MB以下のファイルを選択してください。");
        return;
      }
      this.logoFileName = file.name;
      const reader = new FileReader();
      reader.onload = (e) => {
        this.qrOptions.logo = e.target.result;
        if (["L", "M"].includes(this.qrOptions.errorCorrectionLevel)) {
          this.qrOptions.errorCorrectionLevel = "H";
          this.showFlashNotification("ロゴの読み取り精度を保つため、誤り訂正レベルを「最高」に設定しました。");
        }
        this.updateQrCode();
      };
      reader.readAsDataURL(file);
      event.target.value = "";
    },

    // --- 保存・ダウンロード処理 ---
    // 画像をクリップボードにコピー（全ブラウザ・Safari完全対応版）
    async copyImageToClipboard() {
      if (!this.qrCodeInstance) return;

      const visibleCanvas = this.showSceneModal ? this.$refs.modalQrCanvas : this.$refs.qrCodeCanvas;
      const svgElement = visibleCanvas.querySelector("svg");
      if (!svgElement) return;

      const svgClone = svgElement.cloneNode(true);
      svgClone.setAttribute("width", this.download.size);
      svgClone.setAttribute("height", this.download.size);

      if (this.download.transparentBg) {
        const bgRect = Array.from(svgClone.children).find(el => el.tagName.toLowerCase() === 'rect');
        if (bgRect) {
          bgRect.setAttribute("fill", "transparent");
          bgRect.style.fill = "transparent";
        }
      }

      if (!svgClone.hasAttribute("xmlns:xlink")) {
        svgClone.setAttribute("xmlns:xlink", "http://www.w3.org/1999/xlink");
      }
      const imageTags = svgClone.querySelectorAll("image");
      for (let img of imageTags) {
        const href = img.getAttribute("href") || img.getAttribute("xlink:href");
        if (href) img.setAttribute("xlink:href", href);
      }

      try {
        const finalSvgString = new XMLSerializer().serializeToString(svgClone);
        const blob = new Blob([finalSvgString], { type: "image/svg+xml;charset=utf-8" });
        const svgBlobUrl = URL.createObjectURL(blob);

        // Safari等の制約を回避するため、ClipboardItemにPromiseを直接渡す
        const clipboardItem = new window.ClipboardItem({
          "image/png": new Promise(async (resolve, reject) => {
            try {
              const image = new Image();
              await new Promise((res, rej) => {
                image.onload = res;
                image.onerror = rej;
                image.src = svgBlobUrl;
              });

              const canvas = document.createElement("canvas");
              const svgViewBox = svgElement.viewBox.baseVal;
              const aspectRatio = svgViewBox.height > 0 ? svgViewBox.width / svgViewBox.height : 1;
              canvas.width = this.download.size;
              canvas.height = this.download.size / Math.max(aspectRatio, 0.0001);

              const ctx = canvas.getContext("2d");
              ctx.drawImage(image, 0, 0, canvas.width, canvas.height);

              canvas.toBlob((pngBlob) => {
                if (pngBlob) resolve(pngBlob);
                else reject(new Error("Blob generation failed"));
                setTimeout(() => URL.revokeObjectURL(svgBlobUrl), 100);
              }, "image/png");
            } catch (e) {
              setTimeout(() => URL.revokeObjectURL(svgBlobUrl), 100);
              reject(e);
            }
          })
        });
        await navigator.clipboard.write([clipboardItem]);
        this.showFlashNotification("画像をクリップボードにコピーしました！");
      } catch (err) {
        console.error("コピーに失敗しました", err);
        this.showFlashNotification("このブラウザは画像のコピーに対応していません。");
      }
    },

    // QRコードをPNGまたはSVG形式でダウンロード
    async downloadQrCode() {
      if (!this.qrCodeInstance) return;

      const extension = this.download.format;
      const name = this.download.fileName || "grinds-qr-code";

      const visibleCanvas = this.showSceneModal ? this.$refs.modalQrCanvas : this.$refs.qrCodeCanvas;
      const svgElement = visibleCanvas.querySelector("svg");
      if (!svgElement) {
        console.error("Preview SVG element not found.");
        return;
      }

      const svgClone = svgElement.cloneNode(true);

      // Safari等のCanvas描画バグ（真っ白になる現象）を防ぐための絶対指定
      svgClone.setAttribute("width", this.download.size);
      svgClone.setAttribute("height", this.download.size);

      // 背景透過の処理: <svg> 直下にある一番最初の <rect> (背景要素) だけを透明にします。
      if (this.download.transparentBg) {
        const bgRect = Array.from(svgClone.children).find(el => el.tagName.toLowerCase() === 'rect');
        if (bgRect) {
          bgRect.setAttribute("fill", "transparent");
          bgRect.style.fill = "transparent";
        }
      }

      // Adobe Illustrator や Photoshop などのデザインソフト互換性対応
      if (!svgClone.hasAttribute("xmlns:xlink")) {
        svgClone.setAttribute("xmlns:xlink", "http://www.w3.org/1999/xlink");
      }
      const imageTags = svgClone.querySelectorAll("image");
      for (let img of imageTags) {
        const href = img.getAttribute("href") || img.getAttribute("xlink:href");
        if (href) img.setAttribute("xlink:href", href);
      }

      let svgBlobUrl = null;
      try {
        const finalSvgString = new XMLSerializer().serializeToString(svgClone);
        const blob = new Blob([finalSvgString], { type: "image/svg+xml;charset=utf-8" });
        svgBlobUrl = URL.createObjectURL(blob);

        if (extension === "svg") {
          const a = document.createElement("a");
          a.href = svgBlobUrl;
          a.download = `${name}.svg`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          this.showDownloadModal = false;
        } else if (extension === "png") {
          const image = new Image();

          await new Promise((resolve, reject) => {
            image.onload = resolve;
            image.onerror = reject;
            image.src = svgBlobUrl;
          });

          const canvas = document.createElement("canvas");
          const svgViewBox = svgElement.viewBox.baseVal;
          const aspectRatio = svgViewBox.height > 0 ? svgViewBox.width / svgViewBox.height : 1;

          canvas.width = this.download.size;
          canvas.height = this.download.size / Math.max(aspectRatio, 0.0001); // 0除算回避

          const ctx = canvas.getContext("2d");
          ctx.drawImage(image, 0, 0, canvas.width, canvas.height);

          const pngUrl = canvas.toDataURL("image/png");
          const a = document.createElement("a");
          a.href = pngUrl;
          a.download = `${name}.png`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          this.showDownloadModal = false;
        }
      } catch (err) {
        console.error("ダウンロードに失敗しました", err);
        this.showFlashNotification("画像の生成に失敗しました。");
      } finally {
        if (svgBlobUrl) setTimeout(() => URL.revokeObjectURL(svgBlobUrl), 100);
      }
    },

    // 作成したQRコードをブラウザのローカルストレージに保存
    async saveToGrind() {
      const originalQr = this.editingQRCodeId ? this.savedQRCodes.find((qr) => qr.id === this.editingQRCodeId) : null;
      const conflictingQr = this.savedQRCodes.find((qr) => qr.name.trim() === this.saveName.trim() && qr.id !== this.editingQRCodeId);

      if (conflictingQr) {
        const isConfirmed = window.confirm("同じ名前のQRコードが既に存在します。上書きしてよろしいですか？");
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
        imageOptions: this.qrOptions.imageOptions,
        margin: this.qrOptions.margin,
      };

      const newQr = {
        id: this.editingQRCodeId || this.generateUniqueId(),
        name: this.saveName,
        type: this.selectedType,
        formData: JSON.parse(JSON.stringify(this.formData)),
        qrOptions: JSON.parse(JSON.stringify(this.qrOptions)),
        logoFileName: this.logoFileName,
        frame: JSON.parse(JSON.stringify(this.frame)),
        createdAt: originalQr ? originalQr.createdAt : new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        scans: originalQr ? originalQr.scans : Math.floor(Math.random() * 100),
        previewSvgUrl: await this.getPreviewSvgUrl(previewOptions),
      };

      if (this.editingQRCodeId) {
        const index = this.savedQRCodes.findIndex((qr) => qr.id === this.editingQRCodeId);
        if (index !== -1) {
          this.savedQRCodes[index] = newQr;
        } else {
          this.savedQRCodes.unshift(newQr);
        }
        this.showFlashNotification("QRコードの設定を更新しました。");
      } else {
        this.savedQRCodes.unshift(newQr);
        this.showFlashNotification("QRコードを保存しました。");
      }

      await this.persistSavedQRCodes();

      if (typeof setDirty === 'function') setDirty(true);

      this.hasUnsavedEdit = false;
      this.showSaveModal = false;
      this.currentView = "dashboard";
      this.resetGenerator();
    },

    // --- 補助関数 ---
    // QRコードにエンコードするデータ文字列を生成
    getQrDataString() {
      let data = " ";
      switch (this.selectedType) {
        case "url":
          let urlStr = this.formData.url.address.trim();
          if (urlStr && !/^https?:\/\//i.test(urlStr)) {
            urlStr = "https://" + urlStr;
          }
          data = urlStr || " ";
          break;
        case "text":
          data = this.formData.text.content.trim() || " ";
          break;
        case "wifi":
          const { ssid, password, encryption } = this.formData.wifi;
          const escapeWifiStr = (str) => {
            if (!str) return "";
            return String(str).replace(/([\\;:,\"])/g, "\\$1");
          };
          if (ssid) {
            data = `WIFI:T:${encryption === "なし" ? "nopass" : encryption};S:${escapeWifiStr(ssid)};P:${escapeWifiStr(password)};;`;
          }
          break;
        case "vcard":
          const { firstName, lastName, organization, phone, email, address } = this.formData.vcard;
          const escapeVCard = (str) => {
            if (!str) return "";
            return String(str).replace(/([,;])/g, "\\$1");
          };

          if (firstName || lastName) {
            const vcardLines = [
              "BEGIN:VCARD",
              "VERSION:3.0",
              `N:${escapeVCard(lastName)};${escapeVCard(firstName)}`,
              `FN:${escapeVCard(lastName ? lastName + " " : "")}${escapeVCard(firstName)}`.trim()
            ];
            if (organization) vcardLines.push(`ORG:${escapeVCard(organization)}`);
            if (phone) vcardLines.push(`TEL:${escapeVCard(phone)}`);
            if (email) vcardLines.push(`EMAIL:${escapeVCard(email)}`);
            if (address) vcardLines.push(`ADR:${escapeVCard(address)}`);
            vcardLines.push("END:VCARD");
            data = vcardLines.join("\n");
          }
          break;
        case "event":
          const { summary, location, start, end, description } = this.formData.event;
          const formatDT = (dt) => (dt ? dt.replace(/[-:]/g, "") + "00" : "");
          if (summary && start && end) {
            data = `BEGIN:VEVENT\nSUMMARY:${summary}\nLOCATION:${location}\nDTSTART:${formatDT(start)}\nDTEND:${formatDT(end)}\nDESCRIPTION:${description}\nEND:VEVENT`;
          }
          break;
        case "email":
          const { to, subject, body } = this.formData.email;
          if (to) {
            data = `mailto:${to}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
          }
          break;
        case "geo":
          const { latitude, longitude } = this.formData.geo;
          if (latitude && longitude) {
            data = `geo:${latitude},${longitude}`;
          }
          break;
        case "sns":
          const { service, identifier } = this.formData.sns;
          if (identifier) {
            switch (service) {
              case "x":
                data = `https://twitter.com/${identifier}`;
                break;
              case "instagram":
                data = `https://www.instagram.com/${identifier}`;
                break;
              case "facebook":
                data = `https://www.facebook.com/${identifier}`;
                break;
              case "line":
                data = `https://line.me/R/ti/p/@${identifier}`;
                break;
              case "youtube":
                data = `https://www.youtube.com/channel/${identifier}`;
                break;
              case "tiktok":
                data = `https://www.tiktok.com/@${identifier}`;
                break;
            }
          }
          break;
        case "images":
          let imagesUrlStr = this.formData.images.url.trim();
          if (imagesUrlStr && !/^https?:\/\//i.test(imagesUrlStr)) {
            imagesUrlStr = "https://" + imagesUrlStr;
          }
          data = imagesUrlStr || " ";
          break;
        case "video":
          let videoUrlStr = this.formData.video.url.trim();
          if (videoUrlStr && !/^https?:\/\//i.test(videoUrlStr)) {
            videoUrlStr = "https://" + videoUrlStr;
          }
          data = videoUrlStr || " ";
          break;
        default:
          data = " ";
      }
      return data;
    },

    // QRコードの品質をチェックし、問題があれば警告を表示
    checkQrQuality() {
      this.qrQuality.issues = [];
      let score = 100;

      const fgColors = this.qrOptions.colorType === "single" ? [this.qrOptions.foregroundColor] : [this.qrOptions.gradient.color1, this.qrOptions.gradient.color2];
      const bgRgb = this.hexToRgb(this.qrOptions.backgroundColor);

      let minContrast = Infinity;
      let invalidColor = false;

      if (!bgRgb) {
        invalidColor = true;
      } else {
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

      if (invalidColor) {
        this.qrQuality.issues.push({
          status: "bad",
          message: "無効な色コードです。",
        });
        score -= 50;
      } else {
        if (minContrast < 3) {
          this.qrQuality.issues.push({
            status: "bad",
            message: `コントラスト比が低すぎ (${minContrast.toFixed(1)}:1)`,
          });
          score -= 50;
        } else if (minContrast < 4.5) {
          this.qrQuality.issues.push({
            status: "warning",
            message: `コントラスト比が低め (${minContrast.toFixed(1)}:1)`,
          });
          score -= 25;
        }
      }

      if (this.selectedType === "url" && this.isUrlLong) {
        this.qrQuality.issues.push({
          status: "warning",
          message: `URLが長くドットが細かいです`,
        });
        score -= 15;
      }

      if (!this.includeQuietZone) {
        this.qrQuality.issues.push({
          status: "warning",
          message: "外側の余白がありません。印刷時に注意が必要です。",
        });
        score -= 20;
      }

      // ロゴに関するチェック（サイズ・マージン）
      if (this.qrOptions.logo) {
        // 4-1. 誤り訂正レベルチェック
        if (this.qrOptions.errorCorrectionLevel !== "H") {
          this.qrQuality.issues.push({
            status: "warning",
            message: `ロゴ使用時は訂正レベル「最高」を推奨`,
            action: () => {
              this.qrOptions.errorCorrectionLevel = "H";
              this.updateQrCode();
            },
          });
          score -= 10;
        }

        // 4-2. ロゴ＋余白の合計サイズチェック
        // QRコードのベースサイズ(320px)に基づいて余白の比率を計算
        const baseQrSize = 320;
        // 余白は左右(または上下)に入るため2倍して計算
        const marginRatio = (this.qrOptions.imageOptions.margin * 2) / baseQrSize;
        // ロゴ倍率 + 余白倍率 = 実質的な欠損率
        const totalCoverageRatio = this.qrOptions.imageOptions.imageSize + marginRatio;

        if (totalCoverageRatio > 0.4) {
          this.qrQuality.issues.push({
            status: "warning",
            message: "ロゴと余白の合計範囲が大きすぎます。読み取りエラーの原因になります。",
            action: () => {
              // 改善アクション：サイズと余白の両方を少し小さくする
              this.qrOptions.imageOptions.imageSize = Math.max(0.2, this.qrOptions.imageOptions.imageSize - 0.1);
              this.qrOptions.imageOptions.margin = Math.max(0, this.qrOptions.imageOptions.margin - 2);
              this.updateQrCode();
            },
          });
          score -= 20; // 深刻な問題なので減点を少し増やす
        }

        // 4-3. ロゴのマージンチェック
        if (this.qrOptions.imageOptions.margin < 2) {
          this.qrQuality.issues.push({
            status: "warning",
            message: "ロゴの余白が狭すぎます。ドットと同化する恐れがあります。",
            action: () => {
              this.qrOptions.imageOptions.margin = 4;
              this.updateQrCode();
            },
          });
          score -= 10;
        } else if (this.qrOptions.imageOptions.margin > 18) {
          this.qrQuality.issues.push({
            status: "warning",
            message: "ロゴの余白が広すぎます。データが欠損する恐れがあります。",
          });
          score -= 10;
        }
      }

      this.qrQuality.score = Math.max(0, score);
    },

    // 操作履歴を記録（元に戻す機能のため）
    recordState() {
      if (this.historyIndex < this.history.length - 1) {
        this.history = this.history.slice(0, this.historyIndex + 1);
      }

      // メモリ消費とカクつきを防ぐため、巨大なBase64(logo)はシリアライズから除外して参照でコピー
      const logoBackup = this.qrOptions.logo;
      this.qrOptions.logo = "";

      const currentState = {
        qrOptions: JSON.parse(JSON.stringify(this.qrOptions)),
        frame: JSON.parse(JSON.stringify(this.frame)),
        formData: JSON.parse(JSON.stringify(this.formData)),
      };
      currentState.qrOptions.logo = logoBackup;
      this.qrOptions.logo = logoBackup; // 元に戻す

      this.history.push(currentState);
      if (this.history.length > 30) {
        this.history.shift();
      } else {
        this.historyIndex++;
      }
    },

    // 操作を一つ元に戻す
    undo() {
      if (this.historyIndex > 0) {
        this.historyIndex--;
        this.applyState(this.history[this.historyIndex]);
      }
    },

    // 元に戻した操作をやり直す
    redo() {
      if (this.historyIndex < this.history.length - 1) {
        this.historyIndex++;
        this.applyState(this.history[this.historyIndex]);
      }
    },

    // その他の補助的な関数...
    applyState(state) {
      this.qrOptions = JSON.parse(JSON.stringify(state.qrOptions));
      this.frame = JSON.parse(JSON.stringify(state.frame));
      if (state.formData) this.formData = JSON.parse(JSON.stringify(state.formData));
      this.includeQuietZone = this.qrOptions.margin > 0;
      this.updateQrCode(false);
    },
    generatePresetTemplates() {
      // 基本のテンプレート群
      this.presetTemplates = [
        {
          name: "シンプル",
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><rect x="10" y="10" width="80" height="80" rx="8" fill="#000"/></svg>`,
          options: { ...defaultQrOptions, colorType: "single", foregroundColor: "#000000", backgroundColor: "#ffffff", dotsStyle: "rounded", cornersStyle: "extra-rounded", cornerColor: "#000000", cornerDotColor: "#000000" },
        },
        {
          name: "モダン",
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><circle cx="50" cy="50" r="40" fill="#4338CA"/></svg>`,
          options: { ...defaultQrOptions, colorType: "single", foregroundColor: "#4338CA", cornerColor: "#4338CA", cornerDotColor: "#4338CA", backgroundColor: "#ffffff", dotsStyle: "dots", cornersStyle: "dot", cornersDotStyle: "dot" },
        },
        {
          name: "エレガント",
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#F1F5F9"/><path d="M50 10 A 40 40 0 0 1 90 50 A 40 40 0 0 1 50 90 A 40 40 0 0 1 10 50 A 40 40 0 0 1 50 10 M50 25 A 25 25 0 0 0 25 50 A 25 25 0 0 0 50 75 A 25 25 0 0 0 75 50 A 25 25 0 0 0 50 25" fill="#1F2937"/></svg>`,
          options: { ...defaultQrOptions, colorType: "single", foregroundColor: "#1F2937", cornerColor: "#1F2937", cornerDotColor: "#1F2937", backgroundColor: "#F1F5F9", dotsStyle: "classy", cornersStyle: "square" },
        },
        {
          name: "ダーク",
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#1e293b"/><rect x="10" y="10" width="80" height="80" rx="8" fill="#E2E8F0"/></svg>`,
          options: { ...defaultQrOptions, colorType: "single", foregroundColor: "#E2E8F0", cornerColor: "#E2E8F0", cornerDotColor: "#E2E8F0", backgroundColor: "#1e293b", dotsStyle: "rounded", cornersStyle: "extra-rounded" },
        },
        {
          name: "ポップ",
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#FCE7F3"/><circle cx="50" cy="50" r="40" fill="#DB2777"/></svg>`,
          options: { ...defaultQrOptions, colorType: "single", foregroundColor: "#DB2777", cornerColor: "#DB2777", cornerDotColor: "#DB2777", backgroundColor: "#FCE7F3", dotsStyle: "extra-rounded", cornersStyle: "dot", cornersDotStyle: "dot" },
        },
        {
          name: "オーガニック",
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#F0FDF4"/><rect x="15" y="15" width="70" height="70" rx="35" fill="#15803D"/></svg>`,
          options: { ...defaultQrOptions, colorType: "single", foregroundColor: "#15803D", cornerColor: "#15803D", cornerDotColor: "#15803D", backgroundColor: "#F0FDF4", dotsStyle: "rounded", cornersStyle: "dot", cornersDotStyle: "dot" },
        },
        {
          name: "テクノ",
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
            cornersDotStyle: "square",
          },
        },
        {
          name: "ラグジュアリー",
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
            cornersDotStyle: "dot",
          },
        },
      ];

      // 1. 吹き出しアイコン (Speech Bubble)
      const lineIconSvg = `<svg viewBox="0 0 320 320" xmlns="http://www.w3.org/2000/svg"><circle cx="160" cy="160" fill="#4cc764" r="160"/><path d="m266.7 150.68c0-47.8-47.92-86.68-106.81-86.68s-106.81 38.89-106.81 86.68c0 42.85 38 78.73 89.33 85.52 3.48.75 8.21 2.29 9.41 5.27 1.08 2.7.7 6.93.35 9.66 0 0-1.25 7.54-1.52 9.14-.47 2.7-2.15 10.56 9.25 5.76s61.51-36.22 83.92-62.01c15.48-16.98 22.9-34.2 22.9-53.33z" fill="#fff"/><g fill="#4cc764"><path d="m231.17 178.28c1.13 0 2.04-.91 2.04-2.04v-7.58c0-1.12-.92-2.04-2.04-2.04h-20.39v-7.87h20.39c1.13 0 2.04-.91 2.04-2.04v-7.57c0-1.12-.92-2.04-2.04-2.04h-20.39v-7.87h20.39c1.13 0 2.04-.91 2.04-2.04v-7.57c0-1.12-.92-2.04-2.04-2.04h-30.01c-1.13 0-2.04.91-2.04 2.04v.04 46.54.04c0 1.13.91 2.04 2.04 2.04z"/><path d="m120.17 178.28c1.13 0 2.04-.91 2.04-2.04v-7.58c0-1.12-.92-2.04-2.04-2.04h-20.39v-37c0-1.12-.92-2.04-2.04-2.04h-7.58c-1.13 0-2.04.91-2.04 2.04v46.58.04c0 1.13.91 2.04 2.04 2.04z"/><rect height="50.69" rx="2.04" width="11.65" x="128.62" y="127.58"/><path d="m189.8 127.58h-7.58c-1.13 0-2.04.91-2.04 2.04v27.69l-21.33-28.8c-.05-.07-.11-.14-.16-.21 0 0 0 0-.01-.01-.04-.04-.08-.09-.12-.13-.01-.01-.03-.02-.04-.03-.04-.03-.07-.06-.11-.09-.02-.01-.04-.03-.06-.04-.03-.03-.07-.05-.11-.07-.02-.01-.04-.03-.06-.04-.04-.02-.07-.04-.11-.06-.02-.01-.04-.02-.06-.03-.04-.02-.08-.04-.12-.05-.02 0-.04-.02-.07-.02-.04-.01-.08-.03-.12-.04-.02 0-.05-.01-.07-.02-.04 0-.08-.02-.12-.03-.03 0-.06 0-.09-.01-.04 0-.07-.01-.11-.01s-.07 0-.11 0c-.02 0-.05 0-.07 0h-7.53c-1.13 0-2.04.91-2.04 2.04v46.62c0 1.13.91 2.04 2.04 2.04h7.58c1.13 0 2.04-.91 2.04-2.04v-27.68l21.35 28.84c.15.21.33.38.53.51 0 0 .02.01.02.02.04.03.08.05.13.08.02.01.04.02.06.03.03.02.07.03.1.05s.07.03.1.04c.02 0 .04.02.06.02.05.02.09.03.14.04h.03c.17.04.35.07.53.07h7.53c1.13 0 2.04-.91 2.04-2.04v-46.62c0-1.13-.91-2.04-2.04-2.04z"/></g></svg>`;

      // 2. 文字ロゴ (Text Logo)
      const lineTextSvg = `<svg viewBox="0 0 145.09 50.69" xmlns="http://www.w3.org/2000/svg"><g fill="#4cc764"><path d="m143.05 50.69c1.13 0 2.04-.91 2.04-2.04v-7.58c0-1.12-.92-2.04-2.04-2.04h-20.39v-7.87h20.39c1.13 0 2.04-.91 2.04-2.04v-7.57c0-1.12-.92-2.04-2.04-2.04h-20.39v-7.87h20.39c1.13 0 2.04-.91 2.04-2.04v-7.56c0-1.12-.92-2.04-2.04-2.04h-30.01c-1.13 0-2.04.91-2.04 2.04v.04 46.54.04c0 1.13.91 2.04 2.04 2.04h30.01z"/><path d="m32.05 50.69c1.13 0 2.04-.91 2.04-2.04v-7.58c0-1.12-.92-2.04-2.04-2.04h-20.4v-36.99c0-1.12-.91-2.04-2.04-2.04h-7.57c-1.13 0-2.04.91-2.04 2.04v46.58.04c0 1.13.91 2.04 2.04 2.04h30.01z"/><rect height="50.69" rx="2.04" width="11.65" x="40.5"/><path d="m101.68 0h-7.58c-1.13 0-2.04.91-2.04 2.04v27.69l-21.32-28.81c-.05-.07-.11-.14-.16-.21 0 0 0 0-.01-.01-.04-.04-.08-.09-.12-.13-.01-.01-.03-.02-.04-.03-.04-.03-.07-.06-.11-.09-.02-.01-.04-.03-.06-.04-.03-.03-.07-.05-.11-.07-.02-.01-.04-.03-.06-.04-.04-.02-.07-.04-.11-.06-.02-.01-.04-.02-.06-.03-.04-.02-.08-.04-.12-.05-.02 0-.04-.02-.07-.02-.04-.01-.08-.03-.12-.04-.02 0-.05-.01-.07-.02-.04 0-.08-.02-.12-.03-.03 0-.06 0-.09-.01-.04 0-.07-.01-.11-.01s-.07 0-.11 0c-.02 0-.05 0-.07 0h-7.53c-1.13 0-2.04.91-2.04 2.04v46.62c0 1.13.91 2.04 2.04 2.04h7.58c1.13 0 2.04-.91 2.04-2.04v-27.68l21.35 28.84c.15.21.33.38.53.51 0 0 .02.01.02.02.04.03.08.05.13.08l.06.03c.03.02.07.03.1.05s.07.03.1.04c.02 0 .04.02.06.02.05.02.09.03.14.04h.03c.17.04.35.07.53.07h7.53c1.13 0 2.04-.91 2.04-2.04v-46.63c0-1.13-.91-2.04-2.04-2.04z"/></g></svg>`;

      // Data URLの生成
      const iconGreenUrl = `data:image/svg+xml;base64,${btoa(lineIconSvg)}`;
      const iconBlackUrl = `data:image/svg+xml;base64,${btoa(lineIconSvg.replace(/#4cc764/g, "#000000"))}`;
      const textGreenUrl = `data:image/svg+xml;base64,${btoa(lineTextSvg)}`;
      const textBlackUrl = `data:image/svg+xml;base64,${btoa(lineTextSvg.replace(/#4cc764/g, "#000000"))}`;

      // LINE テンプレート定義
      const lineTemplates = [
        // 1. アイコン・緑
        {
          name: "LINE(緑)",
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#4cc764"/></g><svg x="35" y="35" width="30" height="30" viewBox="0 0 320 320">${lineIconSvg}</svg></svg>`,
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
            imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 4, crossOrigin: "anonymous" },
          },
        },
        // 2. アイコン・黒
        {
          name: "LINE(黒)",
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#000"/></g><svg x="35" y="35" width="30" height="30" viewBox="0 0 320 320">${lineIconSvg.replace(/#4cc764/g, "#000000")}</svg></svg>`,
          options: {
            ...defaultQrOptions,
            errorCorrectionLevel: "H",
            logo: iconBlackUrl,
            colorType: "single",
            foregroundColor: "#000000",
            backgroundColor: "#ffffff",
            dotsStyle: "dots",
            cornersStyle: "extra-rounded",
            cornerColor: "#000000",
            cornerDotColor: "#000000",
            cornersDotStyle: "extra-rounded",
            imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 4, crossOrigin: "anonymous" },
          },
        },
        // 3. 文字ロゴ・緑
        {
          name: "LINE文字(緑)",
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#4cc764"/></g><svg x="20" y="40" width="60" height="20" viewBox="0 0 145.09 50.69">${lineTextSvg}</svg></svg>`,
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
            // 文字ロゴは横長なので、サイズを少し大きめに設定
            imageOptions: { hideBackgroundDots: true, imageSize: 0.35, margin: 6, crossOrigin: "anonymous" },
          },
        },
        // 4. 文字ロゴ・黒
        {
          name: "LINE文字(黒)",
          preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#000"/></g><svg x="20" y="40" width="60" height="20" viewBox="0 0 145.09 50.69">${lineTextSvg.replace(/#4cc764/g, "#000000")}</svg></svg>`,
          options: {
            ...defaultQrOptions,
            errorCorrectionLevel: "H",
            logo: textBlackUrl,
            colorType: "single",
            foregroundColor: "#000000",
            backgroundColor: "#ffffff",
            dotsStyle: "dots",
            cornersStyle: "extra-rounded",
            cornerColor: "#000000",
            cornerDotColor: "#000000",
            cornersDotStyle: "extra-rounded",
            // 文字ロゴは横長なので、サイズを少し大きめに設定
            imageOptions: { hideBackgroundDots: true, imageSize: 0.35, margin: 6, crossOrigin: "anonymous" },
          },
        },
      ];

      this.presetTemplates.push(...lineTemplates);
    },
    getActiveType() {
      return this.qrTypes.find((t) => t.id === this.selectedType) || {};
    },
    showFlashNotification(message) {
      this.notificationMessage = message;
      this.showNotification = true;
      if (this.notificationTimeout) clearTimeout(this.notificationTimeout);
      this.notificationTimeout = setTimeout(() => (this.showNotification = false), 4000);
    },
    generateUniqueId() {
      return Date.now().toString(36) + Math.random().toString(36).substring(2, 11);
    },
    getSnsPlaceholder() {
      const placeholders = {
        x: "grinds_jp",
        instagram: "grinds_official",
        facebook: "GrindJapan",
        line: "grinds",
        youtube: "UCxxxxxxxxxxxxxxxxx_xx",
        tiktok: "grinds.official",
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
            rotation: this.qrOptions.gradient.rotation,
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
      const url = this.formData.url.address;
      this.isUrlLong = url.length > 80;
      if (url.trim() === "") {
        this.urlError = "URLは必須項目です。";
      } else {
        try {
          let fullUrl = url;
          if (!/^https?:\/\//i.test(fullUrl)) {
            fullUrl = "https://" + fullUrl;
          }
          new URL(fullUrl);
          this.urlError = "";
        } catch (_) {
          this.urlError = "有効なURL形式ではありません。";
        }
      }
      this.updateQrCode();
    },
    removeLogo() {
      this.qrOptions.logo = "";
      this.logoFileName = "";
      this.updateQrCode();
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

      // カラータイプの比較
      if (current.colorType !== tempOpts.colorType) return false;

      // 色の比較
      if (current.colorType === "single") {
        if (current.foregroundColor !== tempOpts.foregroundColor || current.backgroundColor !== tempOpts.backgroundColor) return false;
      } else {
        if (!current.gradient || !tempOpts.gradient) return false;
        if (current.gradient.color1 !== tempOpts.gradient.color1 || current.gradient.color2 !== tempOpts.gradient.color2) return false;
      }

      // ロゴの比較
      const currentLogo = current.logo || "";
      const tempLogo = tempOpts.logo || "";
      if (currentLogo !== tempLogo) return false;

      // 形状の比較
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
        if (this.frame.style === "none") return;
        const frameGroup = document.createElementNS("http://www.w3.org/2000/svg", "g");
        frameGroup.classList.add("qr-frame");
        const textColor = this.qrOptions.colorType === "single" ? this.qrOptions.foregroundColor : this.qrOptions.gradient.color1;
        let frameHeight, textY, fontSize;

        const textToMeasure = this.frame.text || "";
        const visualLen = Array.from(textToMeasure).reduce((acc, char) => acc + (char.match(/[^\x01-\x7E\xA1-\xDF]/) ? 2 : 1), 0);

        switch (this.frame.style) {
          case "scan-me-1": {
            frameHeight = 40;
            svgElement.setAttribute("viewBox", `0 0 ${originalSize} ${originalSize + frameHeight}`);
            textY = originalSize + frameHeight / 2;
            fontSize = 24;
            const text1 = document.createElementNS("http://www.w3.org/2000/svg", "text");
            Object.assign(text1.style, {
              textAnchor: "middle",
              dominantBaseline: "central",
              fontFamily: "sans-serif",
              fontWeight: "bold",
            });
            text1.setAttribute("x", "50%");
            text1.setAttribute("y", textY);
            text1.setAttribute("font-size", `${fontSize}px`);
            text1.setAttribute("fill", textColor);
            text1.textContent = this.frame.text;
            frameGroup.appendChild(text1);
            break;
          }
          case "scan-me-2": {
            frameHeight = 50;
            svgElement.setAttribute("viewBox", `0 0 ${originalSize} ${originalSize + frameHeight}`);
            textY = originalSize + frameHeight / 2;
            fontSize = 22;
            const textWidth = visualLen * (fontSize * 0.6) + 30;
            const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
            rect.setAttribute("x", (originalSize - textWidth) / 2);
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
              fontFamily: "sans-serif",
              fontWeight: "bold",
            });
            text2.setAttribute("x", "50%");
            text2.setAttribute("y", textY);
            text2.setAttribute("font-size", `${fontSize}px`);
            text2.setAttribute("fill", textColor);
            text2.textContent = this.frame.text;
            frameGroup.appendChild(text2);
            break;
          }
          case "scan-me-3": {
            frameHeight = 40;
            svgElement.setAttribute("viewBox", `0 0 ${originalSize} ${originalSize + frameHeight}`);
            textY = originalSize + frameHeight / 2;
            fontSize = 22;
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
              fontFamily: "sans-serif",
              fontWeight: "bold",
            });
            text3.setAttribute("x", "50%");
            text3.setAttribute("y", textY);
            text3.setAttribute("font-size", `${fontSize}px`);
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
      this.backupSceneState = {
        options: JSON.parse(JSON.stringify(this.mainSceneOptions)),
        backgroundUrl: this.mainSceneBackgroundUrl,
        scene: this.previewScene,
      };
      this.showSceneModal = true;
      this.$nextTick(() => {
        this.$refs.modalQrCanvas.innerHTML = "";
        this.qrCodeInstance.append(this.$refs.modalQrCanvas);
        this.applyFrame();
      });
    },
    applySceneSettings() {
      this.backupSceneState = {};
      this.showSceneModal = false;
      this.$nextTick(() => {
        this.$refs.qrCodeCanvas.innerHTML = "";
        this.qrCodeInstance.append(this.$refs.qrCodeCanvas);
        this.applyFrame();
      });
    },
    cancelSceneSettings() {
      if (this.backupSceneState.options) {
        this.mainSceneOptions = this.backupSceneState.options;
        this.mainSceneBackgroundUrl = this.backupSceneState.backgroundUrl;
        this.previewScene = this.backupSceneState.scene;
      }
      this.backupSceneState = {};
      this.showSceneModal = false;
      this.$nextTick(() => {
        this.$refs.qrCodeCanvas.innerHTML = "";
        this.qrCodeInstance.append(this.$refs.qrCodeCanvas);
        this.applyFrame();
      });
    },
    loadScenePreset(presetName) {
      if (!this.scenePresets[presetName]) return;
      this.previewScene = presetName;
      const preset = this.scenePresets[presetName];
      this.mainSceneOptions.scale = preset.scale;
      this.mainSceneOptions.x = preset.x;
      this.mainSceneOptions.y = preset.y;
      this.mainSceneOptions.rotation = preset.rotation;
      this.mainSceneBackgroundUrl = preset.backgroundUrl;
    },
    resetSceneOptions() {
      this.mainSceneOptions = {
        scale: 0.7,
        x: 0,
        y: 0,
        rotation: 0,
      };
      this.previewScene = "custom";
    },
    handleSceneBackgroundUpload(event) {
      const file = event.target.files[0];
      if (file) {
        if (file.size > 5 * 1024 * 1024) {
          this.showFlashNotification("背景画像は5MB以下のファイルを選択してください。");
          return;
        }
        // 古い Blob URL が存在する場合はメモリリークを防ぐため解放する
        if (this.mainSceneBackgroundUrl && this.mainSceneBackgroundUrl.startsWith('blob:')) {
          URL.revokeObjectURL(this.mainSceneBackgroundUrl);
        }
        const newUrl = URL.createObjectURL(file);
        this.mainSceneBackgroundUrl = newUrl;
        this.scenePresets.custom.backgroundUrl = newUrl;
        this.previewScene = "custom";
      }
      event.target.value = null;
    },
    resetQrOptions() {
      this.qrOptions = JSON.parse(JSON.stringify(defaultQrOptions));
      this.includeQuietZone = true;
      this.frame = {
        style: "none",
        text: "SCAN ME",
      };
      this.logoFileName = "";
      this.updateQrCode();
    },
    async getPreviewSvgUrl(options) {
      const previewInstance = new QRCodeStyling(options);
      const blob = await previewInstance.getRawData("svg");
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onloadend = () => resolve(reader.result);
        reader.onerror = reject;
        reader.readAsDataURL(blob);
      });
    },
    resetGenerator() {
      this.editingQRCodeId = null;
      this.saveName = "";
      this.selectedType = "url";
      this.formData = JSON.parse(JSON.stringify(defaultFormData));
      this.resetQrOptions();
      this.currentStep = "typeSelection";
      this.hasUnsavedEdit = false;
    },
    openIdb() {
      return new Promise((resolve, reject) => {
        const request = indexedDB.open('GrindsQRCoderDB_Standalone', 2);
        request.onupgradeneeded = (e) => {
          const db = e.target.result;
          if (!db.objectStoreNames.contains('qrcodes')) {
            db.createObjectStore('qrcodes');
          }
          if (!db.objectStoreNames.contains('qrcodes_v2')) {
            db.createObjectStore('qrcodes_v2', { keyPath: 'id' });
          }
        };
        request.onsuccess = (e) => resolve(e.target.result);
        request.onerror = (e) => reject(e.target.error);
      });
    },
    async persistSavedQRCodes() {
      try {
        const db = await this.openIdb();
        return new Promise((resolve, reject) => {
          const tx = db.transaction('qrcodes_v2', 'readwrite');
          const store = tx.objectStore('qrcodes_v2');
          store.clear().onsuccess = () => {
            let count = 0;
            if (this.savedQRCodes.length === 0) {
              resolve();
              return;
            }
            this.savedQRCodes.forEach(qr => {
              const req = store.put(JSON.parse(JSON.stringify(qr)));
              req.onsuccess = () => {
                count++;
                if (count === this.savedQRCodes.length) resolve();
              };
              req.onerror = () => reject(req.error);
            });
          };
        });
      } catch(e) {
        console.error("Failed to save to IndexedDB", e);
        try { localStorage.setItem("grindsSavedQRCodes", JSON.stringify(this.savedQRCodes)); }
        catch(e2) { this.showFlashNotification("容量制限により保存できませんでした。"); }
      }
    },
    async loadSavedQRCodes() {
      try {
        const db = await this.openIdb();
        const saved = await new Promise((resolve, reject) => {
          let tx;
          try {
            tx = db.transaction(['qrcodes_v2', 'qrcodes'], 'readonly');
          } catch(err) {
            tx = db.transaction('qrcodes', 'readonly');
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

        if (saved && Array.isArray(saved) && saved.length > 0) {
          this.savedQRCodes = saved;
        } else if (typeof saved === 'string' && JSON.parse(saved).length > 0) {
          this.savedQRCodes = JSON.parse(saved);
        } else {
          try {
            const lsSaved = localStorage.getItem("grindsSavedQRCodes");
            if (lsSaved && JSON.parse(lsSaved).length > 0) {
              this.savedQRCodes = JSON.parse(lsSaved);
              await this.persistSavedQRCodes();
            } else { this.savedQRCodes = []; }
          } catch (e) {
            console.warn("localStorage のデータが破損しています", e);
            this.savedQRCodes = [];
          }
        }
      } catch(e) {
        try {
          const lsSaved = localStorage.getItem("grindsSavedQRCodes");
          this.savedQRCodes = (lsSaved && JSON.parse(lsSaved).length > 0) ? JSON.parse(lsSaved) : [];
        } catch(err) {
          this.savedQRCodes = [];
        }
      }
      this.currentView = this.savedQRCodes.length > 0 ? "dashboard" : "generator";
    },
    editQRCode(id) {
      const qrToEdit = this.savedQRCodes.find((qr) => qr.id === id);
      if (qrToEdit) {
        this.editingQRCodeId = id;
        this.saveName = qrToEdit.name;
        this.selectedType = qrToEdit.type;
        this.formData = JSON.parse(JSON.stringify(qrToEdit.formData));
        this.qrOptions = JSON.parse(JSON.stringify(qrToEdit.qrOptions));
        this.logoFileName = qrToEdit.logoFileName;
        this.frame = JSON.parse(JSON.stringify(qrToEdit.frame));
        this.currentView = "generator";
        this.currentStep = "contentEntry";
        this.activeStepTab = "content";
        this.$nextTick(() => {
          this.updateQrCode(false);
        });
      }
    },
    async deleteQRCode(id) {
      const isConfirmed = window.confirm("このQRコードを本当に削除しますか？\nこの操作は元に戻せません。");
      if (isConfirmed) {
        this.savedQRCodes = this.savedQRCodes.filter((qr) => qr.id !== id);
        await this.persistSavedQRCodes();
        if (typeof setDirty === 'function') setDirty(true);
        this.showFlashNotification("QRコードを削除しました。");
      }
    },
    async duplicateQRCode(id) {
      const originalQr = this.savedQRCodes.find((qr) => qr.id === id);
      if (originalQr) {
        const newQr = JSON.parse(JSON.stringify(originalQr));
        newQr.id = this.generateUniqueId();
        newQr.name = `${originalQr.name} (コピー)`;
        newQr.createdAt = new Date().toISOString();
        newQr.scans = 0;
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
          imageOptions: newQr.qrOptions.imageOptions,
          margin: newQr.qrOptions.margin,
        };
        newQr.previewSvgUrl = await this.getPreviewSvgUrl(thumbnailOptions);
        this.savedQRCodes.unshift(newQr);
        await this.persistSavedQRCodes();
        if (typeof setDirty === 'function') setDirty(true);
        this.showFlashNotification("QRコードを複製しました。");
      }
    },
    openShareModal(qr) {
      this.qrToShare = qr;
      this.showShareModal = true;
    },
    toggleQuietZone() {
      this.includeQuietZone = !this.includeQuietZone;
      this.qrOptions.margin = this.includeQuietZone ? 4 : 0;
      this.updateQrCode();
    },
    selectBrandLogo(logoUrl) {
      this.brandKit.logo = logoUrl;
      this.qrOptions.logo = logoUrl;
      this.logoFileName = "ブランドアイコン";
      this.updateQrCode();
      this.saveBrandKit();
    },
    removeBrandLogo() {
      this.brandKit.logo = null;
      this.qrOptions.logo = "";
      this.logoFileName = "";
      this.updateQrCode();
      this.saveBrandKit();
    },
    handleBrandLogoUpload(event) {
      const file = event.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (e) => {
        this.brandKit.logo = e.target.result;
        this.qrOptions.logo = e.target.result;
        this.logoFileName = file.name;
        this.updateQrCode();
        this.saveBrandKit();
      };
      reader.readAsDataURL(file);
      event.target.value = null;
    },
    saveBrandKit(showNotification = true) {
      localStorage.setItem("qrBrandKit", JSON.stringify(this.brandKit));
      if (showNotification) {
        this.showFlashNotification("ブランドキットを更新しました。");
      }
    },
    loadBrandKit() {
      const kit = localStorage.getItem("qrBrandKit");
      if (kit) {
        this.brandKit = JSON.parse(kit);
      }
    },
    applyBrandKit() {
      if (this.brandKit.logo) {
        this.qrOptions.logo = this.brandKit.logo;
        this.logoFileName = "ブランドロゴ";
      }
      this.qrOptions.colorType = "single";
      this.qrOptions.foregroundColor = this.brandKit.colors[0];
      this.qrOptions.cornerColor = this.brandKit.colors[0];
      this.qrOptions.cornerDotColor = this.brandKit.colors[0];
      this.qrOptions.backgroundColor = this.brandKit.colors[1];
      this.updateQrCode();
    },
    hexToRgb(hex) {
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
  };
}
