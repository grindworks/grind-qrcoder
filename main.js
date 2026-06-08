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
  const fileName = fileHandle && fileHandle.name ? fileHandle.name : "Unsaved.qrcoder";
  const filenameBadge = document.getElementById("current-filename");
  if (filenameBadge) {
    filenameBadge.textContent = fileName;
    filenameBadge.classList.remove("hidden");
  }
}

async function processQRCoderFile(file) {
  if (file.size > 20 * 1024 * 1024) {
    alert("ファイルサイズが大きすぎます。正しい .qrcoder ファイルを選択してください。");
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

    // データ消失を防ぐ安全装置（フェイルセーフ）
    if (component.savedQRCodes && component.savedQRCodes.length > 0) {
      const shouldMerge = window.confirm(
        "現在のダッシュボードにQRコードが保存されています。\n" +
        "読み込んだバックアップデータを、既存のリストに「追加 (マージ)」しますか？\n\n" +
        "[OK] = 既存のデータに追加する\n" +
        "[キャンセル] = 上書き、または読み込みを中止する"
      );

      if (!shouldMerge) {
        const shouldOverwrite = window.confirm(
          "⚠️ 警告: 現在のデータをすべて削除し、バックアップの内容で「上書き」しますか？\n\n" +
          "[OK] = 上書きする (現在のデータは完全に消えます)\n" +
          "[キャンセル] = 読み込みを中止する"
        );

        if (shouldOverwrite) {
          component.savedQRCodes = data;
        } else {
          return; // 何もしないで完全に中止する
        }
      } else {
        const existingIds = new Set(component.savedQRCodes.map(qr => qr.id));
        const mergedData = [...component.savedQRCodes];

        for (const newQr of data) {
          if (!existingIds.has(newQr.id)) {
            mergedData.push(newQr);
          } else {
            newQr.id = component.generateUniqueId();
            mergedData.push(newQr);
          }
        }
        component.savedQRCodes = mergedData;
      }
    } else {
      component.savedQRCodes = data;
    }

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
  const app = window.$app;
  if (app && app.hasUnsavedEdit) {
    if (!confirm("エディタに未保存の変更があります。破棄してファイルを読み込みますか？")) return;
  }
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
    if (err.name === 'AbortError') return; // キャンセル時は何もしない
    console.error(err);
    alert("ファイルの読み込みに失敗しました。ファイルが破損しているか形式が違います。");
  }
}

async function saveQRCoderFile() {
  const component = window.$app;

  // データ容量オーバー時は、ショートカットからの強行保存をブロック
  if (component && component.qrQuality.issues.some(i => i.id === 'capacity_error')) {
    component.showFlashNotification("データ量が限界を超えているため保存できません。");
    component.hapticFeedback('error');
    return;
  }

  // 未保存の編集データがある場合、自動的にダッシュボードへ保存を試みる
  if (component && component.hasUnsavedEdit) {
    if (component.editingQRCodeId) {
      // 既存のQRコードの編集なら、エディタ画面を維持したまま上書き保存
      await component.saveToGrind(true);
    } else {
      // 新規作成の場合は名前を付けさせるためモーダルを開き、ファイル保存は一旦中断
      component.showSaveModal = true;
      component.showFlashNotification("まずはダッシュボードへ保存するための名前を入力してください。");
      return;
    }
  }

  try {
    const dataString = JSON.stringify(window.Alpine.raw(component.savedQRCodes), null, 2);

    const encoder = new TextEncoder();
    let fileData = encoder.encode(dataString);
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
      fileData = await encryptData(fileData, pwInput.value);
    }

    if ("showSaveFilePicker" in window) {
      try {
        // まだ保存先ファイルが決まっていない場合のみ、保存先選択ダイアログを開く
        if (!fileHandle) {
          fileHandle = await window.showSaveFilePicker({
            suggestedName: "Data.qrcoder",
            types: [{ description: "QR Coder Database", accept: { "application/json": [".qrcoder"] } }]
          });
        }
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
      a.target = "_blank";
      a.rel = "noopener";
      a.href = url;
      a.download = fileHandle && fileHandle.name ? fileHandle.name : "Data.qrcoder";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      fileHandle = { name: a.download };
    }

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

    // UI構造を元に戻した後に、未保存バッジを確実に非表示にする
    setDirty(false);

    if (component && component.hapticFeedback) component.hapticFeedback('success');
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
  const content = document.getElementById("cmd-palette-content");
  const input = document.getElementById("cmd-input");
  if (!palette || !content) return;

  isCommandPaletteOpen = !isCommandPaletteOpen;

  const metaTheme = document.getElementById("meta-theme-color");
  if (metaTheme) metaTheme.setAttribute("content", isCommandPaletteOpen ? "#111827" : "#f8fafc");

  if (isCommandPaletteOpen) {
    palette.classList.remove("hidden");
    palette.classList.add("flex");
    input.value = "";
    selectedCommandIndex = 0;
    renderCommandList();

    input.focus();

    requestAnimationFrame(() => {
      palette.classList.remove("opacity-0");
      palette.classList.add("opacity-100");
      content.classList.remove("scale-95");
      content.classList.add("scale-100");
    });
  } else {
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
      }
    } else if (e.key === "Enter" && filtered[selectedCommandIndex]) {
      e.preventDefault();
      toggleCommandPalette();
      filtered[selectedCommandIndex].action();
      return;
    }
    return; // コマンドパレットが開いている時は他のショートカットは無視
  }

  // フォーム入力中でも実行したいグローバルショートカット (Cmd/Ctrl + S, O, K)
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
      toggleCommandPalette();
      return;
    }
  }

  // 入力フォームにフォーカスがある場合はその他の単一キーショートカットなどを無効化（Escapeは除く）
  if (isInputFocused && e.key !== "Escape") {
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
        fileHandle = fileHandleParams; // グローバルにセット (上書き保存を可能にするため)

        let attempts = 0;
        const maxAttempts = 50; // 最大5秒待機

        // アプリの初期化完了を安全に待つポーリング処理
        const checkAppReady = setInterval(() => {
          attempts++;

          if (window.$app && window.$app._isInitialized) {
            clearInterval(checkAppReady);
            if (typeof processQRCoderFile === 'function') {
              processQRCoderFile(file);
            }
          } else if (attempts > maxAttempts) {
            clearInterval(checkAppReady);
            console.error("アプリの初期化タイムアウトにより、ファイルの読み込みを中止しました。");
          }
        }, 100);
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
      imageSize: 0.3, // 初期値は少し大きめに
      margin: 6, // 初期値は少し広めに
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
    isUpdatingPreview: false, // プレビュー更新時の呼吸エフェクト用フラグ
    previewUpdateTimeout: null,
    editingQRCodeId: null, // 編集中のQRコードID
    saveName: "", // 保存時のQRコード名
    saveMemo: "", // 保存時のメモ
    saveTags: "", // 保存時のタグ（カンマ区切り文字列）
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
    searchQuery: "", // ダッシュボードの検索フィルタ用

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
        description: "Googleフォト等の共有アルバムリンクをQRコード化します。",
        icon: "photo",
      },
      {
        id: "video",
        title: "ビデオ",
        description: "YouTubeなどの動画共有リンクをQRコード化します。",
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
    presetTemplateGroups: [],

    // --- Computed Properties (算出プロパティ) ---
    // 検索クエリでフィルタリングされたリスト
    get filteredQRCodes() {
      if (!this.savedQRCodes) return [];
      let filtered = this.savedQRCodes;
      if (this.searchQuery.trim() !== "") {
        const query = this.searchQuery.toLowerCase().trim();
        filtered = filtered.filter(qr => {
          const nameMatch = qr.name && qr.name.toLowerCase().includes(query);
          const memoMatch = qr.memo && qr.memo.toLowerCase().includes(query);
          const tagsMatch = qr.tags && qr.tags.some(tag => tag.toLowerCase().includes(query));
          return nameMatch || memoMatch || tagsMatch;
        });
      }
      return filtered;
    },
    // 表示するアイテムをソート・ページネーションして計算
    get displayedItems() {
      const sorted = [...this.filteredQRCodes].sort((a, b) => {
        let valA = a[this.sortKey];
        let valB = b[this.sortKey];

        if (typeof valA === 'string') valA = valA.toLowerCase();
        if (typeof valB === 'string') valB = valB.toLowerCase();

        let comparison = 0;
        if (typeof valA === 'string' && typeof valB === 'string') {
          comparison = valA.localeCompare(valB, 'ja', { numeric: true });
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
    // 全ページ数を計算
    get totalPages() {
      return Math.max(1, Math.ceil(this.filteredQRCodes.length / this.itemsPerPage));
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

    // --- 触覚フィードバック ---
    hapticFeedback(type = 'light') {
      if (!navigator.vibrate) return;
      if (type === 'light') navigator.vibrate(10);
      if (type === 'success') navigator.vibrate([15, 50, 15]);
      if (type === 'error') navigator.vibrate([30, 50, 30, 50, 30]);
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

      this.generatePresetTemplates();
      this.loadBrandKit();
      await this.loadSavedQRCodes();

      // 共有データを受け取って起動した場合は、強制的に作成画面を開く
      if (sharedUrl) {
        this.currentView = 'generator';
        this.currentStep = 'contentEntry';
        this.$nextTick(() => { this.updateQrCode(false); });
      }

      this.initQrCode();
      this.validateUrl();

      // モーダル展開時のステータスバー動的暗転 (UX Polish)
      const metaTheme = document.getElementById("meta-theme-color");
      const updateThemeColor = (isOpen) => {
        if (metaTheme) metaTheme.setAttribute("content", isOpen ? "#111827" : "#f8fafc");
      };
      this.$watch('showSaveModal', updateThemeColor);
      this.$watch('showShareModal', updateThemeColor);
      this.$watch('showDownloadModal', updateThemeColor);
      this.$watch('showSceneModal', updateThemeColor);
      this.$watch('showPromptModal', updateThemeColor);

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
        window.scrollTo({ top: 0, behavior: 'smooth' });
      });

      // 初回生成の完了後に未保存フラグをリセットする
      this.$nextTick(() => {
        setTimeout(() => {
          if (typeof setDirty === 'function') setDirty(false);
          this.hasUnsavedEdit = false;
          this._isInitialized = true; // 初期化完了フラグ
          history.replaceState({ view: 'generator', step: 'typeSelection' }, '', location.href);
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
        let hex = /^[0-9A-F]{3,6}$/i.test(color) ? '#' + color : color;
        if (/^#[0-9A-F]{3}$/i.test(hex)) {
          hex = '#' + hex[1] + hex[1] + hex[2] + hex[2] + hex[3] + hex[3];
        }
        return hex;
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

      // --- 過去のバグで保存された無効なロゴ（相対パスなど）を除外してエラーを防ぐ ---
      if (this.qrOptions.logo && !this.qrOptions.logo.startsWith("data:")) {
        console.warn("無効なロゴを検出したため除外しました:", this.qrOptions.logo);
        this.qrOptions.logo = "";
        this.logoFileName = "";
      }

      this.checkQrQuality();

      // 【重要】Alpine.jsの監視データ(Proxy)を解除して、純粋なデータに変換します
      // ディープコピー時のUIフリーズ（OOMクラッシュ）やProxyの意図せぬ反応を防ぐため、スプレッド構文で巨大なBase64を分離
      const rawOptions = window.Alpine.raw(this.qrOptions);
      const { logo, ...restOptions } = rawOptions;

      const plainOptions = JSON.parse(JSON.stringify(restOptions));
      plainOptions.logo = logo;

      // 無効な背景色でライブラリがクラッシュするのを防ぐフォールバック
      const fixHex = (c) => /^#?([0-9a-fA-F]{3,8})$/.test(c) ? (c.startsWith('#') ? c : '#' + c) : '#ffffff';

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
        backgroundOptions: { color: fixHex(plainOptions.backgroundColor) },
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
        this.hapticFeedback('error');
        return;
      }

      // フレームの再描画処理
      this.applyFrame();
      if (this.qrOptions.logo) {
        // 描画のタイミングズレを防ぐため、少し待ってから再度フレームを描画
        setTimeout(() => this.applyFrame(), 50);
      }

      if (recordHistory) this.recordState();

      this.isUpdatingPreview = true;
      if (this.previewUpdateTimeout) clearTimeout(this.previewUpdateTimeout);
      this.previewUpdateTimeout = setTimeout(() => { this.isUpdatingPreview = false; }, 200);
    },

    // --- ユーザー操作に応じた処理 ---
    // QRコードのタイプを選択したときの処理
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
      if (file.type === "image/svg+xml" && file.size > 500 * 1024) {
        this.showFlashNotification("SVGロゴは複雑すぎると処理が重くなるため、500KB以下のファイルを選択してください。");
        event.target.value = "";
        return;
      }
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
    // 画像をクリップボードにコピー
    async copyImageToClipboard() {
      if (!this.qrCodeInstance) return;

      if (!window.ClipboardItem) {
        this.showFlashNotification("お使いのブラウザは画像のコピーに対応していません。ダウンロードをご利用ください。");
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

      svgClone.setAttribute("width", canvasWidth);
      svgClone.setAttribute("height", canvasHeight);

      // SVGの必須名前空間を付与（XMLSerializerのバグ・Illustrator対策）
      svgClone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
      svgClone.setAttribute("xmlns:xlink", "http://www.w3.org/1999/xlink");

      if (this.download.transparentBg) {
        const bgRect = Array.from(svgClone.children).find(el => el.tagName.toLowerCase() === 'rect');
        if (bgRect) {
          bgRect.setAttribute("fill", "transparent");
          bgRect.style.fill = "transparent";
        }
      }

      // DOMを動的に置換するため、Array.from で静的な配列にしておく
      const imageTags = Array.from(svgClone.querySelectorAll("image, img"));
      let hasInvalidImage = false;

      for (let img of imageTags) {
        // 🔥 Canvas描画エラー（SVG Rendering Error）の真の原因である crossorigin を完全に削除！
        img.removeAttribute("crossorigin");
        img.removeAttribute("crossOrigin");

        let href = img.getAttribute("href") || img.getAttribute("xlink:href") || img.getAttribute("src");
        if (href) {
          if (!href.startsWith("data:")) {
            img.remove();
            hasInvalidImage = true;
          } else if (img.tagName.toLowerCase() === 'img') {
            img.remove();
            hasInvalidImage = true;
          } else {
            // 💡 究極のIllustrator互換対策 (God-Rank Polish)
            // Base64のSVGをPNGに妥協せず、生のベクターDOMとしてインライン展開する
            if (href.startsWith("data:image/svg+xml")) {
              try {
                let svgString = "";
                if (href.includes("base64,")) {
                  const binStr = atob(href.split("base64,")[1]);
                  const bytes = new Uint8Array(binStr.length);
                  for (let i = 0; i < binStr.length; i++) {
                    bytes[i] = binStr.charCodeAt(i);
                  }
                  svgString = new TextDecoder('utf-8').decode(bytes); // 文字化け防止
                } else {
                  svgString = decodeURIComponent(href.split(",")[1]);
                }

                // 文字列からSVG要素を生成
                const parser = new DOMParser();
                const doc = parser.parseFromString(svgString, "image/svg+xml");
                const innerSvg = doc.documentElement;

                if (innerSvg && innerSvg.tagName.toLowerCase() === "svg") {
                  // 🛡️ 悪意ある要素や属性の混入を完全防止（XSSサニタイズ強化）
                  const allElements = innerSvg.querySelectorAll("*");
                  allElements.forEach(el => {
                    const tagName = el.tagName.toLowerCase();
                    if (['script', 'foreignobject', 'object', 'embed', 'iframe', 'applet'].includes(tagName)) {
                      el.remove();
                      return;
                    }
                    Array.from(el.attributes).forEach(attr => {
                      const attrName = attr.name.toLowerCase();
                      const attrVal = attr.value.trim().toLowerCase();
                      if (attrName.startsWith('on')) {
                        el.removeAttribute(attr.name);
                      }
                      if ((attrName === 'href' || attrName === 'xlink:href') && attrVal.startsWith('javascript:')) {
                        el.removeAttribute(attr.name);
                      }
                    });
                  });

                  // 元の <image> タグが持っていた座標とサイズを、展開した <svg> に引き継ぐ
                  ['x', 'y', 'width', 'height'].forEach(attr => {
                    const val = img.getAttribute(attr);
                    if (val) innerSvg.setAttribute(attr, val);
                  });

                  // Illustrator用に名前空間を明示
                  innerSvg.setAttribute("xmlns", "http://www.w3.org/2000/svg");

                  // <image> タグを、完全なベクター図形群(<svg>)に置き換える
                  img.parentNode.replaceChild(innerSvg, img);
                  continue; // SVGのインライン化に成功した場合はここで次のループへ
                }
              } catch (e) {
                console.warn("SVGのフルベクター展開に失敗しました。フォールバックします。", e);
              }
            }

            // PNGやJPEG等のラスタ画像の場合のみ、旧来のxlink:hrefを付与して互換性を保つ
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

        // 容量制限のない安全な Blob URL を使用
        const blob = new Blob([finalSvgString], { type: "image/svg+xml;charset=utf-8" });
        const safeSvgBlobUrl = URL.createObjectURL(blob);

        const clipboardItem = new window.ClipboardItem({
          "image/png": new Promise(async (resolve, reject) => {
            try {
              const image = new Image();
              await new Promise((res, rej) => {
                image.onload = res;
                image.onerror = () => {
                  URL.revokeObjectURL(safeSvgBlobUrl);
                  rej(new Error("SVG Rendering Error"));
                };
                image.src = safeSvgBlobUrl;
              });

              const canvas = document.createElement("canvas");
              canvas.width = canvasWidth;
              canvas.height = canvasHeight;

              const ctx = canvas.getContext("2d");
              ctx.drawImage(image, 0, 0, canvas.width, canvas.height);

              canvas.toBlob((pngBlob) => {
                if (pngBlob) resolve(pngBlob);
                else reject(new Error("Blob generation failed"));
                URL.revokeObjectURL(safeSvgBlobUrl);
              }, "image/png");
            } catch (e) {
              URL.revokeObjectURL(safeSvgBlobUrl);
              reject(e);
            }
          })
        });
        await navigator.clipboard.write([clipboardItem]);
        if (hasInvalidImage) {
          this.showFlashNotification("無効なロゴを除外して画像をクリップボードにコピーしました。");
        } else {
          this.showFlashNotification("画像をクリップボードにコピーしました！");
        }
        this.hapticFeedback('success');
      } catch (err) {
        console.error("コピーに失敗しました", err);
        this.showFlashNotification("画像の生成に失敗しました。");
      }
    },

    // QRコードをPNGまたはSVG形式でダウンロード
    async downloadQrCode() {
      if (!this.qrCodeInstance) return;

      const extension = this.download.format;
      const safeName = (this.download.fileName || "grinds-qr-code").replace(/[\\/:*?"<>|]/g, "-");

      const visibleCanvas = this.showSceneModal ? this.$refs.modalQrCanvas : this.$refs.qrCodeCanvas;
      const svgElement = visibleCanvas.querySelector("svg");
      if (!svgElement) return;

      const svgClone = svgElement.cloneNode(true);
      const svgViewBox = svgElement.viewBox.baseVal;
      const aspectRatio = svgViewBox.height > 0 ? svgViewBox.width / svgViewBox.height : 1;
      const canvasWidth = this.download.size;
      const canvasHeight = this.download.size / Math.max(aspectRatio, 0.0001);

      // SVGもPNGも、設定したダウンロードサイズを絶対値(px)として付与する。
      // これによりIllustrator等で開いた際も正しいアートボードサイズで展開される。
      svgClone.setAttribute("width", canvasWidth);
      svgClone.setAttribute("height", canvasHeight);
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

      // DOMを動的に置換するため、Array.from で静的な配列にしておく
      const imageTags = Array.from(svgClone.querySelectorAll("image, img"));
      let hasInvalidImage = false;

      for (let img of imageTags) {
        // 🔥 Canvas描画エラー（SVG Rendering Error）の真の原因である crossorigin を完全に削除！
        img.removeAttribute("crossorigin");
        img.removeAttribute("crossOrigin");

        let href = img.getAttribute("href") || img.getAttribute("xlink:href") || img.getAttribute("src");
        if (href) {
          if (!href.startsWith("data:")) {
            img.remove();
            hasInvalidImage = true;
          } else if (img.tagName.toLowerCase() === 'img') {
            img.remove();
            hasInvalidImage = true;
          } else {
            // 💡 究極のIllustrator互換対策 (God-Rank Polish)
            // Base64のSVGをPNGに妥協せず、生のベクターDOMとしてインライン展開する
            if (href.startsWith("data:image/svg+xml")) {
              try {
                let svgString = "";
                if (href.includes("base64,")) {
                  const binStr = atob(href.split("base64,")[1]);
                  const bytes = new Uint8Array(binStr.length);
                  for (let i = 0; i < binStr.length; i++) {
                    bytes[i] = binStr.charCodeAt(i);
                  }
                  svgString = new TextDecoder('utf-8').decode(bytes); // 文字化け防止
                } else {
                  svgString = decodeURIComponent(href.split(",")[1]);
                }

                // 文字列からSVG要素を生成
                const parser = new DOMParser();
                const doc = parser.parseFromString(svgString, "image/svg+xml");
                const innerSvg = doc.documentElement;

                if (innerSvg && innerSvg.tagName.toLowerCase() === "svg") {
                  // 🛡️ 悪意ある要素や属性の混入を完全防止（XSSサニタイズ強化）
                  const allElements = innerSvg.querySelectorAll("*");
                  allElements.forEach(el => {
                    const tagName = el.tagName.toLowerCase();
                    if (['script', 'foreignobject', 'object', 'embed', 'iframe', 'applet'].includes(tagName)) {
                      el.remove();
                      return;
                    }
                    Array.from(el.attributes).forEach(attr => {
                      const attrName = attr.name.toLowerCase();
                      const attrVal = attr.value.trim().toLowerCase();
                      if (attrName.startsWith('on')) {
                        el.removeAttribute(attr.name);
                      }
                      if ((attrName === 'href' || attrName === 'xlink:href') && attrVal.startsWith('javascript:')) {
                        el.removeAttribute(attr.name);
                      }
                    });
                  });

                  // 元の <image> タグが持っていた座標とサイズを、展開した <svg> に引き継ぐ
                  ['x', 'y', 'width', 'height'].forEach(attr => {
                    const val = img.getAttribute(attr);
                    if (val) innerSvg.setAttribute(attr, val);
                  });

                  // Illustrator用に名前空間を明示
                  innerSvg.setAttribute("xmlns", "http://www.w3.org/2000/svg");

                  // <image> タグを、完全なベクター図形群(<svg>)に置き換える
                  img.parentNode.replaceChild(innerSvg, img);
                  continue; // SVGのインライン化に成功した場合はここで次のループへ
                }
              } catch (e) {
                console.warn("SVGのフルベクター展開に失敗しました。フォールバックします。", e);
              }
            }

            // PNGやJPEG等のラスタ画像の場合のみ、旧来のxlink:hrefを付与して互換性を保つ
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
          const image = new Image();

          await new Promise((resolve, reject) => {
            image.onload = resolve;
            image.onerror = () => reject(new Error("SVG Rendering Error"));
            image.src = svgBlobUrl;
          });

          const canvas = document.createElement("canvas");
          canvas.width = canvasWidth;
          canvas.height = canvasHeight;

          const ctx = canvas.getContext("2d");
          ctx.drawImage(image, 0, 0, canvas.width, canvas.height);

          fileData = await new Promise(resolve => canvas.toBlob(resolve, "image/png"));
          acceptTypes = { "image/png": [".png"] };
        }

        const fullFileName = `${safeName}.${extension}`;

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
              this.showFlashNotification("画像の保存に失敗しました。");
            }
            return; // ユーザーがキャンセルした場合は中止
          }
        } else {
          // API非対応ブラウザ向けのフォールバック
          const a = document.createElement("a");
          a.target = "_blank";
          a.rel = "noopener";
          const url = extension === "png" ? URL.createObjectURL(fileData) : svgBlobUrl;
          a.href = url;
          a.download = fullFileName;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          if (extension === "png") URL.revokeObjectURL(url);
        }

        this.showDownloadModal = false;
        if (hasInvalidImage) {
          this.showFlashNotification("無効なロゴを除外してダウンロードしました。");
        } else {
          this.showFlashNotification("ダウンロードしました。");
        }
        this.hapticFeedback('success');
      } catch (err) {
        console.error("ダウンロードに失敗しました", err);
        this.showFlashNotification("画像の生成に失敗しました。");
      } finally {
        if (svgBlobUrl) setTimeout(() => URL.revokeObjectURL(svgBlobUrl), 100);
      }
    },

    // 作成したQRコードをブラウザのローカルストレージに保存
    // stayOnEditor = true の場合、保存後もダッシュボードへ戻らず編集画面を維持する
    async saveToGrind(stayOnEditor = false) {
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
        imageOptions: {
          ...this.qrOptions.imageOptions,
          margin: this.qrOptions.imageOptions.margin ? this.qrOptions.imageOptions.margin / 4 : 0,
        },
        margin: this.qrOptions.margin ? this.qrOptions.margin / 4 : 0,
      };

      // ディープコピー時のUIフリーズ（OOMクラッシュ）とProxyの副作用を防ぐため、スプレッド構文で巨大なBase64を分離
      const rawOptions = window.Alpine.raw(this.qrOptions);
      const { logo, ...restOptions } = rawOptions;

      const copiedOptions = JSON.parse(JSON.stringify(restOptions));
      copiedOptions.logo = logo;

      // タグを配列に変換（カンマ区切りで分割し、前後の空白を除去、空文字をフィルタリング）
      const tagsArray = this.saveTags ? this.saveTags.split(',').map(t => t.trim()).filter(t => t) : [];

      const isNew = !this.editingQRCodeId;
      const newQr = {
        id: this.editingQRCodeId || this.generateUniqueId(),
        name: this.saveName,
        memo: this.saveMemo,
        tags: tagsArray,
        type: this.selectedType,
        formData: JSON.parse(JSON.stringify(this.formData)),
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
        this.showFlashNotification("QRコードの設定を更新しました。");
      } else {
        this.savedQRCodes.unshift(newQr);
        this.editingQRCodeId = newQr.id; // 新規保存からシームレスに編集モードへ移行
        this.showFlashNotification("QRコードを保存しました。");
        this.hapticFeedback('success');
      }

      await this.persistSavedQRCodes();

      if (typeof setDirty === 'function') setDirty(true);

      this.hasUnsavedEdit = false;
      this.showSaveModal = false;

      if (!stayOnEditor) {
        this.currentView = "dashboard";
        this.resetGenerator();
      }
    },

    // --- 補助関数 ---
    // QRコードにエンコードするデータ文字列を生成
    getQrDataString() {
      let data = " ";
      switch (this.selectedType) {
        case "url":
          let urlStr = this.formData.url.address.trim();
          if (urlStr && !/^[a-zA-Z][a-zA-Z0-9+.-]*:/i.test(urlStr)) {
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
            return String(str).replace(/([\\;:,])/g, "\\$1");
          };
          if (ssid) {
            const encType = encryption === "WPA/WPA2" ? "WPA" : (encryption === "なし" ? "nopass" : encryption);
            data = `WIFI:T:${encType};S:${escapeWifiStr(ssid)};P:${escapeWifiStr(password)};;`;
          }
          break;
        case "vcard":
          const { firstName, lastName, organization, phone, email, address } = this.formData.vcard;
          const escapeVCard = (str) => {
            if (!str) return "";
            return String(str).replace(/([,;\\])/g, "\\$1").replace(/\r?\n/g, "\\n");
          };

          if (firstName || lastName) {
            const vcardLines = [
              "BEGIN:VCARD",
              "VERSION:3.0",
              `N;CHARSET=UTF-8:${escapeVCard(lastName)};${escapeVCard(firstName)}`,
              `FN;CHARSET=UTF-8:${escapeVCard(lastName ? lastName + " " : "")}${escapeVCard(firstName)}`.trim()
            ];
            if (organization) vcardLines.push(`ORG:${escapeVCard(organization)}`);
            if (phone) vcardLines.push(`TEL:${escapeVCard(phone)}`);
            if (email) vcardLines.push(`EMAIL:${escapeVCard(email)}`);
            if (address) vcardLines.push(`ADR;TYPE=WORK:;;${escapeVCard(address)};;;;`);
            vcardLines.push("END:VCARD");
            data = vcardLines.join("\r\n");
          }
          break;
        case "event":
          const { summary, location, start, end, description } = this.formData.event;
          const formatDT = (dt) => (dt ? dt.replace(/[-:]/g, "") + "00" : "");
          const escapeICal = (str) => {
            if (!str) return "";
            return String(str).replace(/[\\;,]/g, "\\$&").replace(/\r?\n/g, "\\n");
          };
          if (summary && start && end) {
            const dtstamp = new Date().toISOString().replace(/[-:]/g, "").split(".")[0] + "Z";
            const uid = `${Date.now()}-${Math.random().toString(36).substring(2,10)}@grinds`;
            data = `BEGIN:VEVENT\r\nVERSION:2.0\r\nPRODID:-//GrindMoney//QRCoder//EN\r\nUID:${uid}\r\nDTSTAMP:${dtstamp}\r\nSUMMARY:${escapeICal(summary)}\r\nLOCATION:${escapeICal(location)}\r\nDTSTART:${formatDT(start)}\r\nDTEND:${formatDT(end)}\r\nDESCRIPTION:${escapeICal(description)}\r\nEND:VEVENT`;
          }
          break;
        case "email":
          const { to, subject, body } = this.formData.email;
          if (to) {
            let query = [];
            if (subject) query.push(`subject=${encodeURIComponent(subject)}`);
            if (body) query.push(`body=${encodeURIComponent(body)}`);
            data = `mailto:${to}${query.length > 0 ? '?' + query.join('&') : ''}`;
          }
          break;
        case "geo":
          const { latitude, longitude } = this.formData.geo;
          if (latitude && longitude) {
            data = `geo:${latitude},${longitude}?q=${latitude},${longitude}`;
          }
          break;
        case "sns":
          const { service, identifier } = this.formData.sns;
          if (identifier) {
            // ユーザーが誤って先頭に @ を入力した場合でも安全に除去（トリムも実行）
            const cleanId = identifier.replace(/^@/, '').trim();
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
              case "linkedin":
                // URLや 'in/' が含まれていない場合は自動付与
                const lnId = cleanId.replace(/^in\//i, '');
                data = `https://www.linkedin.com/in/${encodeURIComponent(lnId)}`;
                break;
              case "whatsapp":
                data = `https://wa.me/${encodeURIComponent(cleanId.replace(/[^0-9]/g, ''))}`;
                break;
              case "github":
                data = `https://github.com/${encodeURIComponent(cleanId)}`;
                break;
              case "discord":
                // URLが直接貼り付けられた場合はそのまま、そうでない場合は招待リンクとして処理
                if (identifier.includes("http")) {
                  data = identifier.trim();
                } else {
                  data = `https://discord.gg/${encodeURIComponent(cleanId)}`;
                }
                break;
              case "paypal":
                data = `https://paypal.me/${encodeURIComponent(cleanId)}`;
                break;
              case "paypay":
                data = identifier.trim();
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

      const fgColorsList = this.qrOptions.colorType === "single" ? [this.qrOptions.foregroundColor] : [this.qrOptions.gradient.color1, this.qrOptions.gradient.color2];

      // コーナーの色も追加して全て背景色とのコントラスト・輝度をチェック
      fgColorsList.push(this.qrOptions.cornerColor, this.qrOptions.cornerDotColor);
      const fgColors = [...new Set(fgColorsList)];

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

        // 背景の輝度と、ドットの輝度を比較
        const bgLum = this.getLuminance(bgRgb.r, bgRgb.g, bgRgb.b);
        let isNegative = false;

        for (const color of fgColors) {
          const fgRgb = this.hexToRgb(color);
          if (fgRgb) {
            const fgLum = this.getLuminance(fgRgb.r, fgRgb.g, fgRgb.b);
            // ドットの方が背景よりも明るい場合（ネガポジ反転）
            if (fgLum > bgLum) {
              isNegative = true;
            }
          }
        }

        if (isNegative) {
          this.qrQuality.issues.push({
            status: "bad",
            message: "背景よりドットが明るい「明暗逆転」になっています。多くのリーダーで読み取れません。",
            // グラデーション時は自動スワップでロジックが破綻するためボタンを非表示にする
            action: this.qrOptions.colorType === "single" ? () => {
              // 背景色と前景色のスワップ（反転）
              const temp = this.qrOptions.backgroundColor;
              this.qrOptions.backgroundColor = this.qrOptions.foregroundColor;
              this.qrOptions.foregroundColor = temp;
              // コーナーの色も追従
              this.qrOptions.cornerColor = temp;
              this.qrOptions.cornerDotColor = temp;
              this.updateQrCode();
            } : null
          });
          score -= 40;
        }
      }

      const currentDataStr = this.getQrDataString();
      if (currentDataStr.length > 100) {
        this.qrQuality.issues.push({
          status: "warning",
          message: `データ量が多いためドットが細かくなっています。読み取り環境にご注意ください。`,
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

        // 閾値を 0.45 に引き上げて、UIの最大値 (0.4) を選択しても即エラーにならないようにする
        if (totalCoverageRatio > 0.45) {
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

      // Alpine.raw を使ってプロキシを解除してからクローンする
      const rawOptions = window.Alpine.raw(this.qrOptions);

      // ロゴ文字列は巨大なので、オブジェクトから分離してメモリを節約しつつクローン
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
      // Undo/Redo時にも巨大なBase64画像のディープコピー（UIフリーズ）を回避する
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
      // 基本のテンプレート群
      const basicTemplates = [
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
      const lineIconSvgInner = `<circle cx="160" cy="160" fill="#4cc764" r="160"/><path d="m266.7 150.68c0-47.8-47.92-86.68-106.81-86.68s-106.81 38.89-106.81 86.68c0 42.85 38 78.73 89.33 85.52 3.48.75 8.21 2.29 9.41 5.27 1.08 2.7.7 6.93.35 9.66 0 0-1.25 7.54-1.52 9.14-.47 2.7-2.15 10.56 9.25 5.76s61.51-36.22 83.92-62.01c15.48-16.98 22.9-34.2 22.9-53.33z" fill="#fff"/><g fill="#4cc764"><path d="m231.17 178.28c1.13 0 2.04-.91 2.04-2.04v-7.58c0-1.12-.92-2.04-2.04-2.04h-20.39v-7.87h20.39c1.13 0 2.04-.91 2.04-2.04v-7.57c0-1.12-.92-2.04-2.04-2.04h-20.39v-7.87h20.39c1.13 0 2.04-.91 2.04-2.04v-7.57c0-1.12-.92-2.04-2.04-2.04h-30.01c-1.13 0-2.04.91-2.04 2.04v.04 46.54.04c0 1.13.91 2.04 2.04 2.04z"/><path d="m120.17 178.28c1.13 0 2.04-.91 2.04-2.04v-7.58c0-1.12-.92-2.04-2.04-2.04h-20.39v-37c0-1.12-.92-2.04-2.04-2.04h-7.58c-1.13 0-2.04.91-2.04 2.04v46.58.04c0 1.13.91 2.04 2.04 2.04z"/><rect height="50.69" rx="2.04" width="11.65" x="128.62" y="127.58"/><path d="m189.8 127.58h-7.58c-1.13 0-2.04.91-2.04 2.04v27.69l-21.33-28.8c-.05-.07-.11-.14-.16-.21 0 0 0 0-.01-.01-.04-.04-.08-.09-.12-.13-.01-.01-.03-.02-.04-.03-.04-.03-.07-.06-.11-.09-.02-.01-.04-.03-.06-.04-.03-.03-.07-.05-.11-.07-.02-.01-.04-.03-.06-.04-.04-.02-.07-.04-.11-.06-.02-.01-.04-.02-.06-.03-.04-.02-.08-.04-.12-.05-.02 0-.04-.02-.07-.02-.04-.01-.08-.03-.12-.04-.02 0-.05-.01-.07-.02-.04 0-.08-.02-.12-.03-.03 0-.06 0-.09-.01-.04 0-.07-.01-.11-.01s-.07 0-.11 0c-.02 0-.05 0-.07 0h-7.53c-1.13 0-2.04.91-2.04 2.04v46.62c0 1.13.91 2.04 2.04 2.04h7.58c1.13 0 2.04-.91 2.04-2.04v-27.68l21.35 28.84c.15.21.33.38.53.51 0 0 .02.01.02.02.04.03.08.05.13.08.02.01.04.02.06.03.03.02.07.03.1.05s.07.03.1.04c.02 0 .04.02.06.02.05.02.09.03.14.04h.03c.17.04.35.07.53.07h7.53c1.13 0 2.04-.91 2.04-2.04v-46.62c0-1.13-.91-2.04-2.04-2.04z"/></g>`;
      const lineIconSvg = `<svg viewBox="0 0 320 320" xmlns="http://www.w3.org/2000/svg">${lineIconSvgInner}</svg>`;

      // 2. 文字ロゴ (Text Logo)
      const lineTextSvgInner = `<g fill="#4cc764"><path d="m143.05 50.69c1.13 0 2.04-.91 2.04-2.04v-7.58c0-1.12-.92-2.04-2.04-2.04h-20.39v-7.87h20.39c1.13 0 2.04-.91 2.04-2.04v-7.57c0-1.12-.92-2.04-2.04-2.04h-20.39v-7.87h20.39c1.13 0 2.04-.91 2.04-2.04v-7.56c0-1.12-.92-2.04-2.04-2.04h-30.01c-1.13 0-2.04.91-2.04 2.04v.04 46.54.04c0 1.13.91 2.04 2.04 2.04h30.01z"/><path d="m32.05 50.69c1.13 0 2.04-.91 2.04-2.04v-7.58c0-1.12-.92-2.04-2.04-2.04h-20.4v-36.99c0-1.12-.91-2.04-2.04-2.04h-7.57c-1.13 0-2.04.91-2.04 2.04v46.58.04c0 1.13.91 2.04 2.04 2.04h30.01z"/><rect height="50.69" rx="2.04" width="11.65" x="40.5"/><path d="m101.68 0h-7.58c-1.13 0-2.04.91-2.04 2.04v27.69l-21.32-28.81c-.05-.07-.11-.14-.16-.21 0 0 0 0-.01-.01-.04-.04-.08-.09-.12-.13-.01-.01-.03-.02-.04-.03-.04-.03-.07-.06-.11-.09-.02-.01-.04-.03-.06-.04-.03-.03-.07-.05-.11-.07-.02-.01-.04-.03-.06-.04-.04-.02-.07-.04-.11-.06-.02-.01-.04-.02-.06-.03-.04-.02-.08-.04-.12-.05-.02 0-.04-.02-.07-.02-.04-.01-.08-.03-.12-.04-.02 0-.05-.01-.07-.02-.04 0-.08-.02-.12-.03-.03 0-.06 0-.09-.01-.04 0-.07-.01-.11-.01s-.07 0-.11 0c-.02 0-.05 0-.07 0h-7.53c-1.13 0-2.04.91-2.04 2.04v46.62c0 1.13.91 2.04 2.04 2.04h7.58c1.13 0 2.04-.91 2.04-2.04v-27.68l21.35 28.84c.15.21.33.38.53.51 0 0 .02.01.02.02.04.03.08.05.13.08l.06.03c.03.02.07.03.1.05s.07.03.1.04c.02 0 .04.02.06.02.05.02.09.03.14.04h.03c.17.04.35.07.53.07h7.53c1.13 0 2.04-.91 2.04-2.04v-46.63c0-1.13-.91-2.04-2.04-2.04z"/></g>`;
      const lineTextSvg = `<svg viewBox="0 0 145.09 50.69" xmlns="http://www.w3.org/2000/svg">${lineTextSvgInner}</svg>`;

      // Data URLの生成
      const iconGreenUrl = `data:image/svg+xml;base64,${btoa(lineIconSvg)}`;
      const textGreenUrl = `data:image/svg+xml;base64,${btoa(lineTextSvg)}`;

      // Gmail テンプレート定義
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
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 4, crossOrigin: "anonymous" },
        },
      };

      // Instagram テンプレート定義
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
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8, crossOrigin: "anonymous" },
        },
      };

      // Facebook テンプレート定義
      const facebookSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="666.667" height="666.667" viewBox="0 0 666.667 666.667"><defs><clipPath id="a" clipPathUnits="userSpaceOnUse"><path d="M0 700h700V0H0Z"/></clipPath></defs><g clip-path="url(#a)" transform="matrix(1.33333 0 0 -1.33333 -133.333 800)"><path d="M0 0c0 138.071-111.929 250-250 250S-500 138.071-500 0c0-117.245 80.715-215.622 189.606-242.638v166.242h-51.552V0h51.552v32.919c0 85.092 38.508 124.532 122.048 124.532 15.838 0 43.167-3.105 54.347-6.211V81.986c-5.901.621-16.149.932-28.882.932-40.993 0-56.832-15.528-56.832-55.9V0h81.659l-14.028-76.396h-67.631v-171.773C-95.927-233.218 0-127.818 0 0" style="fill:#0866ff;fill-opacity:1;fill-rule:nonzero;stroke:none" transform="translate(600 350)"/><path d="m0 0 14.029 76.396H-67.63v27.019c0 40.372 15.838 55.899 56.831 55.899 12.733 0 22.981-.31 28.882-.931v69.253c-11.18 3.106-38.509 6.212-54.347 6.212-83.539 0-122.048-39.441-122.048-124.533V76.396h-51.552V0h51.552v-166.242a250.559 250.559 0 0 1 60.394-7.362c10.254 0 20.358.632 30.288 1.831V0Z" style="fill:#fff;fill-opacity:1;fill-rule:nonzero;stroke:none" transform="translate(447.918 273.604)"/></g></svg>`;
      const facebookLogoUrl = `data:image/svg+xml;base64,${btoa(facebookSvg)}`;

      const facebookTemplate = {
        name: "Facebook",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#0866ff"/></g><image x="30" y="30" width="40" height="40" href="${facebookLogoUrl}" /></svg>`,
        options: {
          ...defaultQrOptions,
          errorCorrectionLevel: "H",
          logo: facebookLogoUrl,
          colorType: "single",
          foregroundColor: "#0866ff",
          backgroundColor: "#ffffff",
          dotsStyle: "rounded",
          cornersStyle: "extra-rounded",
          cornerColor: "#0866ff",
          cornerDotColor: "#0866ff",
          cornersDotStyle: "dot",
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 6, crossOrigin: "anonymous" },
        },
      };

      // TikTok テンプレート定義
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
          imageOptions: { hideBackgroundDots: true, imageSize: 0.4, margin: 10, crossOrigin: "anonymous" },
        },
      };

      // X テンプレート定義
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
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10, crossOrigin: "anonymous" },
        },
      };

      // ZOOM テンプレート定義
      const zoomSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" preserveAspectRatio="xMidYMid" viewBox="0 0 256 256"><defs><linearGradient id="a" x1="23.666%" x2="76.334%" y1="95.6118%" y2="4.3882%"><stop offset=".00006%" stop-color="#0845BF"/><stop offset="19.11%" stop-color="#0950DE"/><stop offset="38.23%" stop-color="#0B59F6"/><stop offset="50%" stop-color="#0B5CFF"/><stop offset="67.32%" stop-color="#0E5EFE"/><stop offset="77.74%" stop-color="#1665FC"/><stop offset="86.33%" stop-color="#246FF9"/><stop offset="93.88%" stop-color="#387FF4"/><stop offset="100%" stop-color="#4F90EE"/></linearGradient></defs><path fill="url(#a)" d="M256 128c0 13.568-1.024 27.136-3.328 40.192-6.912 43.264-41.216 77.568-84.48 84.48C155.136 254.976 141.568 256 128 256c-13.568 0-27.136-1.024-40.192-3.328-43.264-6.912-77.568-41.216-84.48-84.48C1.024 155.136 0 141.568 0 128c0-13.568 1.024-27.136 3.328-40.192 6.912-43.264 41.216-77.568 84.48-84.48C100.864 1.024 114.432 0 128 0c13.568 0 27.136 1.024 40.192 3.328 43.264 6.912 77.568 41.216 84.48 84.48C254.976 100.864 256 114.432 256 128Z"/><path fill="#FFF" d="M204.032 207.872H75.008c-8.448 0-16.64-4.608-20.48-12.032-4.608-8.704-2.816-19.2 4.096-26.112l89.856-89.856H83.968c-17.664 0-32-14.336-32-32h118.784c8.448 0 16.64 4.608 20.48 12.032 4.608 8.704 2.816 19.2-4.096 26.112l-89.6 90.112h74.496c17.664 0 32 14.08 32 31.744Z"/></svg>`;
      const zoomLogoUrl = `data:image/svg+xml;base64,${btoa(zoomSvg)}`;

      const zoomTemplate = {
        name: "Zoom",
        preview: `<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="#fff"/><g opacity="0.2"><rect x="10" y="10" width="80" height="80" rx="8" fill="#0b5cff"/></g><image x="30" y="30" width="40" height="40" href="${zoomLogoUrl}" /></svg>`,
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
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 6, crossOrigin: "anonymous" },
        },
      };

      // Discord テンプレート定義
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
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8, crossOrigin: "anonymous" },
        },
      };

      // GitHub テンプレート定義
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
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10, crossOrigin: "anonymous" },
        },
      };

      // YouTube テンプレート定義
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
          imageOptions: { hideBackgroundDots: true, imageSize: 0.4, margin: 8, crossOrigin: "anonymous" },
        },
      };

      // LinkedIn テンプレート定義
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
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8, crossOrigin: "anonymous" },
        },
      };

      // Spotify テンプレート定義
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
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10, crossOrigin: "anonymous" },
        },
      };

      // Apple Music テンプレート定義
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
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10, crossOrigin: "anonymous" },
        },
      };

      // WhatsApp テンプレート定義
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
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10, crossOrigin: "anonymous" },
        },
      };

      // PayPal テンプレート定義
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
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10, crossOrigin: "anonymous" },
        },
      };

      // Notion テンプレート定義
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
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 8, crossOrigin: "anonymous" },
        },
      };

      // Google Drive テンプレート定義
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
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10, crossOrigin: "anonymous" },
        },
      };

      // PayPay テンプレート定義
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
          imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 10, crossOrigin: "anonymous" },
        },
      };

      // LINE テンプレート定義
      const lineTemplates = [
        // 1. アイコン・緑
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
            imageOptions: { hideBackgroundDots: true, imageSize: 0.3, margin: 6, crossOrigin: "anonymous" },
          },
        },
        // 2. 文字ロゴ・緑
        {
          name: "LINE文字",
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
            // 文字ロゴは横長なので、サイズを少し大きめに設定
            imageOptions: { hideBackgroundDots: true, imageSize: 0.35, margin: 6, crossOrigin: "anonymous" },
          },
        },
      ];

      // カテゴリごとにテンプレートをグループ化
      this.presetTemplateGroups = [
        {
          name: "スタイル・パターン",
          templates: basicTemplates
        },
        {
          name: "SNS・コミュニケーション",
          templates: [
            lineTemplates[0],
            lineTemplates[1],
            instagramTemplate,
            xTemplate,
            facebookTemplate,
            tiktokTemplate,
            whatsappTemplate,
            discordTemplate
          ]
        },
        {
          name: "ビジネス・ツール",
          templates: [
            youtubeTemplate,
            githubTemplate,
            linkedinTemplate,
            notionTemplate,
            googleDriveTemplate,
            zoomTemplate,
            gmailTemplate,
            paypalTemplate,
            paypayTemplate
          ]
        },
        {
          name: "エンタメ・メディア",
          templates: [
            spotifyTemplate,
            appleMusicTemplate
          ]
        }
      ];

      // 既存の処理のためにフラットな配列も保持
      this.presetTemplates = this.presetTemplateGroups.flatMap(group => group.templates);
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
      if (typeof crypto !== 'undefined' && crypto.randomUUID) {
        return crypto.randomUUID();
      }
      // randomUUIDのフォールバック (安全な乱数生成)
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
        linkedin: "ユーザー名 (例: taro-yamada)",
        whatsapp: "電話番号 (国番号付 例: 819012345678)",
        github: "ユーザー名 (例: octocat)",
        discord: "サーバー招待コード または URL",
        paypal: "PayPal.me のID (例: grinds)",
        paypay: "決済リンクURL (例: https://qr.paypay.ne.jp/...)",
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
        if (current.foregroundColor.toLowerCase() !== tempOpts.foregroundColor.toLowerCase() ||
            current.backgroundColor.toLowerCase() !== tempOpts.backgroundColor.toLowerCase()) return false;
      } else {
        if (!current.gradient || !tempOpts.gradient) return false;
        if (current.gradient.color1.toLowerCase() !== tempOpts.gradient.color1.toLowerCase() ||
            current.gradient.color2.toLowerCase() !== tempOpts.gradient.color2.toLowerCase()) return false;
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
            fontSize = 24;
            const textWidth = visualLen * (fontSize * 0.6) + 30;
            const requiredWidth = Math.max(originalSize, textWidth + 20);
            const offsetX = (requiredWidth - originalSize) / 2;
            svgElement.setAttribute("viewBox", `${-offsetX} 0 ${requiredWidth} ${originalSize + frameHeight}`);
            textY = originalSize + frameHeight / 2;
            const text1 = document.createElementNS("http://www.w3.org/2000/svg", "text");
            Object.assign(text1.style, {
              textAnchor: "middle",
              dominantBaseline: "central",
              fontFamily: "'Inter', 'Helvetica Neue', Arial, sans-serif",
              fontWeight: "bold",
            });
            text1.setAttribute("x", originalSize / 2);
            text1.setAttribute("y", textY);
            text1.setAttribute("font-size", `${fontSize}px`);
            text1.setAttribute("fill", textColor);
            text1.textContent = this.frame.text;
            frameGroup.appendChild(text1);
            break;
          }
          case "scan-me-2": {
            frameHeight = 50;
            fontSize = 22;
            const textWidth = visualLen * (fontSize * 0.6) + 30;
            const requiredWidth = Math.max(originalSize, textWidth + 20);
            const offsetX = (requiredWidth - originalSize) / 2;
            svgElement.setAttribute("viewBox", `${-offsetX} 0 ${requiredWidth} ${originalSize + frameHeight}`);
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
              fontFamily: "'Inter', 'Helvetica Neue', Arial, sans-serif",
              fontWeight: "bold",
            });
            text2.setAttribute("x", originalSize / 2);
            text2.setAttribute("y", textY);
            text2.setAttribute("font-size", `${fontSize}px`);
            text2.setAttribute("fill", textColor);
            text2.textContent = this.frame.text;
            frameGroup.appendChild(text2);
            break;
          }
          case "scan-me-3": {
            frameHeight = 40;
            fontSize = 22;
            const textWidth = visualLen * (fontSize * 0.6) + 30;
            const requiredWidth = Math.max(originalSize, textWidth + 20);
            const offsetX = (requiredWidth - originalSize) / 2;
            svgElement.setAttribute("viewBox", `${-offsetX} 0 ${requiredWidth} ${originalSize + frameHeight}`);
            textY = originalSize + frameHeight / 2;
            const bgRect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
            bgRect.setAttribute("x", -offsetX);
            bgRect.setAttribute("y", originalSize);
            bgRect.setAttribute("width", requiredWidth);
            bgRect.setAttribute("height", frameHeight);
            bgRect.setAttribute("fill", textColor);
            frameGroup.appendChild(bgRect);
            const text3 = document.createElementNS("http://www.w3.org/2000/svg", "text");
            Object.assign(text3.style, {
              textAnchor: "middle",
              dominantBaseline: "central",
              fontFamily: "'Inter', 'Helvetica Neue', Arial, sans-serif",
              fontWeight: "bold",
            });
            text3.setAttribute("x", originalSize / 2);
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

      // 古いBlob URLが存在すればメモリを解放する
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

      // ファイルインプットの表示をリセット
      const fileInput = document.getElementById("scene-upload");
      if (fileInput) fileInput.value = "";
    },
    resetSceneOptions() {
      // 古いBlob URLが存在すればメモリを解放する
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
      this.mainSceneBackgroundUrl = "";

      // ファイルインプットの表示をリセット
      const fileInput = document.getElementById("scene-upload");
      if (fileInput) fileInput.value = "";
    },
    handleSceneBackgroundUpload(event) {
      const file = event.target.files[0];
      if (file) {
        if (file.size > 5 * 1024 * 1024) {
          this.showFlashNotification("背景画像は5MB以下のファイルを選択してください。");
          event.target.value = null;
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
        textReader.onloadend = () => {
          let svgString = textReader.result;
          svgString = svgString.replace(/crossorigin="[^"]*"/gi, "");
          const cleanBlob = new Blob([svgString], { type: "image/svg+xml;charset=utf-8" });
          const dataUrlReader = new FileReader();
          dataUrlReader.onloadend = () => resolve(dataUrlReader.result);
          dataUrlReader.onerror = reject;
          dataUrlReader.readAsDataURL(cleanBlob);
        };
        textReader.onerror = reject;
        textReader.readAsText(blob);
      });
    },
    resetGenerator() {
      this.editingQRCodeId = null;
      this.saveName = "";
      this.saveMemo = "";
      this.saveTags = "";
      this.selectedType = "url";
      this.formData = JSON.parse(JSON.stringify(defaultFormData));
      this.resetQrOptions(false);
      this.history = [];
      this.historyIndex = -1;
      this.currentStep = "typeSelection";
      this.$nextTick(() => {
        this.hasUnsavedEdit = false;
        if (typeof setDirty === 'function') setDirty(false);
      });
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

          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);

          store.clear().onsuccess = () => {
            if (this.savedQRCodes.length === 0) return;
            this.savedQRCodes.forEach(qr => {
              // 劇的なパフォーマンス改善: 文字列化のオーバーヘッドを完全に排除
              store.put(window.Alpine.raw(qr));
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

      // --- 古いサムネイル（crossorigin属性付き）の自動修復マイグレーション ---
      let needsSave = false;
      this.savedQRCodes.forEach(qr => {
        if (qr.previewSvgUrl && qr.previewSvgUrl.includes("base64,")) {
          try {
            const b64 = qr.previewSvgUrl.split("base64,")[1];
            const binStr = atob(b64);
            if (binStr.toLowerCase().includes("crossorigin")) {
              const bytes = new Uint8Array(binStr.length);
              for (let i = 0; i < binStr.length; i++) {
                bytes[i] = binStr.charCodeAt(i);
              }
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
            console.warn("サムネイルの自動修復に失敗しました", e);
          }
        }
      });
      if (needsSave) {
        this.persistSavedQRCodes();
      }

      this.currentView = this.savedQRCodes.length > 0 ? "dashboard" : "generator";
    },
    async updateInlineMemo(qr, newMemo) {
      qr.memo = newMemo;
      qr.updatedAt = new Date().toISOString();
      await this.persistSavedQRCodes();
      if (typeof setDirty === 'function') setDirty(true);
      this.showFlashNotification("メモを更新しました。");
    },
    async updateInlineTags(qr, newTagsStr) {
      qr.tags = newTagsStr.split(',').map(t => t.trim()).filter(t => t);
      qr.updatedAt = new Date().toISOString();
      await this.persistSavedQRCodes();
      if (typeof setDirty === 'function') setDirty(true);
      this.showFlashNotification("タグを更新しました。");
    },
    editQRCode(id) {
      const qrToEdit = this.savedQRCodes.find((qr) => qr.id === id);
      if (qrToEdit) {
        this.editingQRCodeId = id;
        this.saveName = qrToEdit.name;
        this.saveMemo = qrToEdit.memo || "";
        this.saveTags = qrToEdit.tags ? qrToEdit.tags.join(', ') : "";
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
          this.history = [];
          this.historyIndex = -1;
          this.recordState();
          this.hasUnsavedEdit = false;
          if (typeof setDirty === 'function') setDirty(false);
        });
      }
    },
    async deleteQRCode(id) {
      const isConfirmed = window.confirm("このQRコードを本当に削除しますか？\nこの操作は元に戻せません。");
      if (isConfirmed) {
        this.savedQRCodes = this.savedQRCodes.filter((qr) => qr.id !== id);
        await this.persistSavedQRCodes();
        if (typeof setDirty === 'function') setDirty(true);

        if (this.currentPage > this.totalPages) {
          this.currentPage = Math.max(1, this.totalPages);
        }

        this.showFlashNotification("QRコードを削除しました。");
      }
    },
    async duplicateQRCode(id) {
      const originalQr = this.savedQRCodes.find((qr) => qr.id === id);
      if (originalQr) {
        // ディープコピー時のOOMクラッシュ対策とProxyの回避
        const rawOriginalQr = window.Alpine.raw(originalQr);
        const { qrOptions, ...restQr } = rawOriginalQr;
        const { logo, ...restOptions } = qrOptions;

        const newQr = JSON.parse(JSON.stringify(restQr));
        newQr.qrOptions = JSON.parse(JSON.stringify(restOptions));
        newQr.qrOptions.logo = logo;

        newQr.id = this.generateUniqueId();
        newQr.name = `${originalQr.name} (コピー)`;
        newQr.memo = originalQr.memo || "";
        newQr.tags = originalQr.tags ? [...originalQr.tags] : [];
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
        this.showFlashNotification("QRコードを複製しました。");
      }
    },
    prepareDownloadFromDashboard(qr) {
      this.editQRCode(qr.id);
      this.download.fileName = qr.name;
      this.download.format = 'png';
      this.download.size = 1024;
      this.showDownloadModal = true;
    },
    async openShareModal(qr) {
      this.qrToShare = qr;

      // Web Share API (File) が使える場合は、画像を直接ネイティブ共有する
      if (navigator.share && navigator.canShare) {
        try {
          const blob = await this.svgDataUrlToPngBlob(qr.previewSvgUrl, 512);
          const file = new File([blob], `${qr.name || 'qrcode'}.png`, { type: 'image/png' });

          if (navigator.canShare({ files: [file] })) {
            await navigator.share({
              title: qr.name,
              text: `「${qr.name}」のQRコード`,
              files: [file],
            });
            return; // 共有成功時はモーダルを開かずに終了
          }
        } catch (error) {
          if (error.name !== 'AbortError') {
             console.error("画像共有に失敗しました", error);
          } else {
             return; // ユーザーキャンセル時
          }
        }
      }

      // APIが非対応、または失敗した場合はフォールバックとしてモーダルを開く
      this.showShareModal = true;
    },
    getShareDataText(qr) {
      const dataStringContext = {
        selectedType: qr.type,
        formData: qr.formData,
      };
      return this.getQrDataString.call(dataStringContext);
    },
    async svgDataUrlToPngBlob(svgDataUrl, size = 512) {
      return new Promise(async (resolve, reject) => {
        try {
          let svgString = "";
          if (svgDataUrl.includes("base64,")) {
            const binStr = atob(svgDataUrl.split("base64,")[1]);
            const bytes = new Uint8Array(binStr.length);
            for (let i = 0; i < binStr.length; i++) {
              bytes[i] = binStr.charCodeAt(i);
            }
            svgString = new TextDecoder('utf-8').decode(bytes); // UTF-8として正しくデコード
          } else if (svgDataUrl.includes(",")) {
            svgString = decodeURIComponent(svgDataUrl.split(",")[1]);
          }

          if (svgString) {
            // 🔥 シェア用のプレビュー画像生成時にも crossorigin を削除してエラーを防ぐ
            svgString = svgString.replace(/crossorigin="[^"]*"/gi, "");
            svgString = svgString.replace(/crossOrigin="[^"]*"/gi, "");
            const blob = new Blob([svgString], { type: "image/svg+xml;charset=utf-8" });
            svgDataUrl = URL.createObjectURL(blob);
          }

          const image = new Image();
          image.onload = () => {
            const canvas = document.createElement("canvas");
            canvas.width = size;
            canvas.height = size;
            const ctx = canvas.getContext("2d");
            ctx.fillStyle = "#ffffff";
            ctx.fillRect(0, 0, size, size);
            ctx.drawImage(image, 0, 0, size, size);
            canvas.toBlob((blob) => {
              if (svgDataUrl.startsWith("blob:")) URL.revokeObjectURL(svgDataUrl);
              if (blob) resolve(blob);
              else reject(new Error("Blob conversion failed"));
            }, "image/png");
          };
          image.onerror = () => {
            if (svgDataUrl.startsWith("blob:")) URL.revokeObjectURL(svgDataUrl);
            reject(new Error("SVG Rendering Error"));
          };
          image.src = svgDataUrl;
        } catch (e) {
          reject(e);
        }
      });
    },
    async copyShareImage(qr) {
      if (!window.ClipboardItem) {
        this.showFlashNotification("お使いのブラウザは画像のコピーに対応していません。");
        return;
      }
      try {
        const clipboardItem = new window.ClipboardItem({
          "image/png": this.svgDataUrlToPngBlob(qr.previewSvgUrl, 512)
        });
        await navigator.clipboard.write([clipboardItem]);
        this.showFlashNotification("画像をクリップボードにコピーしました！");
        this.hapticFeedback('success');
      } catch (e) {
        console.error("画像コピー失敗", e);
        this.showFlashNotification("画像のコピーに失敗しました。");
      }
    },
    toggleQuietZone() {
      this.includeQuietZone = !this.includeQuietZone;
      this.qrOptions.margin = this.includeQuietZone ? 4 : 0;
      this.updateQrCode();
    },
    async selectBrandLogo(logoUrl) {
      try {
        const response = await fetch(logoUrl);
        const blob = await response.blob();
        const reader = new FileReader();
        reader.onloadend = () => {
          this.brandKit.logo = reader.result;
          this.qrOptions.logo = reader.result;
          this.logoFileName = logoUrl.split('/').pop();
          this.updateQrCode();
          this.saveBrandKit();
        };
        reader.readAsDataURL(blob);
      } catch (error) {
        console.error("ロゴの取得に失敗しました", error);
        this.showFlashNotification("ロゴの読み込みに失敗しました。");
      }
    },
    removeBrandLogo() {
      this.brandKit.logo = null;
      this.qrOptions.logo = "";
      this.logoFileName = "";
      this.updateQrCode();
      this.saveBrandKit();

      const fileInput = document.getElementById("brand-logo-upload");
      if (fileInput) fileInput.value = "";
    },
    handleBrandLogoUpload(event) {
      const file = event.target.files[0];
      if (!file) return;

      if (file.type === "image/svg+xml" && file.size > 500 * 1024) {
        this.showFlashNotification("SVGロゴは複雑すぎると処理が重くなるため、500KB以下のファイルを選択してください。");
        event.target.value = null;
        return;
      }

      if (file.size > 2 * 1024 * 1024) {
        this.showFlashNotification("ブランドロゴは2MB以下のファイルを選択してください。");
        event.target.value = null;
        return;
      }

      const reader = new FileReader();
      reader.onload = (e) => {
        this.brandKit.logo = e.target.result;
        this.qrOptions.logo = e.target.result;
        this.logoFileName = file.name;
        this.updateQrCode();
        this.saveBrandKit();
      };
      reader.readAsDataURL(file);
    },
    saveBrandKit(showNotification = true) {
      try {
        localStorage.setItem("qrBrandKit", JSON.stringify(this.brandKit));
        if (showNotification) {
          this.showFlashNotification("ブランドキットを更新しました。");
        }
      } catch (e) {
        this.showFlashNotification("容量制限のため、ブランド設定を保存できませんでした。");
      }
    },
    loadBrandKit() {
      try {
        const kit = localStorage.getItem("qrBrandKit");
        if (kit) {
          this.brandKit = JSON.parse(kit);
          // 不正なロゴのクリーンアップ
          if (this.brandKit.logo && !this.brandKit.logo.startsWith("data:")) {
             this.brandKit.logo = null;
             this.saveBrandKit(false);
          }
        }
      } catch (e) {
        console.warn("ブランドキットの読み込みに失敗しました", e);
        localStorage.removeItem("qrBrandKit");
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
