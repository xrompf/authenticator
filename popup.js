let accounts = [];
let searchQuery = "";
let copiedId = null;

// --- 1. Base32 & RFC 6238 TOTP Engine ---
function base32ToBytes(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = base32.toUpperCase().replace(/=+$/, "").replace(/\s+/g, "");
  let bits = "";
  for (const char of cleaned) {
    const val = alphabet.indexOf(char);
    if (val === -1) throw new Error("Invalid Base32");
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  return bytes;
}

async function generateTOTP(secret, period = 30, digits = 6) {
  const keyBytes = base32ToBytes(secret);
  const timeStep = Math.floor(Date.now() / 1000 / period);
  const buffer = new ArrayBuffer(8);
  new DataView(buffer).setUint32(4, timeStep, false);

  const key = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
  );
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, buffer));
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = (binary % Math.pow(10, digits)).toString().padStart(digits, "0");
  return `${otp.slice(0, 3)} ${otp.slice(3)}`;
}

// --- 2. Parse otpauth:// URI ---
function parseOtpAuthUri(uri) {
  const url = new URL(uri);
  if (url.protocol !== "otpauth:") throw new Error("Not an otpauth URI");

  const rawLabel = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
  const [labelIssuer, accountName] = rawLabel.includes(":")
    ? rawLabel.split(":")
    : ["", rawLabel];

  const secret = url.searchParams.get("secret");
  const issuer = url.searchParams.get("issuer") || labelIssuer || "Unknown";
  if (!secret) throw new Error("Missing secret in QR code");

  return {
    id: Date.now() + Math.random(),
    issuer: issuer.trim(),
    account: (accountName || "").trim(),
    secret: secret.trim().toUpperCase()
  };
}

// --- 3. Scan QR Code Directly From Active Browser Tab ---
document.getElementById("scanQrBtn").addEventListener("click", async () => {
  try {
    if (!("BarcodeDetector" in window)) {
      return showStatus("BarcodeDetector not supported in this browser.");
    }
    const dataUrl = await chrome.tabs.captureVisibleTab(null, { format: "png" });
    const img = new Image();
    img.src = dataUrl;
    await img.decode();

    const detector = new BarcodeDetector({ formats: ["qr_code"] });
    const codes = await detector.detect(img);

    if (!codes.length) return showStatus("No QR code found on screen.");

    const parsed = parseOtpAuthUri(codes[0].rawValue);
    accounts.push(parsed);
    await saveAccounts();
    render();
    showStatus(`Added ${parsed.issuer}!`);
  } catch (err) {
    showStatus("QR Scan failed: " + err.message);
  }
});

// --- 4. Storage Helpers (chrome.storage.local with localStorage fallback) ---
async function loadAccounts() {
  if (typeof chrome !== "undefined" && chrome.storage) {
    const res = await chrome.storage.local.get(["accounts"]);
    accounts = res.accounts || [];
  } else {
    accounts = JSON.parse(localStorage.getItem("accounts") || "[]");
  }
}

async function saveAccounts() {
  if (typeof chrome !== "undefined" && chrome.storage) {
    await chrome.storage.local.set({ accounts });
  } else {
    localStorage.setItem("accounts", JSON.stringify(accounts));
  }
}

// --- 5. Encrypted Backup & Restore (AES-GCM + PBKDF2) ---
async function encryptData(text, password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
  );
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(text));
  return JSON.stringify({
    encrypted: true,
    salt: Array.from(salt),
    iv: Array.from(iv),
    data: Array.from(new Uint8Array(cipher))
  });
}

async function decryptData(payload, password) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: new Uint8Array(payload.salt), iterations: 100000, hash: "SHA-256" },
    baseKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
  );
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(payload.iv) },
    aesKey, new Uint8Array(payload.data)
  );
  return new TextDecoder().decode(plain);
}

document.getElementById("exportBtn").addEventListener("click", async () => {
  const pass = document.getElementById("backupPass").value;
  const raw = JSON.stringify(accounts, null, 2);
  const output = pass ? await encryptData(raw, pass) : raw;

  const blob = new Blob([output], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "authenticator-backup.json";
  a.click();
});

document.getElementById("importBtn").addEventListener("click", () => {
  document.getElementById("importFile").click();
});

document.getElementById("importFile").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const parsed = JSON.parse(await file.text());
    let imported = parsed;
    if (parsed.encrypted) {
      const pass = document.getElementById("backupPass").value;
      if (!pass) return showStatus("Enter password to decrypt backup.");
      imported = JSON.parse(await decryptData(parsed, pass));
    }
    accounts = [...accounts, ...imported];
    await saveAccounts();
    render();
    showStatus(`Imported ${imported.length} accounts.`);
  } catch {
    showStatus("Failed to import backup (check password).");
  }
});

// --- 6. UI Rendering & Shortcuts ---
async function render() {
  const list = document.getElementById("accountList");
  const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
  const circumference = 2 * Math.PI * 9;
  const dashOffset = circumference * (1 - remaining / 30);

  const filtered = accounts.filter((a) =>
    `${a.issuer} ${a.account}`.toLowerCase().includes(searchQuery.toLowerCase())
  );

  list.innerHTML = "";
  for (const acc of filtered) {
    let code = "INVALID";
    try { code = await generateTOTP(acc.secret); } catch {}

    const item = document.createElement("div");
    item.className = "account-item";
    const isCopied = copiedId === acc.id;

    item.innerHTML = `
      <div>
        <div class="issuer">${acc.issuer}</div>
        ${acc.account ? `<div class="account-name">${acc.account}</div>` : ""}
        <div class="otp-code ${isCopied ? "copied" : ""}">${isCopied ? "Copied!" : code}</div>
      </div>
      <div class="ring-wrap">
        <svg class="countdown">
          <circle class="ring-bg" cx="12" cy="12" r="9"></circle>
          <circle class="ring-fg ${remaining <= 5 ? "expiring" : ""}"
            cx="12" cy="12" r="9"
            stroke-dasharray="${circumference}"
            stroke-dashoffset="${dashOffset}"></circle>
        </svg>
        <button class="del-btn" data-id="${acc.id}" title="Remove">&times;</button>
      </div>
    `;

    item.addEventListener("click", (e) => {
      if (e.target.classList.contains("del-btn")) return;
      navigator.clipboard.writeText(code.replace(/\s+/g, ""));
      copiedId = acc.id;
      render();
      setTimeout(() => { copiedId = null; render(); }, 1200);
    });

    item.querySelector(".del-btn").addEventListener("click", async () => {
      accounts = accounts.filter((x) => x.id !== acc.id);
      await saveAccounts();
      render();
    });

    list.appendChild(item);
  }
}

function showStatus(msg) {
  const el = document.getElementById("statusMsg");
  el.textContent = msg;
  el.style.display = "block";
  setTimeout(() => { el.style.display = "none"; }, 3000);
}

// Drawer toggles & '/' search hotkey
document.getElementById("toggleAddBtn").onclick = () =>
  document.getElementById("addDrawer").classList.toggle("open");
document.getElementById("toggleBackupBtn").onclick = () =>
  document.getElementById("backupDrawer").classList.toggle("open");

document.getElementById("addDrawer").addEventListener("submit", async (e) => {
  e.preventDefault();
  accounts.push({
    id: Date.now(),
    issuer: document.getElementById("issuerInput").value.trim(),
    account: document.getElementById("labelInput").value.trim(),
    secret: document.getElementById("secretInput").value.trim().toUpperCase()
  });
  await saveAccounts();
  e.target.reset();
  document.getElementById("addDrawer").classList.remove("open");
  render();
});

document.getElementById("searchInput").addEventListener("input", (e) => {
  searchQuery = e.target.value;
  render();
});

document.addEventListener("keydown", (e) => {
  if (e.key === "/" && document.activeElement.tagName !== "INPUT") {
    e.preventDefault();
    document.getElementById("searchInput").focus();
  }
});

(async function init() {
  await loadAccounts();
  render();
  setInterval(render, 1000);
})();
