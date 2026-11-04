import React, { useEffect, useState } from "react";
import { Button, Placeholder } from "@telegram-apps/telegram-ui";
import { ClipboardPaste, Copy, RefreshCw, ScanLine } from "lucide-react";
import QRCode from "qrcode";
import {
  scan,
  Format,
  checkPermissions,
  requestPermissions,
} from "@tauri-apps/plugin-barcode-scanner";
import { api } from "../api";
import { t } from "../i18n";

/** 相机扫码只在移动端有实现；桌面端没这个插件本体。 */
const CAN_SCAN =
  typeof navigator !== "undefined" && /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);

export default function MyIdPage({ onClose, onAdded, notify }) {
  const [connId, setConnId] = useState("");
  const [myId, setMyId] = useState("");
  const [qr, setQr] = useState("");
  const [invite, setInvite] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  // 生成邀请 = 在 mailbox 上建一条接收队列，把地址 + 写权限给对方。
  const refresh = async () => {
    setBusy(true);
    try {
      const mailboxes = await api.mailboxPeers();
      if (!mailboxes || mailboxes.length === 0) {
        notify(t("noMailbox"), "err");
        return;
      }
      const [id, text] = await api.createConnection(mailboxes[0]);
      setConnId(id);
      setMyId(text);
      setQr(await QRCode.toDataURL(text, { width: 220, margin: 1 }));
    } catch (e) {
      notify(String(e), "err");
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(myId);
      notify(t("copied"));
    } catch {
      notify(t("copied"));
    }
  };

  const connectWith = async (value) => {
    const text = (value ?? invite).trim();
    if (!text) return false;
    if (!connId) {
      notify(t("refreshId"), "err");
      return false;
    }
    setBusy(true);
    try {
      await api.acceptConnection(connId, text);
      if (name.trim()) await api.renameConnection(connId, name.trim());
      notify(t("saveOk"));
      onAdded?.();
      return true;
    } catch (e) {
      notify(String(e), "err");
      return false;
    } finally {
      setBusy(false);
    }
  };

  const connect = () => connectWith(invite);

  /** 移动端扫码：扫到就填进输入框并直接连上。 */
  const scanAndConnect = async () => {
    setBusy(true);
    try {
      const current = await checkPermissions();
      const permission =
        current === "granted" ? current : await requestPermissions();
      if (permission !== "granted") {
        notify(t("cameraDenied"), "err");
        return;
      }
      const result = await scan({ windowed: false, formats: [Format.QRCode] });
      const text = (result?.content || "").trim();
      if (!text) {
        notify(t("scanFailed"), "err");
        return;
      }
      setInvite(text);
      await connectWith(text);
    } catch (e) {
      const message = String(e ?? "");
      if (/cancel/i.test(message)) return; // 用户按返回键取消，不提示
      // 扫码用的是 ML Kit，没有 Google 服务的机器会直接失败。
      if (/mlkit|ml kit|google|play services|gms/i.test(message)) {
        notify(t("scanNeedsGms"), "err");
        return;
      }
      notify(message || t("scanFailed"), "err");
    } finally {
      setBusy(false);
    }
  };

  /** 扫不了（没相机 / 没 Google 服务）时的退路：从剪贴板粘贴。 */
  const pasteInvite = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (!text || !text.trim()) {
        notify(t("scanFailed"), "err");
        return;
      }
      setInvite(text.trim());
    } catch {
      notify(t("pasteFailed"), "err");
    }
  };

  return (
    <div className="page">
      <header className="page-head">
        <div className="page-title">{t("profile")}</div>
      </header>

      <div className="id-card">
        {qr ? <img src={qr} alt="QR" className="qr" /> : <Placeholder description={t("myId")} />}
        <div className="id-value mono">{myId}</div>
        <Button stretched mode="bezeled" onClick={copy} before={<Copy size={18} />}>{t("copyId")}</Button>
        <Button stretched mode="plain" loading={busy} onClick={refresh} before={<RefreshCw size={18} />}>{t("refreshId")}</Button>
      </div>

      <div className="add-block">
        <input
          className="plain-input mono"
          placeholder={t("inviteHint")}
          value={invite}
          onChange={(e) => setInvite(e.target.value)}
        />
        <input
          className="plain-input"
          placeholder={t("name")}
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <Button
          stretched
          mode="plain"
          disabled={busy}
          onClick={pasteInvite}
          before={<ClipboardPaste size={18} />}
        >
          {t("pasteInvite")}
        </Button>
        {CAN_SCAN && (
          <Button
            stretched
            mode="bezeled"
            disabled={busy}
            onClick={scanAndConnect}
            before={<ScanLine size={18} />}
          >
            {t("scanQr")}
          </Button>
        )}
        <Button stretched mode="filled" loading={busy} onClick={connect}>
          {t("connect")}
        </Button>
      </div>
    </div>
  );
}
