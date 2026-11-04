import React, { useEffect, useState } from "react";
import { Button, Placeholder } from "@telegram-apps/telegram-ui";
import { Copy, RefreshCw } from "lucide-react";
import QRCode from "qrcode";
import { api } from "../api";
import { t } from "../i18n";

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
      // 在所有已配置节点上建同一队列（多副本）。
      const [id, text] = await api.createConnection();
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

  const connect = async () => {
    if (!invite.trim()) return;
    if (!connId) {
      notify(t("refreshId"), "err");
      return;
    }
    setBusy(true);
    try {
      await api.acceptConnection(connId, invite.trim());
      if (name.trim()) await api.renameConnection(connId, name.trim());
      notify(t("saveOk"));
      onAdded?.();
    } catch (e) {
      notify(String(e), "err");
    } finally {
      setBusy(false);
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
          className="plain-input"
          placeholder={t("peerId")}
          value={invite}
          onChange={(e) => setInvite(e.target.value)}
        />
        <input
          className="plain-input"
          placeholder={t("name")}
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <Button stretched mode="filled" loading={busy} onClick={connect}>
          {t("connect")}
        </Button>
      </div>
    </div>
  );
}
