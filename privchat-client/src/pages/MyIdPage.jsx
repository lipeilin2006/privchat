import React, { useEffect, useState } from "react";
import { Button, Placeholder } from "@telegram-apps/telegram-ui";
import { Copy, RefreshCw } from "lucide-react";
import QRCode from "qrcode";
import { api } from "../api";
import { t } from "../i18n";

export default function MyIdPage({ onClose, onAdded, notify }) {
  const [myId, setMyId] = useState("");
  const [qr, setQr] = useState("");
  const [invite, setInvite] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = async () => {
    setBusy(true);
    try {
      const ticket = await api.selfTicket();
      setMyId(ticket);
      setQr(await QRCode.toDataURL(ticket, { width: 220, margin: 1 }));
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
    setBusy(true);
    try {
      await api.connectPeer(invite.trim(), name.trim() || null);
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
