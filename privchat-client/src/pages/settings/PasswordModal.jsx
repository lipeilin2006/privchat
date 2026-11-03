import React, { useEffect, useState } from "react";
import {
  List,
  Cell,
  Button,
  Switch,
  Modal,
  Placeholder,
} from "@telegram-apps/telegram-ui";
import {
  ArrowLeft,
  Mail,
  Waypoints,
  Clock,
  KeyRound,
  Lock,
  Info,
  ChevronUp,
  ChevronDown,
  X,
  Activity,
  ChevronRight,
  Globe,
  FileDown,
  Check,
} from "lucide-react";
import Group from "../../components/Group";
import { api } from "../../api";
import { t, locale } from "../../i18n";

const RELAY_RE = /^[0-9a-fA-F]{64}$/;


export default function PasswordModal({ open, onClose, notify }) {
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (!oldPw || !newPw || newPw !== confirm) {
      notify("密码不一致", "err");
      return;
    }
    setBusy(true);
    try {
      await api.changePassword(oldPw, newPw);
      notify(t("saveOk"));
      onClose();
    } catch (e) {
      notify(String(e), "err");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal open={open} onOpenChange={(v) => !v && onClose()}>
      <div className="modal-card">
        <h3>{t("password")}</h3>
        <input className="plain-input" type="password" placeholder="当前密码" value={oldPw} onChange={(e) => setOldPw(e.target.value)} />
        <input className="plain-input" type="password" placeholder="新密码" value={newPw} onChange={(e) => setNewPw(e.target.value)} />
        <input className="plain-input" type="password" placeholder="确认新密码" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        <div className="modal-actions">
          <Button mode="plain" onClick={onClose}>{t("cancel")}</Button>
          <Button mode="filled" loading={busy} onClick={submit}>{t("save")}</Button>
        </div>
      </div>
    </Modal>
  );
}
