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

import PasswordModal from "./PasswordModal";

export default function SettingsMain({ notify, onLocked, onOpenMailbox, onOpenOnion }) {
  const [autoLock, setAutoLock] = useState(0);
  const [mailboxCount, setMailboxCount] = useState(null);
  const [pwModal, setPwModal] = useState(false);
  const [lockModal, setLockModal] = useState(false);
  const [langModal, setLangModal] = useState(false);
  const [onionOn, setOnionOn] = useState(false);

  useEffect(() => {
    api.autoLock().then(setAutoLock).catch(() => {});
    api.mailboxPeers().then((p) => setMailboxCount(p.length)).catch(() => {});
    api.getOnion().then((c) => setOnionOn(!!c?.enabled)).catch(() => {});
  }, []);

  const chooseAutoLock = async (minutes) => {
    setAutoLock(minutes);
    setLockModal(false);
    try {
      await api.setAutoLock(minutes);
      notify(t("saveOk"));
    } catch (e) {
      notify(String(e), "err");
    }
  };

  const lock = async () => {
    try {
      await api.lockVault();
      onLocked?.();
    } catch (e) {
      notify(String(e), "err");
    }
  };

  const exportDiag = async () => {
    try {
      await api.diagnostics();
      notify(t("exported"));
    } catch (e) {
      notify(String(e), "err");
    }
  };

  const setLanguage = (loc) => {
    localStorage.setItem("privchat_locale", loc);
    setLangModal(false);
    window.location.reload();
  };

  const autoLockText = autoLock === 0 ? t("never") : `${autoLock} min`;

  return (
    <div className="page">
      <header className="page-head">
        <div className="page-title">{t("settings")}</div>
      </header>

      <div className="scroll">
        <Group title={t("network")}>
          <Cell
            before={<span className="cell-icon" style={{ background: "#3390ec" }}><Mail size={18} /></span>}
            subtitle={
              mailboxCount === null
                ? t("mailboxHint")
                : mailboxCount === 0
                  ? t("mailboxNone")
                  : locale === "zh"
                    ? `${mailboxCount} 个节点`
                    : `${mailboxCount} ${mailboxCount === 1 ? "node" : "nodes"}`
            }
            onClick={onOpenMailbox}
            after={<ChevronRight size={18} color="#c4c4c6" />}
          >
            {t("mailbox")}
          </Cell>
          <Cell
            before={<span className="cell-icon" style={{ background: "#8e5bd0" }}><Waypoints size={18} /></span>}
            subtitle={onionOn ? t("on") : t("off")}
            onClick={onOpenOnion}
            after={<ChevronRight size={18} color="#c4c4c6" />}
          >
            {t("onion")}
          </Cell>
        </Group>

        <Group title={t("privacy")}>
          <Cell
            before={<span className="cell-icon" style={{ background: "#4fae4e" }}><Clock size={18} /></span>}
            subtitle={`${t("autoLockHint2")} · ${autoLockText}`}
            onClick={() => setLockModal(true)}
            after={<ChevronRight size={18} color="#c4c4c6" />}
          >
            {t("autoLock")}
          </Cell>
          <Cell
            before={<span className="cell-icon" style={{ background: "#ef8f36" }}><KeyRound size={18} /></span>}
            onClick={() => setPwModal(true)}
            after={<ChevronRight size={18} color="#c4c4c6" />}
          >
            {t("password")}
          </Cell>
          <Cell
            before={<span className="cell-icon" style={{ background: "#df3e3e" }}><Lock size={18} /></span>}
            onClick={lock}
          >
            {t("lock")}
          </Cell>
        </Group>

        <Group title={t("appearance")}>
          <Cell
            before={<span className="cell-icon" style={{ background: "#6ab3f3" }}><Globe size={18} /></span>}
            subtitle={locale === "en" ? "English" : "中文"}
            onClick={() => setLangModal(true)}
            after={<ChevronRight size={18} color="#c4c4c6" />}
          >
            {t("language")}
          </Cell>
        </Group>

        <Group title={t("other")}>
          <Cell
            before={<span className="cell-icon" style={{ background: "#7d8e9e" }}><FileDown size={18} /></span>}
            subtitle={t("diagnosticsHint")}
            onClick={exportDiag}
          >
            {t("diagnostics")}
          </Cell>
          <Cell
            before={<span className="cell-icon" style={{ background: "#9aa0a6" }}><Info size={18} /></span>}
            after="0.1.0"
          >
            {t("version")}
          </Cell>
        </Group>
      </div>

      <PasswordModal open={pwModal} onClose={() => setPwModal(false)} notify={notify} />

      <Modal open={lockModal} onOpenChange={(v) => !v && setLockModal(false)}>
        <div className="modal-card">
          <h3>{t("autoLock")}</h3>
          {[0, 1, 5].map((m) => (
            <button
              key={m}
              className={`option-row ${autoLock === m ? "selected" : ""}`}
              onClick={() => chooseAutoLock(m)}
            >
              {m === 0 ? t("never") : `${m} min`}
              {autoLock === m && <Check size={18} />}
            </button>
          ))}
        </div>
      </Modal>

      <Modal open={langModal} onOpenChange={(v) => !v && setLangModal(false)}>
        <div className="modal-card">
          <h3>{t("language")}</h3>
          {[{ k: "zh", label: "中文" }, { k: "en", label: "English" }].map((o) => (
            <button
              key={o.k}
              className={`option-row ${locale === o.k ? "selected" : ""}`}
              onClick={() => setLanguage(o.k)}
            >
              {o.label}
              {locale === o.k && <Check size={18} />}
            </button>
          ))}
        </div>
      </Modal>
    </div>
  );
}
