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


export default function MailboxPage({ notify, onClose }) {
  const [peers, setPeers] = useState([]);
  const [input, setInput] = useState("");
  const [count, setCount] = useState(0);
  const [health, setHealth] = useState({});

  const load = async () => {
    try {
      setPeers(await api.mailboxPeers());
      setCount(await api.getWriteCount());
    } catch (e) {
      notify(String(e), "err");
    }
  };

  useEffect(() => {
    load();
  }, []);

  const add = async () => {
    const id = input.trim();
    if (!RELAY_RE.test(id)) {
      notify(t("invalidId"), "err");
      return;
    }
    try {
      await api.addMailbox(id);
      setInput("");
      await load();
    } catch (e) {
      notify(String(e), "err");
    }
  };

  const remove = async (id) => {
    try {
      await api.removeMailbox(id);
      await load();
    } catch (e) {
      notify(String(e), "err");
    }
  };

  const ping = async (id) => {
    try {
      const ms = await api.pingMailbox(id);
      setHealth((h) => ({ ...h, [id]: { ok: true, ms } }));
    } catch (e) {
      setHealth((h) => ({ ...h, [id]: { ok: false, msg: String(e) } }));
    }
  };

  return (
    <div className="page">
      <header className="page-head">
        <button className="head-icon" onClick={onClose} aria-label={t("back")}>
          <ArrowLeft size={22} />
        </button>
        <div className="page-title">{t("mailbox")}</div>
      </header>

      <div className="scroll">
        <div className="form-row inset">
          <input
            className="plain-input grow"
            placeholder={t("peerId")}
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
          <Button mode="filled" onClick={add}>{t("addBtn")}</Button>
        </div>

        <div className="group-card mailbox-card">
          {peers.length === 0 && <Placeholder description={t("mailboxHint")} />}
          {peers.map((p) => (
            <Cell
              key={p}
              subtitle={health[p] ? (health[p].ok ? `${t("online")} · ${health[p].ms} ms` : t("offline")) : p.slice(0, 18) + "…"}
              after={
                <div className="row-actions">
                  <button className="row-icon" onClick={() => ping(p)} aria-label={t("ping")}>
                    <Activity size={18} />
                  </button>
                  <button className="row-icon" onClick={() => remove(p)} aria-label={t("remove")}>
                    <X size={18} />
                  </button>
                </div>
              }
            >
              {p.slice(0, 10)}…{p.slice(-6)}
            </Cell>
          ))}
        </div>

        <Group title={t("writeCount")}>
          <Cell
            after={
              <select
                className="tg-select"
                value={count}
                onChange={async (e) => {
                  const v = Number(e.target.value);
                  setCount(v);
                  try {
                    await api.setWriteCount(v);
                  } catch (err) {
                    notify(String(err), "err");
                  }
                }}
              >
                <option value={0}>{t("copiesAll")}</option>
                {[1, 2, 3, 4, 5, 6, 8].map((n) => (
                  <option key={n} value={n}>{n}</option>
                ))}
              </select>
            }
          >
            {t("copies")}
          </Cell>
        </Group>
      </div>
    </div>
  );
}
