import React, { useEffect, useMemo, useState } from "react";
import { Button, Placeholder } from "@telegram-apps/telegram-ui";
import { ArrowLeft, Gauge, Mail, X } from "lucide-react";
import { api } from "../../api";
import { t } from "../../i18n";

const PEER_RE = /^[0-9a-fA-F]{64}$/;
const PRIORITIES = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

function shortId(id) {
  return id.length > 18 ? `${id.slice(0, 10)}…${id.slice(-6)}` : id;
}

export default function MailboxPage({ notify, onClose }) {
  const [peers, setPeers] = useState([]);
  const [input, setInput] = useState("");
  const [priority, setPriority] = useState(0);
  const [health, setHealth] = useState({});
  const [testing, setTesting] = useState(false);

  const load = async () => {
    try {
      setPeers(await api.mailboxPeers());
    } catch (e) {
      notify(String(e), "err");
    }
  };

  useEffect(() => {
    load();
  }, []);

  const add = async () => {
    const id = input.trim();
    if (!PEER_RE.test(id)) {
      notify(t("invalidId"), "err");
      return;
    }
    try {
      await api.addMailbox(id, priority);
      setInput("");
      await load();
    } catch (e) {
      notify(String(e), "err");
    }
  };

  const remove = async (id) => {
    try {
      await api.removeMailbox(id);
      setHealth((h) => {
        const next = { ...h };
        delete next[id];
        return next;
      });
      await load();
    } catch (e) {
      notify(String(e), "err");
    }
  };

  const ping = async (id) => {
    setHealth((h) => ({ ...h, [id]: { testing: true } }));
    try {
      const ms = await api.pingMailbox(id);
      setHealth((h) => ({ ...h, [id]: { ms } }));
    } catch (e) {
      setHealth((h) => ({ ...h, [id]: { err: String(e) } }));
    }
  };

  /// 一次测完所有节点，同优先级自动挑最快的那台。
  const pingAll = async () => {
    if (peers.length === 0) return;
    setTesting(true);
    setHealth(Object.fromEntries(peers.map((p) => [p.peer_id, { testing: true }])));
    try {
      const results = await api.pingMailboxes();
      const next = {};
      for (const r of results || []) {
        next[r.peer_id] = r.ms != null ? { ms: r.ms } : { err: r.error || "timeout" };
      }
      setHealth(next);
    } catch (e) {
      notify(String(e), "err");
    } finally {
      setTesting(false);
    }
  };

  const changePriority = async (id, value) => {
    try {
      await api.setMailboxPriority(id, Number(value));
      await load();
    } catch (e) {
      notify(String(e), "err");
    }
  };

  const fastest = useMemo(() => {
    let best = null;
    for (const [id, h] of Object.entries(health)) {
      if (h?.ms != null && (best == null || h.ms < best.ms)) best = { id, ms: h.ms };
    }
    return best;
  }, [health]);

  const latency = (id) => {
    const h = health[id];
    if (!h) return <span className="lat-badge idle">{t("untested")}</span>;
    if (h.testing) return <span className="lat-badge idle">{t("testing")}</span>;
    if (h.ms != null) {
      const best = fastest?.id === id ? " best" : "";
      return <span className={`lat-badge ok${best}`}>{h.ms} ms</span>;
    }
    return <span className="lat-badge bad">{t("offline")}</span>;
  };

  return (
    <div className="page">
      <header className="page-head">
        <button className="head-icon" onClick={onClose} aria-label={t("back")}>
          <ArrowLeft size={22} />
        </button>
        <div className="page-title">{t("mailbox")}</div>
        <Button size="s" mode="plain" loading={testing} onClick={pingAll}>
          {t("testAll")}
        </Button>
      </header>

      <div className="scroll">
        <div className="form-row inset">
          <input
            className="plain-input grow mono"
            placeholder={t("peerId")}
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
          <select
            className="tg-select priority-select"
            value={priority}
            onChange={(e) => setPriority(Number(e.target.value))}
            aria-label={t("priority")}
          >
            {PRIORITIES.map((n) => (
              <option key={n} value={n}>
                {t("priority")} {n}
              </option>
            ))}
          </select>
          <Button mode="filled" onClick={add}>
            {t("addBtn")}
          </Button>
        </div>

        <div className="hint-line">{t("priorityHint")}</div>

        <div className="group-card mailbox-card">
          {peers.length === 0 && <Placeholder description={t("mailboxHint")} />}
          {peers.map((peer, i) => (
            <div className="peer-row" key={peer.peer_id}>
              <span className="peer-icon">
                <Mail size={16} />
              </span>
              <div className="peer-main">
                <div className="peer-id mono">
                  <span className="peer-index">{i + 1}</span>
                  {shortId(peer.peer_id)}
                </div>
                <div className="peer-meta">
                  <span className="peer-priority">
                    {t("priority")}
                    <select
                      className="tg-select priority-select small"
                      value={peer.priority}
                      onChange={(e) => changePriority(peer.peer_id, e.target.value)}
                    >
                      {PRIORITIES.map((n) => (
                        <option key={n} value={n}>
                          {n}
                        </option>
                      ))}
                    </select>
                  </span>
                  {latency(peer.peer_id)}
                </div>
              </div>
              <div className="row-actions">
                <button
                  className="row-icon"
                  onClick={() => ping(peer.peer_id)}
                  aria-label={t("testSpeed")}
                  title={t("testSpeed")}
                >
                  <Gauge size={18} />
                </button>
                <button
                  className="row-icon"
                  onClick={() => remove(peer.peer_id)}
                  aria-label={t("remove")}
                >
                  <X size={18} />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
