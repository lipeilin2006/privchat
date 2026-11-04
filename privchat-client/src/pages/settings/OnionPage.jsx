import React, { useEffect, useState } from "react";
import { Button, Cell, Switch, Placeholder } from "@telegram-apps/telegram-ui";
import {
  ArrowLeft,
  Waypoints,
  ChevronUp,
  ChevronDown,
  X,
  ShieldCheck,
} from "lucide-react";
import Group from "../../components/Group";
import { api } from "../../api";
import { t } from "../../i18n";

const RELAY_RE = /^[0-9a-fA-F]{64}$/;

function shortId(id) {
  return id.length > 18 ? `${id.slice(0, 10)}…${id.slice(-6)}` : id;
}

export default function OnionPage({ notify, onClose }) {
  const [cfg, setCfg] = useState({ enabled: false, relays: [] });
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .getOnion()
      .then((c) =>
        setCfg({
          enabled: !!c?.enabled,
          relays: Array.isArray(c?.relays) ? [...c.relays] : [],
        })
      )
      .catch(() => {});
  }, []);

  const save = async () => {
    if (cfg.enabled && cfg.relays.length === 0) {
      notify(t("noRelays"), "err");
      return;
    }
    setBusy(true);
    try {
      await api.setOnion(cfg);
      notify(t("saveOk"));
    } catch (e) {
      notify(String(e), "err");
    } finally {
      setBusy(false);
    }
  };

  const add = () => {
    const id = input.trim();
    if (!RELAY_RE.test(id)) return notify(t("invalidId"), "err");
    if (cfg.relays.includes(id)) return notify(t("relayExists"), "err");
    setCfg((c) => ({ ...c, relays: [...c.relays, id] }));
    setInput("");
  };

  const move = (i, d) => {
    setCfg((c) => {
      const list = [...c.relays];
      const j = i + d;
      if (j < 0 || j >= list.length) return c;
      [list[i], list[j]] = [list[j], list[i]];
      return { ...c, relays: list };
    });
  };

  const removeRelay = (id) =>
    setCfg((c) => ({ ...c, relays: c.relays.filter((x) => x !== id) }));

  return (
    <div className="page">
      <header className="page-head">
        <button className="head-icon" onClick={onClose} aria-label={t("back")}>
          <ArrowLeft size={22} />
        </button>
        <div className="page-title">{t("onion")}</div>
        <Button size="s" mode="plain" loading={busy} onClick={save}>
          {t("save")}
        </Button>
      </header>

      <div className="scroll">
        <Group title={t("onion")}>
          <Cell
            before={
              <span className="cell-icon" style={{ background: "#8e5bd0" }}>
                <Waypoints size={18} />
              </span>
            }
            subtitle={t("onionHint")}
            after={
              <Switch
                checked={cfg.enabled}
                onChange={(e) =>
                  setCfg((c) => ({ ...c, enabled: e.target.checked }))
                }
              />
            }
          >
            {t("onion")}
          </Cell>
        </Group>

        <div className="path-preview">
          <span className="path-node">{t("relays")} × {cfg.relays.length}</span>
          <span className="path-arrow">→</span>
          <span className="path-node terminal">{t("mailbox")}</span>
        </div>
        <div className="hint-line">{t("terminalHint")}</div>

        <Group title={t("relayPath")}>
          <div className="form-row inset">
            <input
              className="plain-input grow mono"
              placeholder={t("relayPlaceholder")}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") add();
              }}
            />
            <Button mode="filled" onClick={add}>
              {t("addRelay")}
            </Button>
          </div>

          {cfg.relays.length === 0 && <Placeholder description={t("noRelays")} />}
          {cfg.relays.map((r, i) => (
            <div className="peer-row" key={r}>
              <span className="peer-icon relay">
                <span className="relay-index">{i + 1}</span>
              </span>
              <div className="peer-main">
                <div className="peer-id mono">{shortId(r)}</div>
                <div className="peer-meta">
                  <span className="muted">{t("relayRole")}</span>
                </div>
              </div>
              <div className="row-actions">
                <button
                  className="row-icon"
                  disabled={i === 0}
                  onClick={() => move(i, -1)}
                  aria-label="up"
                >
                  <ChevronUp size={18} />
                </button>
                <button
                  className="row-icon"
                  disabled={i === cfg.relays.length - 1}
                  onClick={() => move(i, 1)}
                  aria-label="down"
                >
                  <ChevronDown size={18} />
                </button>
                <button
                  className="row-icon"
                  onClick={() => removeRelay(r)}
                  aria-label="remove"
                >
                  <X size={18} />
                </button>
              </div>
            </div>
          ))}
        </Group>

        <div className="privacy-note">
          <ShieldCheck size={16} />
          <span>{t("onionPrivacy")}</span>
        </div>
      </div>
    </div>
  );
}
