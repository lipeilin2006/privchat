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


export default function OnionPage({ notify, onClose }) {
  const [cfg, setCfg] = useState({ enabled: false, relays: [] });
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.getOnion().then((c) =>
      setCfg({ enabled: !!c?.enabled, relays: Array.isArray(c?.relays) ? [...c.relays] : [] })
    ).catch(() => {});
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
    if (cfg.relays.includes(id)) return;
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

  return (
    <div className="page">
      <header className="page-head">
        <button className="head-icon" onClick={onClose} aria-label={t("back")}>
          <ArrowLeft size={22} />
        </button>
        <div className="page-title">{t("onion")}</div>
        <Button size="s" mode="plain" loading={busy} onClick={save}>{t("save")}</Button>
      </header>

      <div className="scroll">
        <Group title={t("onion")}>
          <Cell
            before={<span className="cell-icon" style={{ background: "#8e5bd0" }}><Waypoints size={18} /></span>}
            subtitle={t("onionHint")}
            after={
              <Switch
                checked={cfg.enabled}
                onChange={(e) => setCfg((c) => ({ ...c, enabled: e.target.checked }))}
              />
            }
          >
            {t("onion")}
          </Cell>
        </Group>

        <Group title={t("relayPath")}>
          <div className="form-row inset">
            <input
              className="plain-input grow"
              placeholder={t("relayPlaceholder")}
              value={input}
              onChange={(e) => setInput(e.target.value)}
            />
            <Button mode="filled" onClick={add}>{t("addRelay")}</Button>
          </div>
          {cfg.relays.length === 0 && <Placeholder description={t("noRelays")} />}
          {cfg.relays.map((r, i) => (
            <Cell
              key={r}
              before={<span className="relay-index">{i + 1}</span>}
              subtitle={`${r.slice(0, 12)}…${r.slice(-6)}`}
              after={
                <div className="row-actions">
                  <button className="row-icon" onClick={() => move(i, -1)} aria-label="up"><ChevronUp size={18} /></button>
                  <button className="row-icon" onClick={() => move(i, 1)} aria-label="down"><ChevronDown size={18} /></button>
                  <button className="row-icon" onClick={() => setCfg((c) => ({ ...c, relays: c.relays.filter((x) => x !== r) }))} aria-label="remove"><X size={18} /></button>
                </div>
              }
            />
          ))}
        </Group>
      </div>
    </div>
  );
}
