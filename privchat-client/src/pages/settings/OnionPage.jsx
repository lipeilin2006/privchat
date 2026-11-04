import React, { useEffect, useMemo, useState } from "react";
import { Button, Cell, Switch, Placeholder } from "@telegram-apps/telegram-ui";
import {
  ArrowLeft,
  Waypoints,
  ChevronUp,
  ChevronDown,
  X,
  Activity,
} from "lucide-react";
import Group from "../../components/Group";
import { api } from "../../api";
import { t } from "../../i18n";

const RELAY_RE = /^[0-9a-fA-F]{64}$/;
const PRIORITIES = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

function shortId(id) {
  return id.length > 18 ? `${id.slice(0, 10)}…${id.slice(-6)}` : id;
}

function emptyConfig() {
  return {
    enabled: false,
    mode: "static",
    relays: [],
    hops: 2,
    weight: 0.5,
  };
}

export default function OnionPage({ notify, onClose }) {
  const [cfg, setCfg] = useState(emptyConfig());
  const [latency, setLatency] = useState({});
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    Promise.all([api.getOnion(), api.onionRelayLatency().catch(() => ({}))])
      .then(([c, lat]) => {
        setCfg({
          ...emptyConfig(),
          ...(c || {}),
          relays: Array.isArray(c?.relays)
            ? c.relays.map((r) =>
                typeof r === "string"
                  ? { peer_id: r, priority: 0 }
                  : { peer_id: r.peer_id, priority: r.priority ?? 0 }
              )
            : [],
        });
        setLatency(lat || {});
      })
      .catch(() => {});
  }, []);

  const dynamic = cfg.mode === "dynamic";

  const save = async () => {
    if (cfg.enabled && cfg.relays.length === 0) {
      notify(t("noRelays"), "err");
      return;
    }
    setBusy(true);
    try {
      await api.setOnion({
        ...cfg,
        relays: cfg.relays.map((r) => ({
          peer_id: r.peer_id,
          priority: Number(r.priority) || 0,
        })),
        hops: Number(cfg.hops) || 1,
        weight: Number(cfg.weight) || 0,
      });
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
    if (cfg.relays.some((r) => r.peer_id === id)) {
      return notify(t("relayExists"), "err");
    }
    setCfg((c) => ({ ...c, relays: [...c.relays, { peer_id: id, priority: 0 }] }));
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

  const patchRelay = (id, patch) =>
    setCfg((c) => ({
      ...c,
      relays: c.relays.map((r) => (r.peer_id === id ? { ...r, ...patch } : r)),
    }));

  const removeRelay = (id) =>
    setCfg((c) => ({ ...c, relays: c.relays.filter((r) => r.peer_id !== id) }));

  const testRelays = async () => {
    if (cfg.relays.length === 0) return;
    setTesting(true);
    try {
      const results = await api.testOnionRelays();
      const next = {};
      for (const r of results || []) {
        if (r.ms != null) next[r.peer_id] = r.ms;
      }
      setLatency(next);
    } catch (e) {
      notify(String(e), "err");
    } finally {
      setTesting(false);
    }
  };

  const fastest = useMemo(() => {
    let best = null;
    for (const [id, ms] of Object.entries(latency)) {
      if (best == null || ms < best.ms) best = { id, ms };
    }
    return best;
  }, [latency]);

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
                onChange={(e) => setCfg((c) => ({ ...c, enabled: e.target.checked }))}
              />
            }
          >
            {t("onion")}
          </Cell>
        </Group>

        <Group title={t("relayPath")}>
          <div className="seg">
            <button
              className={`seg-item ${!dynamic ? "active" : ""}`}
              onClick={() => setCfg((c) => ({ ...c, mode: "static" }))}
            >
              {t("staticMode")}
            </button>
            <button
              className={`seg-item ${dynamic ? "active" : ""}`}
              onClick={() => setCfg((c) => ({ ...c, mode: "dynamic" }))}
            >
              {t("dynamicMode")}
            </button>
          </div>
          {dynamic && (
            <div className="tune-block">
              <div className="tune-row">
                <span className="tune-label">{t("hops")}</span>
                <select
                  className="tg-select priority-select"
                  value={cfg.hops}
                  onChange={(e) => setCfg((c) => ({ ...c, hops: Number(e.target.value) }))}
                >
                  {[1, 2, 3, 4, 5].map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </select>
              </div>
              <div className="tune-row weight-row">
                <span className="tune-label">{t("weightPrioritySide")}</span>
                <input
                  className="tune-slider"
                  type="range"
                  min="0"
                  max="1"
                  step="0.05"
                  value={cfg.weight}
                  onChange={(e) =>
                    setCfg((c) => ({ ...c, weight: Number(e.target.value) }))
                  }
                />
                <span className="tune-label right">{t("weightLatencySide")}</span>
                <span className="tune-value">{Number(cfg.weight).toFixed(2)}</span>
              </div>
            </div>
          )}

          <div className="path-preview">
            <span className="path-node">
              {dynamic
                ? `${t("relays")} × ${Math.min(cfg.hops, cfg.relays.length || cfg.hops)}`
                : `${t("relays")} × ${cfg.relays.length}`}
            </span>
            <span className="path-arrow">→</span>
            <span className="path-node terminal">{t("mailbox")}</span>
            <button
              className="row-icon push-right"
              onClick={testRelays}
              disabled={testing || cfg.relays.length === 0}
              aria-label={t("testRelay")}
              title={t("testRelay")}
            >
              <Activity size={16} />
            </button>
          </div>

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
            <div className="peer-row" key={r.peer_id}>
              <span className="peer-icon relay">
                <span className="relay-index">{i + 1}</span>
              </span>
              <div className="peer-main">
                <div className="peer-id mono">{shortId(r.peer_id)}</div>
                <div className="peer-meta">
                  {dynamic ? (
                    <span className="peer-priority">
                      {t("priority")}
                      <select
                        className="tg-select priority-select small"
                        value={r.priority}
                        onChange={(e) =>
                          patchRelay(r.peer_id, { priority: Number(e.target.value) })
                        }
                      >
                        {PRIORITIES.map((n) => (
                          <option key={n} value={n}>
                            {n}
                          </option>
                        ))}
                      </select>
                    </span>
                  ) : null}
                  {latency[r.peer_id] != null ? (
                    <span
                      className={`lat-badge ok${
                        fastest?.id === r.peer_id ? " best" : ""
                      }`}
                    >
                      {latency[r.peer_id]} ms
                    </span>
                  ) : (
                    <span className="lat-badge idle">{t("untested")}</span>
                  )}
                </div>
              </div>
              <div className="row-actions">
                {!dynamic && (
                  <>
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
                  </>
                )}
                <button
                  className="row-icon"
                  onClick={() => removeRelay(r.peer_id)}
                  aria-label="remove"
                >
                  <X size={18} />
                </button>
              </div>
            </div>
          ))}
        </Group>

      </div>
    </div>
  );
}
