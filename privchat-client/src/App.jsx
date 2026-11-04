import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AppRoot, Spinner } from "@telegram-apps/telegram-ui";
import {
  MessageCircle,
  Users,
  CircleUserRound,
  Settings as SettingsIcon,
} from "lucide-react";
import { listen } from "@tauri-apps/api/event";
import { onBackButtonPress } from "@tauri-apps/api/app";

import { api } from "./api";
import { t } from "./i18n";
import VaultGate from "./components/VaultGate";
import ChatList from "./components/ChatList";
import ChatWindow from "./components/ChatWindow";
import ContactsPage from "./components/ContactsPage";
import ErrorBoundary from "./components/ErrorBoundary";
import SettingsPage from "./pages/settings";
import MyIdPage from "./pages/MyIdPage";

export default function App() {
  const [vaultState, setVaultState] = useState("loading");
  const [initialized, setInitialized] = useState(false);
  const [contacts, setContacts] = useState([]);
  const [history, setHistory] = useState({});
  const [activePeer, setActivePeer] = useState(null);
  const [page, setPage] = useState("chats");
  const [toast, setToast] = useState(null);
  const toastTimer = useRef(null);

  const notify = useCallback((text, type = "ok") => {
    setToast({ text, type });
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 2400);
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const st = await api.vaultStatus();
        setInitialized(!!st?.initialized);
        setVaultState(st?.unlocked ? "unlocked" : "locked");
      } catch {
        setVaultState("locked");
      }
    })();
  }, []);

  const loadAll = useCallback(async () => {
    try {
      const list = await api.listConnections();
      const mapped = (list || []).map((c) => ({
        peer_id: c.conn_id,
        name: c.name,
        state: c.state,
      }));
      setContacts(mapped);
      const entries = await Promise.all(
        mapped.map(async (c) => [c.conn_id, await api.connectionHistory(c.conn_id)])
      );
      const map = {};
      for (const [connId, msgs] of entries) map[connId] = msgs || [];
      setHistory(map);
    } catch (e) {
      notify(String(e), "err");
    }
  }, [notify]);

  useEffect(() => {
    if (vaultState === "unlocked") loadAll();
  }, [vaultState, loadAll]);

  useEffect(() => {
    if (vaultState !== "unlocked") return;
    let stopped = false;
    const tick = async () => {
      if (stopped) return;
      try {
        const list = await api.listConnections();
        for (const c of list || []) {
          if (c.state !== "established") continue;
          const got = await api.pollConnection(c.conn_id);
          if (got && got.length) {
            const msgs = await api.connectionHistory(c.conn_id);
            setHistory((prev) => ({ ...prev, [c.conn_id]: msgs || [] }));
          }
        }
      } catch {
        // 网络抖动：下一轮再试
      }
    };
    const timer = setInterval(tick, 3000);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [vaultState]);

  useEffect(() => {
    if (vaultState !== "unlocked") return;
    let off;
    listen("chat://message", (event) => {
      const { from, text, time } = event.payload || {};
      if (!from) return;
      setHistory((prev) => {
        const list = prev[from] ? [...prev[from]] : [];
        if (list.some((m) => m.id === `live-${time}`)) return prev;
        list.push({ id: `live-${time}`, from: "peer", text, time, status: "received" });
        return { ...prev, [from]: list };
      });
    }).then((unlisten) => {
      off = unlisten;
    });
    return () => {
      if (off) off();
    };
  }, [vaultState]);

  const conversations = useMemo(() => {
    return contacts
      .map((c) => {
        const msgs = history[c.peer_id] || [];
        const last = msgs[msgs.length - 1];
        return {
          ...c,
          title: c.name || c.peer_id.slice(0, 10),
          lastText: last?.text || "",
          lastTime: last?.time || 0,
        };
      })
      .sort((a, b) => (b.lastTime || 0) - (a.lastTime || 0));
  }, [contacts, history]);

  const send = useCallback(
    async (peerId, text) => {
      if (!text.trim()) return;
      const optimistic = {
        id: `local-${Date.now()}`,
        from: "me",
        text,
        time: Date.now(),
        status: "sending",
      };
      setHistory((prev) => ({ ...prev, [peerId]: [...(prev[peerId] || []), optimistic] }));
      try {
        await api.sendOnConnection(peerId, text);
        const msgs = await api.connectionHistory(peerId);
        setHistory((prev) => ({ ...prev, [peerId]: msgs || [] }));
      } catch (e) {
        setHistory((prev) => ({
          ...prev,
          [peerId]: (prev[peerId] || []).map((m) =>
            m.id === optimistic.id ? { ...m, status: "failed" } : m
          ),
        }));
        notify(String(e), "err");
      }
    },
    [notify]
  );

  const goBack = useCallback(() => {
    if (page === "chat") setPage("chats");
    else if (page === "mailbox" || page === "onion") setPage("settings");
    else if (page === "settings" || page === "add" || page === "contacts") setPage("chats");
    else api.exitApp().catch(() => {});
  }, [page]);

  const backRef = useRef(goBack);
  backRef.current = goBack;

  useEffect(() => {
    let off;
    try {
      if (typeof onBackButtonPress === "function") {
        const maybe = onBackButtonPress(() => backRef.current());
        if (maybe && typeof maybe.then === "function") {
          maybe
            .then((fn) => {
              off = fn;
            })
            .catch(() => {});
        }
      }
    } catch (e) {
      console.warn("back button hook unavailable:", e);
    }
    return () => {
      if (off) off();
    };
  }, []);

  if (vaultState === "loading") {
    return (
      <AppRoot appearance="light">
        <div className="center-screen">
          <Spinner size="l" />
        </div>
      </AppRoot>
    );
  }

  if (vaultState === "locked") {
    return (
      <AppRoot appearance="light">
        <VaultGate
          initialized={initialized}
          onUnlocked={() => setVaultState("unlocked")}
          notify={notify}
        />
      </AppRoot>
    );
  }

  const active = conversations.find((c) => c.peer_id === activePeer);

  return (
    <AppRoot appearance="light" className="tg-root">
      <div className="app-shell">
        <main className="app-screen">
          <ErrorBoundary>
            {page === "chats" && (
              <ChatList
                conversations={conversations}
                onOpen={(peer) => {
                  setActivePeer(peer);
                  setPage("chat");
                }}
              />
            )}

            {page === "contacts" && (
              <ContactsPage
                conversations={conversations}
                onOpen={(peer) => {
                  setActivePeer(peer);
                  setPage("chat");
                }}
                onAdd={() => setPage("add")}
              />
            )}

            {page === "chat" && (
              <ChatWindow
                conversation={active}
                messages={history[activePeer] || []}
                onBack={() => setPage("chats")}
                onSend={(text) => send(activePeer, text)}
              />
            )}

            {page === "settings" && (
              <SettingsPage
                notify={notify}
                onLocked={() => setVaultState("locked")}
                onOpenMailbox={() => setPage("mailbox")}
                onOpenOnion={() => setPage("onion")}
              />
            )}

            {page === "mailbox" && (
              <SettingsPage notify={notify} sub="mailbox" onClose={() => setPage("settings")} />
            )}
            {page === "onion" && (
              <SettingsPage notify={notify} sub="onion" onClose={() => setPage("settings")} />
            )}

            {page === "add" && (
              <MyIdPage
                notify={notify}
                onAdded={async () => {
                  await loadAll();
                  setPage("chats");
                }}
              />
            )}
          </ErrorBoundary>
        </main>

        {["chats", "contacts", "settings", "add"].includes(page) && (
          <nav className="tabbar">
            <button className={`tab ${page === "chats" ? "active" : ""}`} onClick={() => setPage("chats")}>
              <MessageCircle size={23} strokeWidth={page === "chats" ? 2.2 : 1.8} />
              <span>{t("chats")}</span>
            </button>
            <button className={`tab ${page === "contacts" ? "active" : ""}`} onClick={() => setPage("contacts")}>
              <Users size={23} strokeWidth={page === "contacts" ? 2.2 : 1.8} />
              <span>{t("contacts")}</span>
            </button>
            <button className={`tab ${page === "settings" ? "active" : ""}`} onClick={() => setPage("settings")}>
              <SettingsIcon size={23} strokeWidth={page === "settings" ? 2.2 : 1.8} />
              <span>{t("settings")}</span>
            </button>
            <button className={`tab ${page === "add" ? "active" : ""}`} onClick={() => setPage("add")}>
              <CircleUserRound size={23} strokeWidth={page === "add" ? 2.2 : 1.8} />
              <span>{t("profile")}</span>
            </button>
          </nav>
        )}

        {toast && <div className={`tg-toast ${toast.type === "err" ? "err" : ""}`}>{toast.text}</div>}
      </div>
    </AppRoot>
  );
}
