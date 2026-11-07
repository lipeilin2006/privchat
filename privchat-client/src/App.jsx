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
import { cancel as cancelScan } from "@tauri-apps/plugin-barcode-scanner";
import { ensureNotificationPermission, notifyMessage } from "./notify";

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
  const contactsRef = useRef([]);
  contactsRef.current = contacts;

  /// 锁上之后立即回到密码界面（后端会把 App 停掉、轮询任务也 abort）。
  const lockNow = useCallback(async () => {
    try {
      await api.lockVault();
    } catch {
      // 已经锁了也无所谓
    }
    setVaultState("locked");
  }, []);

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
      // 未配对的连接只是「还没扫完的邀请」，不算联系人。
      const mapped = (list || [])
        .filter((c) => c.state === "established")
        .map((c) => ({
          peer_id: c.conn_id,
          name: c.name,
          state: c.state,
        }));
      setContacts(mapped);
      const entries = await Promise.all(
        mapped.map(async (c) => [c.peer_id, await api.connectionHistory(c.peer_id)])
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

  // 解锁后把通知权限要一次
  useEffect(() => {
    if (vaultState === "unlocked") ensureNotificationPermission();
  }, [vaultState]);

  // 自动锁定：空闲计时（0 = 永不）。
  useEffect(() => {
    if (vaultState !== "unlocked") return;
    let minutes = 0;
    let idleTimer;
    const arm = () => {
      clearTimeout(idleTimer);
      if (minutes > 0) idleTimer = setTimeout(lockNow, minutes * 60000);
    };
    api
      .autoLock()
      .then((value) => {
        minutes = value || 0;
        arm();
      })
      .catch(() => {});
    const events = ["pointerdown", "keydown", "touchstart", "wheel"];
    events.forEach((event) => window.addEventListener(event, arm, { passive: true }));
    // 设置页改完自动锁定，立刻按新值重新计时。
    const onConfig = (event) => {
      minutes = Number(event.detail) || 0;
      arm();
    };
    window.addEventListener("privchat:autolock", onConfig);
    return () => {
      clearTimeout(idleTimer);
      events.forEach((event) => window.removeEventListener(event, arm));
      window.removeEventListener("privchat:autolock", onConfig);
    };
  }, [vaultState, lockNow]);

  // 切后台：超过设定时长再回来也要重新解锁。
  useEffect(() => {
    if (vaultState !== "unlocked") return;
    let hiddenAt = 0;
    let minutes = 0;
    api
      .autoLock()
      .then((value) => {
        minutes = value || 0;
      })
      .catch(() => {});
    const onVisibility = () => {
      if (document.visibilityState === "hidden") {
        hiddenAt = Date.now();
        return;
      }
      if (!hiddenAt) return;
      const elapsed = Date.now() - hiddenAt;
      hiddenAt = 0;
      if (minutes > 0 && elapsed >= minutes * 60000) lockNow();
    };
    const onConfig = (event) => {
      minutes = Number(event.detail) || 0;
    };
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("privchat:autolock", onConfig);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("privchat:autolock", onConfig);
    };
  }, [vaultState, lockNow]);

  useEffect(() => {
    if (vaultState !== "unlocked") return;
    let off;
    // 后台轮询拉到新消息后会发这个事件；前端只用重新读一次历史，
    // 不再自己 setInterval 轮询（以前两边都在拉，消息会被对方先取走）。
    listen("connection://message", async (event) => {
      const connId = event.payload?.conn_id;
      if (!connId) return;
      try {
        const msgs = await api.connectionHistory(connId);
        setHistory((prev) => ({ ...prev, [connId]: msgs || [] }));
      } catch {
        // 下一轮事件会再来
      }
      // 空文本是「对方配对完成」的控制帧，不弹通知
      const text = event.payload?.text;
      if (text && document.visibilityState === "hidden") {
        const name = contactsRef.current.find((c) => c.peer_id === connId)?.name;
        notifyMessage(name || t("newMessage"), String(text).slice(0, 80));
      }
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

  const scanningRef = useRef(false);

  const goBack = useCallback(() => {
    // 正在扫码：返回键先关相机，别把页面带走。
    if (scanningRef.current) {
      scanningRef.current = false;
      cancelScan().catch(() => {});
      return;
    }
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
                notify={notify}
                onReload={async () => {
                  try {
                    const msgs = await api.connectionHistory(activePeer);
                    setHistory((prev) => ({ ...prev, [activePeer]: msgs || [] }));
                  } catch {
                    // 忽略：下次事件会刷新
                  }
                }}
                onRotate={async () => {
                  try {
                    await api.rotateConnection(activePeer);
                    notify(t("rotateDone"));
                  } catch (e) {
                    notify(String(e), "err");
                  }
                }}
                onDelete={async () => {
                  try {
                    await api.deleteConnection(activePeer);
                    setActivePeer(null);
                    setPage("chats");
                    await loadAll();
                    notify(t("deleteDone"));
                  } catch (e) {
                    notify(String(e), "err");
                  }
                }}
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
                onScanStateChange={(active) => {
                  scanningRef.current = active;
                }}
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
