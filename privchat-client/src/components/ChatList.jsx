import { useEffect, useState } from "react";
import { Avatar, Placeholder } from "@telegram-apps/telegram-ui";
import { SendHorizontal } from "lucide-react";
import SearchBox from "./SearchBox";
import { api } from "../api";
import { t } from "../i18n";
import { avatarColor, fmtTime, initials } from "../utils/format";

export default function ChatList({ conversations, onOpen }) {
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState([]);
  const filtered = conversations.filter((c) =>
    (c.title || "").toLowerCase().includes(query.trim().toLowerCase())
  );

  // 搜消息正文（防抖 250ms）
  useEffect(() => {
    const q = query.trim();
    if (!q) {
      setHits([]);
      return;
    }
    const timer = setTimeout(async () => {
      try {
        setHits(await api.searchMessages(q, 30));
      } catch {
        setHits([]);
      }
    }, 250);
    return () => clearTimeout(timer);
  }, [query]);

  return (
    <div className="page page-chats">
      <header className="page-head chats-head">
        <div className="brand">
          <span className="brand-logo">
            <SendHorizontal size={20} strokeWidth={2.2} />
          </span>
          <span className="brand-name">{t("appName")}</span>
        </div>
      </header>

      <div className="search-wrap">
        <SearchBox value={query} onChange={setQuery} placeholder={t("searchChats")} variant="grey" />
      </div>

      {filtered.length === 0 ? (
        <Placeholder description={t("noChats")}>
          <div className="ph-icon">💬</div>
        </Placeholder>
      ) : (
        <div className="chat-list">
          {filtered.map((c) => (
            <button key={c.peer_id} className="chat-row" onClick={() => onOpen(c.peer_id)}>
              <Avatar
                size={48}
                acronym={initials(c.title)}
                style={{ background: avatarColor(c.title) }}
              />
              <div className="chat-main">
                <div className="chat-top">
                  <span className="chat-name">{c.title}</span>
                  <span className="chat-time">{fmtTime(c.lastTime)}</span>
                </div>
                <div className="chat-preview">{c.lastText || t("noMessages")}</div>
              </div>
            </button>
          ))}
        </div>
      )}

      {hits.length > 0 && (
        <div className="search-hits">
          <div className="search-hits-title">{t("messageResults")}</div>
          {hits.map((hit) => (
            <button
              key={`${hit.conn_id}-${hit.msg_id}`}
              className="hit-row"
              onClick={() => onOpen(hit.conn_id)}
            >
              <span className="hit-name">{hit.name || hit.conn_id.slice(0, 10)}</span>
              <span className="hit-text">{hit.text}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
