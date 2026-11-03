import { useEffect, useRef, useState } from "react";
import { Placeholder } from "@telegram-apps/telegram-ui";
import { ArrowLeft, CheckCheck, SendHorizontal } from "lucide-react";
import wallpaper from "../assets/wallpaper.png";
import { t } from "../i18n";
import { avatarColor, fmtTime, initials } from "../utils/format";

export default function ChatWindow({ conversation, messages, onBack, onSend }) {
  const [text, setText] = useState("");
  const bodyRef = useRef(null);

  useEffect(() => {
    if (bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
  }, [messages.length]);

  const submit = () => {
    if (!text.trim()) return;
    onSend(text);
    setText("");
  };

  if (!conversation) {
    return (
      <div className="page">
        <header className="page-head">
          <button className="head-icon" onClick={onBack} aria-label={t("back")}>
            <ArrowLeft size={22} />
          </button>
        </header>
        <Placeholder description={t("noChats")} />
      </div>
    );
  }

  return (
    <div className="chat-screen" style={{ backgroundImage: `url(${wallpaper})` }}>
      <header className="chat-head">
        <button className="round-btn" onClick={onBack} aria-label={t("back")}>
          <ArrowLeft size={20} />
        </button>
        <span className="chat-head-avatar" style={{ background: avatarColor(conversation.title) }}>
          {initials(conversation.title)}
        </span>
        <div className="chat-head-text">
          <div className="chat-head-name">{conversation.title}</div>
          <div className="chat-head-sub">{t("online")}</div>
        </div>
      </header>

      <div className="chat-body" ref={bodyRef}>
        {messages.length > 0 && <div className="date-sep">{t("today")}</div>}
        {messages.length === 0 && <Placeholder description={t("noMessages")} />}
        {messages.map((m) => (
          <div key={m.id} className={`msg-row ${m.from === "me" ? "me" : ""}`}>
            <div
              className={`msg ${m.from === "me" ? "out" : "in"} ${
                m.status === "failed" ? "failed" : ""
              }`}
            >
              <div className="msg-text">{m.text}</div>
              <div className="msg-meta">
                <span>{fmtTime(m.time)}</span>
                {m.from === "me" && (m.status === "sent" || m.status === "sending") && (
                  <CheckCheck size={14} className="ticks" />
                )}
                {m.status === "failed" && <span className="failed-mark">!</span>}
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="composer">
        <input
          className="composer-input"
          placeholder={t("messagePlaceholder")}
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") submit();
          }}
        />
        <button
          className={`send-btn ${text.trim() ? "ready" : ""}`}
          onClick={submit}
          aria-label={t("send")}
          disabled={!text.trim()}
        >
          <SendHorizontal size={20} />
        </button>
      </div>
    </div>
  );
}
