import { Fragment, useEffect, useRef, useState } from "react";
import { Placeholder } from "@telegram-apps/telegram-ui";
import { ArrowLeft, CheckCheck, MoreHorizontal, Paperclip, SendHorizontal } from "lucide-react";
import { t } from "../i18n";
import { api } from "../api";
import { openPath } from "@tauri-apps/plugin-opener";
import ActionSheet from "./ActionSheet";
import { avatarColor, fmtTime, initials } from "../utils/format";

/** 同一天分组用：YYYY-M-D。 */
function dayKey(time) {
  const d = new Date(time);
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

/** 今天 / 昨天 / 2024-05-03。 */
function dayLabel(time) {
  const d = new Date(time);
  const today = new Date();
  const sameDay = (a, b) =>
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate();
  if (sameDay(d, today)) return t("today");
  const yesterday = new Date(today);
  yesterday.setDate(today.getDate() - 1);
  if (sameDay(d, yesterday)) return t("yesterday");
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(
    d.getDate()
  ).padStart(2, "0")}`;
}

export default function ChatWindow({
  conversation,
  messages,
  onBack,
  onSend,
  onRotate,
  onDelete,
  onReload,
  notify,
}) {
  const [text, setText] = useState("");
  const [sheetOpen, setSheetOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [sendingFile, setSendingFile] = useState(false);
  const [preview, setPreview] = useState(null);
  const [opening, setOpening] = useState(false);
  const fileRef = useRef(null);
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
    <div className="chat-screen">
      <header className="chat-head">
        <button className="round-btn" onClick={onBack} aria-label={t("back")}>
          <ArrowLeft size={20} />
        </button>
        <span className="chat-head-avatar" style={{ background: avatarColor(conversation.title) }}>
          {initials(conversation.title)}
        </span>
        <div className="chat-head-text">
          <div className="chat-head-name">{conversation.title}</div>
          <div className="chat-head-sub">{t("e2eHint")}</div>
        </div>
        <button
          className="round-btn"
          onClick={() => fileRef.current?.click()}
          aria-label={t("attach")}
          disabled={sendingFile}
        >
          <Paperclip size={18} />
        </button>
        <button
          className="round-btn"
          onClick={() => setSheetOpen(true)}
          aria-label={t("more")}
        >
          <MoreHorizontal size={20} />
        </button>
        <input
          ref={fileRef}
          type="file"
          className="hidden-file"
          accept="image/*,application/pdf,text/plain,*/*"
          onChange={async (event) => {
            const file = event.target.files?.[0];
            event.target.value = "";
            if (!file) return;
            if (file.size > 2 * 1024 * 1024) {
              notify?.(t("fileTooLarge"), "err");
              return;
            }
            setSendingFile(true);
            try {
              const dataUrl = await new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = () => resolve(reader.result);
                reader.onerror = reject;
                reader.readAsDataURL(file);
              });
              const base64 = String(dataUrl).split(",")[1] || "";
              await api.sendFile(
                conversation.peer_id,
                file.name,
                file.type || "application/octet-stream",
                base64
              );
              await onReload?.();
            } catch (err) {
              notify?.(String(err), "err");
            } finally {
              setSendingFile(false);
            }
          }}
        />
      </header>

      {sheetOpen && (
        <ActionSheet
          title={conversation.title}
          onClose={() => setSheetOpen(false)}
          actions={[
            {
              label: t("rotateQueue"),
              onClick: onRotate,
            },
            {
              label: t("deleteConnection"),
              danger: true,
              onClick: () => setConfirmDelete(true),
            },
          ]}
        />
      )}

      {confirmDelete && (
        <div className="confirm-mask" onClick={() => setConfirmDelete(false)}>
          <div className="confirm-sheet" onClick={(e) => e.stopPropagation()}>
            <div className="confirm-title">{t("deleteConnection")}</div>
            <div className="confirm-text">{t("deleteConfirm2")}</div>
            <div className="confirm-actions">
              <button className="confirm-btn" onClick={() => setConfirmDelete(false)}>
                {t("cancel")}
              </button>
              <button
                className="confirm-btn danger"
                onClick={async () => {
                  await onDelete?.();
                  setConfirmDelete(false);
                }}
              >
                {t("confirmOk")}
              </button>
            </div>
          </div>
        </div>
      )}

      {preview && (
        <div className="image-viewer" onClick={() => setPreview(null)}>
          <img src={preview} alt="preview" />
        </div>
      )}

      <div className="chat-body" ref={bodyRef}>
        {messages.length === 0 && (
          <div className="chat-empty">
            <div className="chat-empty-icon">🔒</div>
            <div className="chat-empty-title">{t("noMessages")}</div>
            <div className="chat-empty-hint">{t("emptyHint")}</div>
          </div>
        )}
        {messages.map((m, index) => {
          const day = dayKey(m.time);
          const prevDay = index > 0 ? dayKey(messages[index - 1].time) : null;
          return (
            <Fragment key={m.id}>
              {day !== prevDay && <div className="date-sep">{dayLabel(m.time)}</div>}
              <div className={`msg-row ${m.from === "me" ? "me" : ""}`}>
            <div
              className={`msg ${m.from === "me" ? "out" : "in"} ${
                m.status === "failed" ? "failed" : ""
              }`}
            >
              {m.kind === "file" ? (
                String(m.mime || "").startsWith("image/") && m.data ? (
                  <img
                    className="msg-image"
                    src={`data:${m.mime};base64,${m.data}`}
                    alt={m.name || "image"}
                    onClick={() => setPreview(`data:${m.mime};base64,${m.data}`)}
                  />
                ) : (
                  <div className="file-card">
                    <span className="file-name">{m.name || m.text}</span>
                    <button
                      className="file-open"
                      disabled={opening}
                      onClick={async () => {
                        setOpening(true);
                        try {
                          const path = await api.exportAttachment(conversation.peer_id, m.id);
                          // 安卓在命令里已经调起查看器了，桌面这边再交给系统打开
                          if (path && !/Android/i.test(navigator.userAgent)) {
                            await openPath(path);
                          }
                        } catch (err) {
                          notify?.(String(err), "err");
                        } finally {
                          setOpening(false);
                        }
                      }}
                    >
                      {t("openFile")}
                    </button>
                  </div>
                )
              ) : (
                <div className="msg-text">{m.text}</div>
              )}
              <div className="msg-meta">
                <span>{fmtTime(m.time)}</span>
                {m.from === "me" && (m.status === "sent" || m.status === "sending") && (
                  <CheckCheck size={14} className="ticks" />
                )}
                {m.status === "failed" && <span className="failed-mark">!</span>}
              </div>
            </div>
          </div>
            </Fragment>
          );
        })}
      </div>

      <div className="composer">
        <textarea
          className="composer-input"
          rows={1}
          placeholder={t("messagePlaceholder")}
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            e.target.style.height = "auto";
            e.target.style.height = `${Math.min(e.target.scrollHeight, 120)}px`;
          }}
          onKeyDown={(e) => {
            // 桌面：回车发送、Shift+回车换行；移动端回车换行
            const mobile = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
            if (e.key === "Enter" && !e.shiftKey && !mobile) {
              e.preventDefault();
              submit();
            }
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
