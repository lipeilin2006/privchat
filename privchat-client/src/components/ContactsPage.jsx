import { useState } from "react";
import { Avatar, Cell, Placeholder } from "@telegram-apps/telegram-ui";
import { UserPlus } from "lucide-react";
import Group from "./Group";
import SearchBox from "./SearchBox";
import { t } from "../i18n";
import { avatarColor, fmtTime, initials } from "../utils/format";

export default function ContactsPage({ conversations, onOpen, onAdd }) {
  const [query, setQuery] = useState("");
  const list = conversations.filter((c) =>
    (c.title || "").toLowerCase().includes(query.trim().toLowerCase())
  );

  return (
    <div className="page">
      <header className="page-head">
        <div className="page-title">{t("contacts")}</div>
      </header>

      <div className="search-wrap">
        <SearchBox
          value={query}
          onChange={setQuery}
          placeholder={`${t("search")} ${t("contacts")}`}
        />
      </div>

      <div className="scroll">
        <Group title="">
          <Cell
            before={
              <span className="cell-icon" style={{ background: "#3390ec" }}>
                <UserPlus size={18} />
              </span>
            }
            onClick={onAdd}
          >
            {t("inviteFriends")}
          </Cell>
        </Group>

        <Group title={t("sortedByRecent")} accent>
          {list.length === 0 && <Placeholder description={t("noContacts")} />}
          {list.map((c) => (
            <Cell
              key={c.peer_id}
              before={
                <Avatar
                  size={56}
                  acronym={initials(c.title)}
                  style={{ background: avatarColor(c.peer_id) }}
                />
              }
              subtitle={
                c.lastTime ? `${t("lastSeen")} · ${fmtTime(c.lastTime)}` : t("noActivity")
              }
              onClick={() => onOpen(c.peer_id)}
            >
              {c.title}
            </Cell>
          ))}
        </Group>
      </div>

      <button className="fab" onClick={onAdd} aria-label={t("add")}>
        <UserPlus size={24} />
      </button>
    </div>
  );
}
