import { List } from "@telegram-apps/telegram-ui";

export default function Group({ title, children, accent = false }) {
  return (
    <div className="group">
      {title ? <div className={`group-title${accent ? " accent" : ""}`}>{title}</div> : null}
      <div className="group-card">
        <List>{children}</List>
      </div>
    </div>
  );
}
