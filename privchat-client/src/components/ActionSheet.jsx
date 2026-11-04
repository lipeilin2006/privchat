import React from "react";
import { t } from "../i18n";

/**
 * 底部动作面板：聊天页的「更多」用它装 手动轮换 / 删除连接。
 * actions: [{ label, danger, onClick }]
 */
export default function ActionSheet({ title, actions, onClose }) {
  return (
    <div className="confirm-mask" onClick={onClose}>
      <div className="confirm-sheet" onClick={(e) => e.stopPropagation()}>
        {title && <div className="confirm-title">{title}</div>}
        {actions.map((action) => (
          <button
            key={action.label}
            className={`sheet-action${action.danger ? " danger" : ""}`}
            onClick={async () => {
              await action.onClick?.();
              onClose();
            }}
          >
            {action.label}
          </button>
        ))}
        <button className="sheet-action muted" onClick={onClose}>
          {t("cancel")}
        </button>
      </div>
    </div>
  );
}
