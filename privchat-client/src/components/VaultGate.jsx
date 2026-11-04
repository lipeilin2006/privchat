import React, { useEffect, useState } from "react";
import { Button, Spinner } from "@telegram-apps/telegram-ui";
import { api } from "../api";
import { t } from "../i18n";

export default function VaultGate({ initialized, onUnlocked, notify }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [bootLog, setBootLog] = useState("");

  // 上一轮如果没走到「ui mounted」就退出了，把那份启动日志摊开，
  // 这样在拿不到 logcat 的手机上也能看见死在哪一步。
  useEffect(() => {
    (async () => {
      try {
        const log = await api.bootPrevLog();
        if (log && !log.trimEnd().endsWith("ui mounted")) setBootLog(log);
        await api.bootPrevLogClear();
      } catch {
        // 诊断本身失败不能影响正常启动
      }
    })();
  }, []);

  const submit = async () => {
    if (!password) return;
    setBusy(true);
    setError("");
    try {
      const st = initialized ? await api.unlockVault(password) : await api.createVault(password);
      if (st?.unlocked) {
        onUnlocked();
      } else {
        setError(String(st?.error || "unlock failed"));
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="vault-screen">
      <div className="vault-logo">P</div>
      <h2 className="vault-title">{initialized ? t("unlock") : t("create")}</h2>
      <p className="vault-hint">{t("vaultHint")}</p>
      <input
        className="plain-input vault-input"
        type="password"
        placeholder={t("password")}
        value={password}
        onChange={(e) => {
          setPassword(e.target.value);
          setError("");
        }}
        onKeyDown={(e) => {
          if (e.key === "Enter") submit();
        }}
      />
      {error && <div className="vault-error">{error}</div>}
      {busy ? (
        <Spinner size="m" />
      ) : (
        <Button stretched size="l" mode="filled" disabled={!password} onClick={submit}>
          {initialized ? t("unlock") : t("create")}
        </Button>
      )}
      {bootLog && (
        <details className="boot-diag">
          <summary>{t("bootDiag")}</summary>
          <pre>{bootLog}</pre>
        </details>
      )}
    </div>
  );
}
