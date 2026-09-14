import { useState } from "react";

import type { ProductSnapshot, SettingItem } from "../model";
import { CapabilityBadge } from "../components/StatusBadge";
import { PageHeader, SectionCard } from "../components/AppShell";
import type { ProductAdapter } from "../adapters/productAdapter";

function displayValue(value: SettingItem["value"]): string {
  if (typeof value === "boolean") {
    return value ? "On" : "Off";
  }
  return String(value);
}

function applyLabel(item: SettingItem): string | undefined {
  switch (item.applyMode) {
    case "live":
      return "Applies immediately";
    case "reconnect":
      return "Applies on next connection";
    case "restart_host":
      return "Applies after host restart";
    case "restart_application":
      return "Applies after app restart";
    default:
      return undefined;
  }
}

function SettingRow({
  item,
  saving,
  onChange,
}: {
  item: SettingItem;
  saving: boolean;
  onChange: (value: string | number | boolean | null) => void;
}) {
  const unavailable = item.state === "unavailable" || item.state === "not-implemented";
  const apply = applyLabel(item);

  return (
    <div className={`setting-row ${unavailable ? "setting-row-disabled" : ""}`}>
      <div className="setting-copy">
        <div className="setting-title-line">
          <h3>{item.label}</h3>
          <CapabilityBadge state={item.state} />
        </div>
        <p>{item.description}</p>
        {apply ? <div className="setting-note">{apply}</div> : null}
        {unavailable ? (
          <div className="setting-note">This setting is not available on the current runtime.</div>
        ) : null}
      </div>
      <div className="setting-value-wrap">
        {typeof item.value === "boolean" ? (
          <label className="toggle-control">
            <input
              type="checkbox"
              checked={item.value}
              disabled={unavailable || saving}
              onChange={(event) => onChange(event.currentTarget.checked)}
            />
            <span>{displayValue(item.value)}</span>
          </label>
        ) : item.options ? (
          <select
            className="setting-select"
            value={String(item.value)}
            disabled={unavailable || saving}
            onChange={(event) => onChange(event.currentTarget.value)}
          >
            {item.options.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        ) : (
          <input
            className="setting-text-input"
            value={String(item.value)}
            disabled={unavailable || saving}
            onChange={(event) => onChange(event.currentTarget.value)}
          />
        )}
      </div>
    </div>
  );
}

export function SettingsPage({
  snapshot,
  adapter,
  onSnapshot,
}: {
  snapshot: ProductSnapshot;
  adapter: ProductAdapter;
  onSnapshot: (snapshot: ProductSnapshot) => void;
}) {
  const [saving, setSaving] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const update = async (item: SettingItem, value: string | number | boolean | null) => {
    setSaving(item.id);
    setError(null);
    try {
      const next = await adapter.updateSetting(item.id, value);
      onSnapshot(next);
      if (item.id === "host.enabled" && typeof value === "boolean") {
        const lifecycle = await adapter.dispatch(value ? "EnableHosting" : "DisableHosting");
        onSnapshot(lifecycle);
      }
    } catch {
      setError(`Could not update ${item.label}. The previous value remains active.`);
    } finally {
      setSaving(null);
    }
  };

  const pending = snapshot.pendingSettingKeys ?? [];

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Preferences"
        title="Settings"
        description="Tune the desktop experience. Each control reports whether its runtime capability is available."
        actions={<span className="save-state">{saving ? "Saving…" : "Saved to this device"}</span>}
      />

      {error ? <div className="error-banner" role="alert">{error}</div> : null}
      {snapshot.restartRequired ? (
        <div className="notice-banner">Some changes apply after restarting OpenStream.</div>
      ) : null}
      {snapshot.hostRestartRequired ? (
        <div className="notice-banner">
          <span>Some host changes apply after the host agent restarts.</span>
          <button
            className="secondary-button"
            type="button"
            disabled={saving !== null}
            onClick={() => {
              setSaving("__host_restart__");
              setError(null);
              void adapter
                .dispatch("RestartHosting")
                .then(onSnapshot)
                .catch(() => setError("Could not restart the host agent. The current host remains unchanged."))
                .finally(() => setSaving(null));
            }}
          >
            Restart host
          </button>
        </div>
      ) : null}
      {pending.length > 0 ? (
        <div className="setting-note">Pending changes: {pending.join(", ")}</div>
      ) : null}

      {snapshot.settings.map((section) => (
        <SectionCard key={section.id} title={section.label} description={section.description}>
          <div className="settings-list">
            {section.items.map((item) => (
              <SettingRow
                key={item.id}
                item={item}
                saving={saving === item.id}
                onChange={(value) => void update(item, value)}
              />
            ))}
          </div>
        </SectionCard>
      ))}
    </div>
  );
}
