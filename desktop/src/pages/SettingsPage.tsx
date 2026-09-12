import type { ProductSnapshot, SettingItem } from "../model";
import { CapabilityBadge } from "../components/StatusBadge";
import { PageHeader, SectionCard } from "../components/AppShell";

function displayValue(value: SettingItem["value"]): string {
  if (typeof value === "boolean") {
    return value ? "On" : "Off";
  }
  return String(value);
}

function SettingRow({ item }: { item: SettingItem }) {
  const disabled = item.state === "unavailable";

  return (
    <div className={`setting-row ${disabled ? "setting-row-disabled" : ""}`}>
      <div className="setting-copy">
        <div className="setting-title-line">
          <h3>{item.label}</h3>
          <CapabilityBadge state={item.state} />
        </div>
        <p>{item.description}</p>
        {disabled ? <div className="setting-note">This setting is visible, but its backend capability is not available yet.</div> : null}
      </div>
      <div className="setting-value-wrap">
        <span className={`setting-value ${disabled ? "setting-value-muted" : ""}`}>{displayValue(item.value)}</span>
        {item.options ? <span className="setting-chevron" aria-hidden="true">⌄</span> : null}
      </div>
    </div>
  );
}

export function SettingsPage({ snapshot }: { snapshot: ProductSnapshot }) {
  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Preferences"
        title="Settings"
        description="Tune the desktop experience. Each control reports whether its runtime capability is available."
        actions={<span className="save-state">Changes apply through the session adapter</span>}
      />

      {snapshot.settings.map((section) => (
        <SectionCard key={section.id} title={section.label} description={section.description}>
          <div className="settings-list">
            {section.items.map((item) => <SettingRow key={item.id} item={item} />)}
          </div>
        </SectionCard>
      ))}
    </div>
  );
}
