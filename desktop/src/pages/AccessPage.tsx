import type { ProductSnapshot } from "../model";
import { CapabilityBadge } from "../components/StatusBadge";
import { EmptyState, PageHeader, SectionCard } from "../components/AppShell";

export function AccessPage({ snapshot }: { snapshot: ProductSnapshot }) {
  const { access } = snapshot;

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Trust and pairing"
        title="Access"
        description="Manage the control-plane boundary and the devices allowed to discover this OpenStream installation."
        actions={<button className="primary-button" type="button" disabled title="Pairing is not configured">Add device</button>}
      />

      <div className="two-column-grid">
        <SectionCard title="Control plane" description="Discovery and approval state comes from the configured control plane.">
          <div className="access-state-card">
            <div className="access-state-icon" aria-hidden="true">↔</div>
            <div>
              <div className="summary-label">Endpoint status</div>
              <div className="summary-value">{access.controlPlane.detail}</div>
            </div>
            <CapabilityBadge state={access.controlPlane.state} />
          </div>
          <button className="secondary-button full-width-button" type="button" disabled title="Control-plane configuration is not wired to this local adapter">Configure endpoint</button>
        </SectionCard>

        <SectionCard title="Pairing" description="Pairing material stays inside the trusted adapter boundary and is never rendered here.">
          <div className="pairing-panel">
            <div className="summary-label">Pairing state</div>
            <div className="pairing-state-line">
              <span className="pairing-state-name">{access.pairing.state.replaceAll("-", " ")}</span>
              <CapabilityBadge state={access.pairing.state === "ready" ? "available" : access.pairing.state === "pending" ? "pending" : "unavailable"} />
            </div>
            <p>{access.pairing.detail}</p>
          </div>
        </SectionCard>
      </div>

      <SectionCard title="Trusted devices" description="Only devices authorized by the control plane will be listed.">
        {access.trustedDevices.length === 0 ? (
          <EmptyState
            title="No trusted devices"
            description="There are no device records in the local adapter. Add a device after the control plane is configured."
          />
        ) : (
          <div className="device-list">
            {access.trustedDevices.map((device) => (
              <div className="device-row" key={device.id}>
                <div className="device-avatar" aria-hidden="true">{device.name.slice(0, 1).toUpperCase()}</div>
                <div>
                  <h3>{device.name}</h3>
                  <p>{device.platform} · Added {device.addedAt}</p>
                </div>
                <span className={`device-status device-status-${device.status}`}>{device.status}</span>
              </div>
            ))}
          </div>
        )}
      </SectionCard>
    </div>
  );
}
