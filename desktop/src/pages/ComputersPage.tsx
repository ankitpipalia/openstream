import type { ProductSnapshot } from "../model";
import { CapabilityBadge, ComputerStatusBadge } from "../components/StatusBadge";
import { EmptyState, PageHeader, SectionCard } from "../components/AppShell";

export function ComputersPage({ snapshot }: { snapshot: ProductSnapshot }) {
  const controlPlane = snapshot.access.controlPlane;

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Workspace"
        title="Computers"
        description="Discover trusted OpenStream hosts and start a session when the control plane reports one as available."
        actions={<button className="secondary-button" type="button" disabled title="Refresh is waiting for the control-plane adapter">Refresh</button>}
      />

      <SectionCard title="Your computers" description="Only hosts reported by the configured control plane appear here.">
        {snapshot.computers.length === 0 ? (
          <EmptyState
            title="No computers discovered yet"
            description="OpenStream has not received a host record. Configure Access first, then return here when discovery is available."
          />
        ) : (
          <div className="computer-list">
            {snapshot.computers.map((computer) => (
              <article className="computer-row" key={computer.id}>
                <div className="computer-avatar" aria-hidden="true">{computer.name.slice(0, 1).toUpperCase()}</div>
                <div className="computer-main">
                  <div className="computer-title-line">
                    <h3>{computer.name}</h3>
                    <ComputerStatusBadge status={computer.status} />
                  </div>
                  <p>{computer.platform} · {computer.detail}</p>
                  {computer.lastSeen ? <span className="muted-label">Last seen {computer.lastSeen}</span> : null}
                </div>
                <div className="computer-actions">
                  <button className="secondary-button" type="button" disabled title="The session command adapter is not connected">Connect</button>
                </div>
              </article>
            ))}
          </div>
        )}
      </SectionCard>

      <SectionCard title="Discovery status" description="The shell keeps discovery state separate from host readiness.">
        <div className="capability-summary">
          <div className="capability-summary-main">
            <div className="summary-label">Control plane</div>
            <div className="summary-value">{controlPlane.detail}</div>
          </div>
          <CapabilityBadge state={controlPlane.state} />
        </div>
      </SectionCard>
    </div>
  );
}
