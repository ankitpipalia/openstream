import { useState } from "react";

import type { Capability, ProductSnapshot } from "../model";
import type { ProductAdapter } from "../adapters/productAdapter";
import { CapabilityBadge, SessionStatusBadge } from "../components/StatusBadge";
import { PageHeader, SectionCard } from "../components/AppShell";

function CapabilityRow({ capability }: { capability: Capability }) {
  return (
    <div className="diagnostic-row">
      <div>
        <h3>{capability.label}</h3>
        <p>{capability.detail}</p>
      </div>
      <CapabilityBadge state={capability.state} />
    </div>
  );
}

export function DiagnosticsPage({
  snapshot,
  adapter,
  onSnapshot,
}: {
  snapshot: ProductSnapshot;
  adapter: ProductAdapter;
  onSnapshot: (snapshot: ProductSnapshot) => void;
}) {
  const { diagnostics } = snapshot;
  const [refreshing, setRefreshing] = useState(false);

  async function runChecks() {
    setRefreshing(true);
    try {
      onSnapshot(await adapter.refresh());
    } catch {
      // The parent poll will retry. Keep this page's error surface bounded to
      // a static message rather than exposing bridge or server details.
    } finally {
      setRefreshing(false);
    }
  }

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Observability"
        title="Diagnostics"
        description="See what OpenStream has actually verified. Pending and unavailable states are intentionally explicit."
        actions={<button className="secondary-button" type="button" onClick={() => void runChecks()} disabled={refreshing}>{refreshing ? "Checking…" : "Run checks"}</button>}
      />

      <div className="diagnostics-overview">
        <div className="overview-card overview-card-accent">
          <div className="summary-label">Session state</div>
          <div className="overview-value"><SessionStatusBadge state={diagnostics.session.state} /></div>
          <p>{diagnostics.session.detail}</p>
        </div>
        <div className="overview-card">
          <div className="summary-label">Known capabilities</div>
          <div className="overview-value">{snapshot.capabilities.filter((capability) => capability.state === "available").length} available</div>
          <p>Availability is reported by the adapter, not inferred from UI controls.</p>
        </div>
      </div>

      <SectionCard title="Preflight checks" description="These checks do not contain credentials or raw pairing material.">
        <div className="diagnostic-list">
          {diagnostics.checks.map((capability) => <CapabilityRow key={capability.id} capability={capability} />)}
        </div>
      </SectionCard>

      <SectionCard title="Transport paths" description="A transport is selected only after host discovery and session negotiation.">
        <div className="diagnostic-list">
          {diagnostics.transport.map((capability) => <CapabilityRow key={capability.id} capability={capability} />)}
        </div>
      </SectionCard>
    </div>
  );
}
