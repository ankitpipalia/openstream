import { useState } from "react";

import type { ProductAdapter } from "../adapters/productAdapter";
import { createRuntimeUnavailableSnapshot } from "../adapters/productAdapter";
import type { ProductSnapshot } from "../model";
import { CapabilityBadge, ComputerStatusBadge } from "../components/StatusBadge";
import { EmptyState, PageHeader, SectionCard } from "../components/AppShell";

export function ComputersPage({
  snapshot,
  adapter,
  onSnapshot,
}: {
  snapshot: ProductSnapshot;
  adapter: ProductAdapter;
  onSnapshot: (snapshot: ProductSnapshot) => void;
}) {
  const [refreshing, setRefreshing] = useState(false);
  const [action, setAction] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const controlPlane = snapshot.access.controlPlane;

  async function handleConnect(deviceId: string) {
    setAction(deviceId);
    setActionError(null);
    try {
      onSnapshot(
        await adapter.dispatch({
          Connect: {
            device_id: deviceId,
            requested: {
              view: true,
              keyboard: true,
              mouse: true,
              gamepad: false,
              clipboard: false,
              microphone: false,
              tablet: false,
              virtual_usb: false,
            },
          },
        }),
      );
    } catch {
      // A connect failure is usually recoverable (host offline, session could
      // not start). Surface it inline and keep the current view; wiping the
      // whole snapshot to a runtime-unavailable placeholder would throw away
      // settings, the computer list, diagnostics, and access state over a
      // routine, retryable error.
      setActionError("The session could not be started. The host may be offline; try again.");
    } finally {
      setAction(null);
    }
  }

  async function handleDisconnect() {
    setAction("disconnect");
    setActionError(null);
    try {
      onSnapshot(await adapter.dispatch("Disconnect"));
    } catch {
      setActionError("The session could not be stopped cleanly. Refresh to see the current state.");
    } finally {
      setAction(null);
    }
  }

  async function handleRefresh() {
    setRefreshing(true);
    try {
      onSnapshot(await adapter.refresh());
    } catch {
      onSnapshot(createRuntimeUnavailableSnapshot("The runtime bridge did not respond."));
    } finally {
      setRefreshing(false);
    }
  }

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Workspace"
        title="Computers"
        description="Discover trusted OpenStream hosts and start a session when the control plane reports one as available."
        actions={
          <>
            {snapshot.connection.state !== "idle" ? (
              <button className="secondary-button" type="button" onClick={handleDisconnect} disabled={action !== null}>
                Disconnect
              </button>
            ) : null}
            <button className="secondary-button" type="button" onClick={handleRefresh} disabled={refreshing || action !== null}>
              Refresh
            </button>
          </>
        }
      />

      {actionError ? <div className="error-banner" role="alert">{actionError}</div> : null}

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
                  <button
                    className="secondary-button"
                    type="button"
                    onClick={() => handleConnect(computer.id)}
                    disabled={computer.status !== "online" || action !== null}
                  >
                    {action === computer.id ? "Starting…" : snapshot.connection.computerId === computer.id ? "Connected" : "Connect"}
                  </button>
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
