import { useState } from "react";

import type { ProductSnapshot } from "../model";
import { CapabilityBadge } from "../components/StatusBadge";
import { EmptyState, PageHeader, SectionCard } from "../components/AppShell";
import type { ProductAdapter } from "../adapters/productAdapter";

export function AccessPage({
  snapshot,
  adapter,
  onSnapshot,
}: {
  snapshot: ProductSnapshot;
  adapter: ProductAdapter;
  onSnapshot: (snapshot: ProductSnapshot) => void;
}) {
  const { access } = snapshot;
  const signedIn = access.pairing.state === "ready";
  const localMode = access.localMode;
  const [authMode, setAuthMode] = useState<"sign-in" | "register">("sign-in");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [authError, setAuthError] = useState<string | null>(null);
  const [authPending, setAuthPending] = useState(false);

  async function authenticate() {
    setAuthPending(true);
    setAuthError(null);
    try {
      const next = authMode === "register"
        ? await adapter.registerAccount(username, password)
        : await adapter.signIn(username, password);
      setPassword("");
      onSnapshot(next);
    } catch {
      // Never render a server/parser error here: it could contain a URL,
      // account identifier, or an implementation detail that belongs only in
      // the redacted diagnostic channel.
      setAuthError("Authentication failed. Check the account details and control-plane endpoint.");
    } finally {
      setAuthPending(false);
    }
  }

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Trust and pairing"
        title="Access"
        description="Manage the control-plane boundary and the devices allowed to discover this OpenStream installation."
        actions={
          signedIn ? (
            <button
              className="secondary-button"
              type="button"
              disabled={authPending}
              onClick={() => {
                setAuthPending(true);
                void adapter
                  .signOut()
                  .then(onSnapshot)
                  .catch(() => setAuthError("Could not sign out of the control plane."))
                  .finally(() => setAuthPending(false));
              }}
            >
              Sign out
            </button>
          ) : (
            <button className="primary-button" type="button" disabled title="Device enrollment is managed after sign-in">Add device</button>
          )
        }
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

      {localMode ? (
        <SectionCard title="Account" description="This local development mode does not require account authentication.">
          <p className="section-note">Use a configured HTTPS control plane for durable accounts, device enrollment and remote discovery.</p>
        </SectionCard>
      ) : signedIn ? (
        <SectionCard title="Account" description="This desktop is authenticated. Bearer credentials remain in the native runtime.">
          <div className="access-state-card">
            <div className="access-state-icon" aria-hidden="true">✓</div>
            <div>
              <div className="summary-label">Authentication</div>
              <div className="summary-value">Signed in and ready</div>
            </div>
            <CapabilityBadge state="available" />
          </div>
        </SectionCard>
      ) : (
        <SectionCard
          title={authMode === "register" ? "Create account" : "Sign in"}
          description="Use the self-hosted control plane to enroll this device and discover trusted hosts."
        >
          <form
            className="auth-form"
            onSubmit={(event) => {
              event.preventDefault();
              void authenticate();
            }}
          >
            <label className="auth-field">
              <span>Username</span>
              <input
                className="setting-text-input"
                autoComplete="username"
                value={username}
                onChange={(event) => setUsername(event.currentTarget.value)}
                minLength={3}
                maxLength={128}
                required
              />
            </label>
            <label className="auth-field">
              <span>Password</span>
              <input
                className="setting-text-input"
                type="password"
                autoComplete={authMode === "register" ? "new-password" : "current-password"}
                value={password}
                onChange={(event) => setPassword(event.currentTarget.value)}
                minLength={12}
                maxLength={256}
                required
              />
            </label>
            {authError ? <div className="error-banner" role="alert">{authError}</div> : null}
            <div className="auth-actions">
              <button className="primary-button" type="submit" disabled={authPending}>
                {authPending ? "Working…" : authMode === "register" ? "Create account" : "Sign in"}
              </button>
              <button
                className="secondary-button"
                type="button"
                disabled={authPending}
                onClick={() => {
                  setAuthMode(authMode === "register" ? "sign-in" : "register");
                  setAuthError(null);
                }}
              >
                {authMode === "register" ? "Use existing account" : "Create an account"}
              </button>
            </div>
          </form>
        </SectionCard>
      )}

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
                <div className="device-actions">
                  <span className={`device-status device-status-${device.status}`}>{device.status}</span>
                  {device.status === "revoked" ? (
                    <button
                      className="secondary-button"
                      type="button"
                      onClick={() => {
                        void adapter
                          .setDeviceTrust(device.id, "trusted")
                          .then(onSnapshot)
                          .catch(() => setAuthError("Could not update device trust."));
                      }}
                    >
                      Restore
                    </button>
                  ) : (
                    <button
                      className="secondary-button"
                      type="button"
                      onClick={() => {
                        void adapter
                          .setDeviceTrust(device.id, "revoked")
                          .then(onSnapshot)
                          .catch(() => setAuthError("Could not update device trust."));
                      }}
                    >
                      Revoke
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </SectionCard>
    </div>
  );
}
