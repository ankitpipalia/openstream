import { useEffect, useRef, useState } from "react";

import type { ProductAdapter } from "../adapters/productAdapter";
import type { ProductSnapshot } from "../model";

/** The control-plane endpoint setting the login screen lets the operator edit
 * before signing in, since a bearer token is only meaningful against the origin
 * it was issued by. */
const SIGNAL_ORIGIN_SETTING = "client.signal_origin";

/** The current control-plane origin, read from the settings snapshot so the
 * field is pre-filled with what the runtime will actually use. */
function currentSignalOrigin(snapshot: ProductSnapshot): string {
  for (const section of snapshot.settings) {
    for (const item of section.items) {
      if (item.id === SIGNAL_ORIGIN_SETTING && typeof item.value === "string") {
        return item.value;
      }
    }
  }
  return "";
}

/**
 * The front door: shown before anything else when this desktop is configured
 * against a control plane and is not signed in. A user logs in (or creates an
 * account) here first, and can edit the control-plane endpoint before doing so,
 * after which the unified Computers / Access / Settings shell unlocks.
 *
 * Local development mode (`access.localMode`) never reaches this screen -- it
 * requires no account -- so the gate is purely the Secure-mode front door.
 */
export function LoginPage({
  snapshot,
  adapter,
  onSnapshot,
}: {
  snapshot: ProductSnapshot;
  adapter: ProductAdapter;
  onSnapshot: (snapshot: ProductSnapshot) => void;
}) {
  const [authMode, setAuthMode] = useState<"sign-in" | "register">("sign-in");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [authError, setAuthError] = useState<string | null>(null);
  const [authPending, setAuthPending] = useState(false);

  const [showEndpoint, setShowEndpoint] = useState(false);
  const configuredEndpoint = currentSignalOrigin(snapshot);
  const [endpoint, setEndpoint] = useState(configuredEndpoint);
  const [endpointPending, setEndpointPending] = useState(false);
  const [endpointSaved, setEndpointSaved] = useState(false);
  const [endpointError, setEndpointError] = useState<string | null>(null);
  /// Whether the operator has typed in the field since it was last filled in
  /// from the runtime. Their text always wins over a later snapshot.
  const [endpointEdited, setEndpointEdited] = useState(false);
  const lastConfiguredEndpoint = useRef(configuredEndpoint);

  // The first snapshot this page renders against is the adapter's unresolved
  // placeholder, which carries no settings -- so the initial value here can be
  // empty even when a perfectly good endpoint is configured. The real snapshot
  // arrives a moment later, and without this the field kept the empty string:
  // opening "Edit control-plane endpoint" then showed nothing, and saving it
  // wrote that nothing over the working endpoint.
  useEffect(() => {
    if (configuredEndpoint === lastConfiguredEndpoint.current) {
      return;
    }
    lastConfiguredEndpoint.current = configuredEndpoint;
    if (!endpointEdited) {
      setEndpoint(configuredEndpoint);
    }
  }, [configuredEndpoint, endpointEdited]);

  async function authenticate() {
    setAuthPending(true);
    setAuthError(null);
    try {
      const next =
        authMode === "register"
          ? await adapter.registerAccount(username, password)
          : await adapter.signIn(username, password);
      setPassword("");
      onSnapshot(next);
    } catch {
      // Never surface a server/parser error verbatim: it can carry a URL, an
      // account identifier, or an implementation detail that belongs only in
      // the redacted diagnostic channel.
      setAuthError(
        "Sign in failed. Check the account details and the control-plane endpoint.",
      );
    } finally {
      setAuthPending(false);
    }
  }

  async function saveEndpoint() {
    setEndpointPending(true);
    setEndpointError(null);
    setEndpointSaved(false);
    try {
      const next = await adapter.updateSetting(SIGNAL_ORIGIN_SETTING, endpoint.trim());
      onSnapshot(next);
      setEndpointSaved(true);
      // Their edit is now the configured value, so later snapshots may drive
      // the field again.
      setEndpointEdited(false);
    } catch {
      setEndpointError("Could not update the control-plane endpoint.");
    } finally {
      setEndpointPending(false);
    }
  }

  return (
    <div className="login-screen">
      <div className="login-card">
        <div className="login-brand">
          <div className="login-mark" aria-hidden="true">
            {snapshot.product.name.slice(0, 1) || "O"}
          </div>
          <div>
            <h1 className="login-title">{snapshot.product.name}</h1>
            <p className="login-subtitle">
              {authMode === "register"
                ? "Create an account to host and connect to your computers."
                : "Sign in to host and connect to your computers."}
            </p>
          </div>
        </div>

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
              autoFocus
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
          {authError ? (
            <div className="error-banner" role="alert">
              {authError}
            </div>
          ) : null}
          <div className="auth-actions">
            <button className="primary-button" type="submit" disabled={authPending}>
              {authPending
                ? "Working…"
                : authMode === "register"
                  ? "Create account"
                  : "Sign in"}
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
              {authMode === "register" ? "Use an existing account" : "Create an account"}
            </button>
          </div>
        </form>

        <div className="login-endpoint">
          <button
            className="link-button"
            type="button"
            aria-expanded={showEndpoint}
            onClick={() => setShowEndpoint((open) => !open)}
          >
            {showEndpoint ? "Hide control-plane endpoint" : "Edit control-plane endpoint"}
          </button>
          {showEndpoint ? (
            <div className="login-endpoint-body">
              <label className="auth-field">
                <span>Control-plane endpoint</span>
                <input
                  className="setting-text-input"
                  inputMode="url"
                  placeholder="https://control.example.com"
                  value={endpoint}
                  onChange={(event) => {
                    setEndpoint(event.currentTarget.value);
                    setEndpointEdited(true);
                    setEndpointSaved(false);
                  }}
                />
              </label>
              <p className="section-note">
                Changing this signs out any existing session, because a bearer
                credential must never travel to a different origin.
              </p>
              {endpointError ? (
                <div className="error-banner" role="alert">
                  {endpointError}
                </div>
              ) : null}
              <div className="auth-actions">
                <button
                  className="secondary-button"
                  type="button"
                  disabled={endpointPending}
                  onClick={() => void saveEndpoint()}
                >
                  {endpointPending ? "Saving…" : "Save endpoint"}
                </button>
                {endpointSaved ? <span className="section-note">Saved to this device.</span> : null}
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
