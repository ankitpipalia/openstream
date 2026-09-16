import { useMemo, useState } from "react";
import type { ConnectRequest, PermissionSet } from "../model";

/** The permission classes, as [key, label], in a stable display order. */
const PERMISSION_CLASSES: ReadonlyArray<readonly [keyof PermissionSet, string]> = [
  ["view", "Screen"],
  ["keyboard", "Keyboard"],
  ["mouse", "Mouse"],
  ["gamepad", "Gamepad"],
  ["clipboard", "Clipboard"],
  ["microphone", "Microphone"],
  ["tablet", "Tablet"],
  ["virtual_usb", "USB devices"],
];

const NO_PERMISSIONS: PermissionSet = {
  view: false,
  keyboard: false,
  mouse: false,
  gamepad: false,
  clipboard: false,
  microphone: false,
  tablet: false,
  virtual_usb: false,
};

/**
 * The approval prompt for one incoming Secure Connect request.
 *
 * Rendered app-wide (above every page) so an approval is never missed. It shows
 * the requesting device, the time left, and -- when the broker carries them --
 * a checkbox per requested permission class, pre-checked, so the host grants
 * exactly what it allows (only ever a subset of what was asked). When the broker
 * carries no request, it falls back to the host's configured policy and grants
 * `undefined`, leaving the choice to the server-derived default.
 */
export function ConnectApprovalModal({
  request,
  secondsRemaining,
  pending,
  error,
  onApprove,
  onDeny,
}: {
  request: ConnectRequest;
  secondsRemaining: number | null;
  pending: boolean;
  error: string | null;
  onApprove: (granted: PermissionSet | undefined) => void;
  onDeny: () => void;
}) {
  const countdown =
    secondsRemaining === null
      ? null
      : secondsRemaining > 0
        ? `Expires in ${secondsRemaining}s`
        : "Expiring…";

  // The classes the requester asked for, in display order.
  const requestedClasses = useMemo(
    () =>
      request.requested
        ? PERMISSION_CLASSES.filter(([key]) => request.requested?.[key])
        : [],
    [request.requested],
  );

  // Each requested class starts checked; the host may uncheck to grant less. Any
  // class not requested is never grantable here, so it is never offered.
  const [checked, setChecked] = useState<Partial<Record<keyof PermissionSet, boolean>>>(() =>
    Object.fromEntries(requestedClasses.map(([key]) => [key, true])),
  );

  const toggle = (key: keyof PermissionSet) =>
    setChecked((previous) => ({ ...previous, [key]: !previous[key] }));

  const approve = () => {
    if (requestedClasses.length === 0) {
      // Nothing was requested; leave the grant to the server-derived default.
      onApprove(undefined);
      return;
    }
    const granted: PermissionSet = { ...NO_PERMISSIONS };
    for (const [key] of requestedClasses) {
      granted[key] = Boolean(checked[key]);
    }
    onApprove(granted);
  };

  return (
    <div className="modal-backdrop" role="presentation">
      <div
        className="modal-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="connect-approval-title"
      >
        <h2 id="connect-approval-title">Incoming connection request</h2>
        <p className="modal-lead">A device is asking to start a session on this computer.</p>

        <dl className="modal-facts">
          <div>
            <dt>Requesting device</dt>
            <dd className="modal-monospace">{request.requesterDeviceId}</dd>
          </div>
          {countdown ? (
            <div>
              <dt>Time to answer</dt>
              <dd>{countdown}</dd>
            </div>
          ) : null}
        </dl>

        {requestedClasses.length > 0 ? (
          <div className="modal-permissions">
            <p className="modal-note">This device is requesting access. Grant only what you allow:</p>
            <ul className="modal-permission-list" aria-label="Requested access">
              {requestedClasses.map(([key, label]) => (
                <li key={key}>
                  <label>
                    <input
                      type="checkbox"
                      checked={Boolean(checked[key])}
                      onChange={() => toggle(key)}
                      disabled={pending}
                    />
                    {label}
                  </label>
                </li>
              ))}
            </ul>
            <p className="modal-note">
              Only the checked access is granted. Deny if you did not expect this request.
            </p>
          </div>
        ) : (
          <p className="modal-note">
            The session is granted the input and device access allowed by this host's
            configured policy. Deny if you did not expect this request.
          </p>
        )}

        {error ? (
          <div className="error-banner" role="alert">
            {error}
          </div>
        ) : null}

        <div className="modal-actions">
          <button
            className="secondary-button"
            type="button"
            onClick={onDeny}
            disabled={pending}
          >
            Deny
          </button>
          <button
            className="primary-button"
            type="button"
            onClick={approve}
            disabled={pending}
          >
            {pending ? "Working…" : "Approve"}
          </button>
        </div>
      </div>
    </div>
  );
}
