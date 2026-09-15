import type { ConnectRequest } from "../model";

/**
 * The approval prompt for one incoming Secure Connect request.
 *
 * Rendered app-wide (above every page) so an approval is never missed because
 * of where the operator happened to be. It shows only what the broker's
 * pending-request payload carries today -- the requesting device and the time
 * left -- and leaves granted permissions to the host's configured policy.
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
  onApprove: () => void;
  onDeny: () => void;
}) {
  const countdown =
    secondsRemaining === null
      ? null
      : secondsRemaining > 0
        ? `Expires in ${secondsRemaining}s`
        : "Expiring…";

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

        <p className="modal-note">
          The session is granted the input and device access allowed by this host's
          configured policy. Deny if you did not expect this request.
        </p>

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
            onClick={onApprove}
            disabled={pending}
          >
            {pending ? "Working…" : "Approve"}
          </button>
        </div>
      </div>
    </div>
  );
}
