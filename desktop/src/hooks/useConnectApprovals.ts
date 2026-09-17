import { useCallback, useEffect, useRef, useState } from "react";

import type { ProductAdapter } from "../adapters/productAdapter";
import type { ConnectRequest, PermissionSet } from "../model";

/** Base polling cadence for incoming Secure Connect requests. */
const POLL_BASE_MS = 2000;
/** Upper bound the error backoff grows to, so a broken broker is not hammered. */
const POLL_MAX_MS = 30000;

interface QueuedRequest {
  request: ConnectRequest;
  /** Epoch-ms deadline, fixed when the request first enters the queue. */
  deadline: number;
}

export interface ConnectApprovals {
  /** The request currently awaiting an answer, or null when none is pending. */
  current: ConnectRequest | null;
  /** Whole seconds until the current request expires, or null when none. */
  secondsRemaining: number | null;
  /** True while an approve/deny call is in flight; controls should disable. */
  pending: boolean;
  /** A recoverable failure message to show while keeping the request visible. */
  error: string | null;
  approve: (granted?: PermissionSet) => void;
  deny: () => void;
}

/**
 * Owns the incoming Secure Connect approval flow: a background poll (only while
 * `enabled`), a de-duplicated, serialized queue of requests, per-request
 * expiration, and idempotent approve/deny with retry.
 *
 * Deliberate properties, matching the host security model:
 * - polls only while `enabled` (the caller passes hosting && authenticated);
 * - pauses while the document is hidden or the browser is offline;
 * - backs off on poll errors;
 * - de-duplicates by request id and shows one request at a time;
 * - defaults to denial on expiration -- an expired request is dropped, never
 *   auto-approved, and a poll or command failure never approves anything;
 * - keeps a request visible after a recoverable approve/deny failure so the
 *   operator can retry.
 */
export function useConnectApprovals(
  adapter: ProductAdapter,
  options: { enabled: boolean; onResolved: () => void },
): ConnectApprovals {
  const { enabled, onResolved } = options;
  const [queue, setQueue] = useState<QueuedRequest[]>([]);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());

  // Latest onResolved without retriggering the poll effect.
  const onResolvedRef = useRef(onResolved);
  onResolvedRef.current = onResolved;

  // Background poll. Only runs while enabled; clears any stale queue otherwise.
  useEffect(() => {
    if (!enabled) {
      setQueue((previous) => (previous.length === 0 ? previous : []));
      return;
    }
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let backoff = POLL_BASE_MS;

    const mergeIncoming = (incoming: ConnectRequest[]) => {
      setQueue((previous) => {
        const nowMs = Date.now();
        const knownIds = new Set(previous.map((entry) => entry.request.requestId));
        const incomingIds = new Set(incoming.map((request) => request.requestId));
        // Keep existing entries still advertised by the broker, preserving
        // their fixed deadline and their order.
        const next = previous.filter((entry) => incomingIds.has(entry.request.requestId));
        // Append newly seen requests, de-duplicated by id.
        for (const request of incoming) {
          if (!knownIds.has(request.requestId)) {
            next.push({ request, deadline: nowMs + request.expiresInSeconds * 1000 });
          }
        }
        return next.length === previous.length &&
          next.every((entry, index) => entry === previous[index])
          ? previous
          : next;
      });
    };

    const paused = () =>
      (typeof document !== "undefined" && document.hidden) ||
      (typeof navigator !== "undefined" && navigator.onLine === false);

    const poll = () => {
      if (cancelled) {
        return;
      }
      if (paused()) {
        timer = setTimeout(poll, POLL_BASE_MS);
        return;
      }
      adapter
        .hostConnectRequests()
        .then((requests) => {
          if (cancelled) {
            return;
          }
          mergeIncoming(requests);
          backoff = POLL_BASE_MS;
        })
        .catch(() => {
          backoff = Math.min(backoff * 2, POLL_MAX_MS);
        })
        .finally(() => {
          if (!cancelled) {
            timer = setTimeout(poll, backoff);
          }
        });
    };

    poll();
    return () => {
      cancelled = true;
      if (timer !== undefined) {
        clearTimeout(timer);
      }
    };
  }, [adapter, enabled]);

  // Tick once a second while a request is shown, to drive the countdown.
  useEffect(() => {
    if (queue.length === 0) {
      return;
    }
    const tick = () => setNow(Date.now());
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [queue.length]);

  // Drop expired requests. This is the default-deny path: an expired request is
  // removed without ever being approved. A request mid-action is left in place
  // until its call resolves.
  useEffect(() => {
    if (pending) {
      return;
    }
    setQueue((previous) => {
      const live = previous.filter((entry) => entry.deadline > now);
      return live.length === previous.length ? previous : live;
    });
  }, [now, pending]);

  const head = queue[0] ?? null;
  const headId = head?.request.requestId ?? null;

  // A stale error must not carry over to a different request.
  useEffect(() => {
    setError(null);
  }, [headId]);

  const resolve = useCallback(
    (action: "approve" | "deny", granted?: PermissionSet) => {
      if (!head || pending) {
        return;
      }
      const requestId = head.request.requestId;
      setPending(true);
      setError(null);
      const call =
        action === "approve"
          ? adapter.approveConnectRequest(requestId, granted)
          : adapter.denyConnectRequest(requestId);
      call
        .then(() => {
          setQueue((previous) =>
            previous.filter((entry) => entry.request.requestId !== requestId),
          );
          onResolvedRef.current();
        })
        .catch(() => {
          setError(
            action === "approve"
              ? "Could not approve the request. It is still pending; try again."
              : "Could not deny the request. It is still pending; try again.",
          );
        })
        .finally(() => setPending(false));
    },
    [adapter, head, pending],
  );

  return {
    current: head?.request ?? null,
    secondsRemaining: head ? Math.max(0, Math.ceil((head.deadline - now) / 1000)) : null,
    pending,
    error,
    approve: (granted?: PermissionSet) => resolve("approve", granted),
    deny: () => resolve("deny"),
  };
}
