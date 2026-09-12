import { capabilityLabel, computerStatusLabel, sessionStateLabel } from "../model";
import type { CapabilityState, ComputerStatus, SessionState } from "../model";

interface BadgeProps {
  label: string;
  tone: CapabilityState | "online" | "offline" | "idle" | "starting" | "running" | "stopped";
}

export function StatusBadge({ label, tone }: BadgeProps) {
  return (
    <span className={`status-badge status-${tone}`}>
      <span className="status-dot" aria-hidden="true" />
      {label}
    </span>
  );
}

export function CapabilityBadge({ state }: { state: CapabilityState }) {
  return <StatusBadge label={capabilityLabel(state)} tone={state} />;
}

export function ComputerStatusBadge({ status }: { status: ComputerStatus }) {
  const tone = status === "online" ? "online" : status === "offline" ? "offline" : status === "pending" ? "pending" : "unavailable";
  return <StatusBadge label={computerStatusLabel(status)} tone={tone} />;
}

export function SessionStatusBadge({ state }: { state: SessionState }) {
  const tone = state === "running" ? "running" : state === "starting" ? "starting" : state === "stopped" ? "stopped" : state === "idle" ? "idle" : "unavailable";
  return <StatusBadge label={sessionStateLabel(state)} tone={tone} />;
}
