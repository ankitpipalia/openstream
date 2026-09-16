export type PageId = "computers" | "access" | "settings" | "diagnostics" | "about";

export const navigationItems: ReadonlyArray<{ id: PageId; label: string; hint: string }> = [
  { id: "computers", label: "Computers", hint: "Discover and connect to hosts" },
  { id: "access", label: "Access", hint: "Pairing and trusted devices" },
  { id: "settings", label: "Settings", hint: "Desktop and stream preferences" },
  { id: "diagnostics", label: "Diagnostics", hint: "Capabilities and checks" },
  { id: "about", label: "About", hint: "Version and project details" },
];

export type CapabilityState = "available" | "pending" | "unavailable" | "experimental" | "not-implemented";

export interface Capability {
  id: string;
  label: string;
  state: CapabilityState;
  detail: string;
}

export type ComputerStatus = "online" | "offline" | "pending" | "unavailable";

export interface Computer {
  id: string;
  name: string;
  platform: string;
  status: ComputerStatus;
  detail: string;
  lastSeen?: string;
  capabilities: Capability[];
}

export type ConnectionState = "idle" | "connecting" | "connected" | "unavailable";

export interface ConnectionSnapshot {
  state: ConnectionState;
  detail: string;
  computerId?: string;
}

/**
 * An incoming Secure Connect request this device is being asked to answer.
 *
 * `requested` is what the requester asked for, carried through the broker so
 * the host approves against the actual request rather than a blanket grant. It
 * is optional so a control plane that predates permission negotiation still
 * renders (the modal then falls back to the host's policy note). The
 * requester's account and target host are still not part of the payload.
 */
export interface ConnectRequest {
  requestId: string;
  requesterDeviceId: string;
  expiresInSeconds: number;
  requested?: PermissionSet;
}

export interface PermissionSet {
  view: boolean;
  keyboard: boolean;
  mouse: boolean;
  gamepad: boolean;
  clipboard: boolean;
  microphone: boolean;
  tablet: boolean;
  virtual_usb: boolean;
}

/**
 * The only commands the WebView may express. Every authoritative outcome --
 * authentication succeeding, negotiation, a session actually connecting or
 * dropping, host readiness or failure, and the passage of time -- is
 * decided in Rust and deliberately has no constructor here. `request_id`
 * and `now_ms` are likewise Rust-owned: the runtime reads its own clock and
 * mints its own request ids, so neither is ever supplied by this side.
 */
export type RuntimeCommand =
  | "SignIn"
  | "SignOut"
  | { Connect: { device_id: string; requested: PermissionSet } }
  | { ApproveRequest: { request_id: string; available: PermissionSet } }
  | { RejectRequest: { request_id: string } }
  | "Disconnect"
  | "ClearFailure"
  | "EnableHosting"
  | "DisableHosting"
  | "RestartHosting";

export type PairingState = "not-configured" | "pending" | "ready" | "unavailable";

export interface TrustedDevice {
  id: string;
  name: string;
  platform: string;
  addedAt: string;
  status: DeviceTrustState;
  /** Short display fingerprint; never the raw public key. */
  fingerprint?: string;
}

export type DeviceTrustState = "trusted" | "pending" | "revoked";

export interface AccessSnapshot {
  pairing: {
    state: PairingState;
    detail: string;
  };
  controlPlane: Capability;
  trustedDevices: TrustedDevice[];
  /**
   * True when the desktop runs in local mode (no control plane). Carried as a
   * structured flag so the UI never has to infer the mode from a human-readable
   * detail string, which silently broke when the wording or casing changed.
   */
  localMode: boolean;
}

export interface SettingItem {
  id: string;
  label: string;
  description: string;
  value: string | number | boolean;
  state: CapabilityState;
  options?: string[];
  scope?: SettingScope;
  applyMode?: SettingApplyMode;
  visibility?: SettingVisibility;
}

export type SettingScope = "global" | "client" | "host" | "device" | "session";
export type SettingApplyMode = "live" | "reconnect" | "restart_host" | "restart_application";
export type SettingVisibility = "normal" | "advanced" | "experimental";

export interface SettingSection {
  id: string;
  label: string;
  description: string;
  items: SettingItem[];
}

export type SessionState = "idle" | "starting" | "running" | "stopped" | "unavailable";

export interface DiagnosticsSnapshot {
  session: {
    state: SessionState;
    detail: string;
  };
  checks: Capability[];
  transport: Capability[];
}

export interface ProductSnapshot {
  product: {
    name: string;
    version: string;
    channel: string;
  };
  connection: ConnectionSnapshot;
  computers: Computer[];
  access: AccessSnapshot;
  settings: SettingSection[];
  capabilities: Capability[];
  diagnostics: DiagnosticsSnapshot;
  /**
   * Optional because not every adapter (for example the fixture-driven
   * local adapter) sources these from a runtime snapshot; a Tauri-backed
   * adapter always sets them.
   */
  restartRequired?: boolean;
  hostRestartRequired?: boolean;
  pendingSettingKeys?: string[];
}

export function capabilityLabel(state: CapabilityState): string {
  switch (state) {
    case "available":
      return "Available";
    case "pending":
      return "Checking";
    case "experimental":
      return "Experimental";
    case "unavailable":
      return "Unavailable";
    case "not-implemented":
      return "Not implemented";
  }
}

export function computerStatusLabel(status: ComputerStatus): string {
  switch (status) {
    case "online":
      return "Online";
    case "offline":
      return "Offline";
    case "pending":
      return "Checking";
    case "unavailable":
      return "Unavailable";
  }
}

export function sessionStateLabel(state: SessionState): string {
  switch (state) {
    case "idle":
      return "Idle";
    case "starting":
      return "Starting";
    case "running":
      return "Running";
    case "stopped":
      return "Stopped";
    case "unavailable":
      return "Unavailable";
  }
}

/**
 * The permission classes a request is asking for, as human labels in a stable
 * order. Empty when nothing is requested, so the caller can fall back to the
 * host's policy note.
 */
export function requestedPermissionLabels(requested: PermissionSet): string[] {
  const labels: Array<[keyof PermissionSet, string]> = [
    ["view", "Screen"],
    ["keyboard", "Keyboard"],
    ["mouse", "Mouse"],
    ["gamepad", "Gamepad"],
    ["clipboard", "Clipboard"],
    ["microphone", "Microphone"],
    ["tablet", "Tablet"],
    ["virtual_usb", "USB devices"],
  ];
  return labels.filter(([key]) => requested[key]).map(([, label]) => label);
}
