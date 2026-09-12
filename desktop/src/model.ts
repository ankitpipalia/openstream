export type PageId = "computers" | "access" | "settings" | "diagnostics" | "about";

export const navigationItems: ReadonlyArray<{ id: PageId; label: string; hint: string }> = [
  { id: "computers", label: "Computers", hint: "Discover and connect to hosts" },
  { id: "access", label: "Access", hint: "Pairing and trusted devices" },
  { id: "settings", label: "Settings", hint: "Desktop and stream preferences" },
  { id: "diagnostics", label: "Diagnostics", hint: "Capabilities and checks" },
  { id: "about", label: "About", hint: "Version and project details" },
];

export type CapabilityState = "available" | "pending" | "unavailable" | "experimental";

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

export type RuntimeCommand =
  | "BeginAuthentication"
  | "AuthenticationSucceeded"
  | { Connect: { device_id: string; request_id: string; requested: PermissionSet; now_ms: number } }
  | { ApproveRequest: { request_id: string; available: PermissionSet; now_ms: number } }
  | { RejectRequest: { request_id: string; now_ms: number } }
  | { Tick: { now_ms: number } }
  | "ConnectionNegotiating"
  | { ConnectionEstablished: { session_id: string; generation: number } }
  | { ConnectionLost: { retryable: boolean } }
  | "Disconnect"
  | "Disconnected"
  | "EnableHosting"
  | "DisableHosting"
  | "HostReady"
  | { HostFailed: { retryable: boolean } };

export type PairingState = "not-configured" | "pending" | "ready" | "unavailable";

export interface TrustedDevice {
  id: string;
  name: string;
  platform: string;
  addedAt: string;
  status: "trusted" | "pending" | "revoked";
}

export interface AccessSnapshot {
  pairing: {
    state: PairingState;
    detail: string;
  };
  controlPlane: Capability;
  trustedDevices: TrustedDevice[];
}

export interface SettingItem {
  id: string;
  label: string;
  description: string;
  value: string | number | boolean;
  state: CapabilityState;
  options?: string[];
}

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
