import { invoke } from "@tauri-apps/api/core";

/// Advertised product version. This is a prerelease identifier until
/// every gate in release/openstream-1.0-gates.tsv actually passes.
const PRODUCT_VERSION = "1.0.0-dev";

import type {
  AccessSnapshot,
  Capability,
  CapabilityState,
  Computer,
  ComputerStatus,
  ConnectionSnapshot,
  DiagnosticsSnapshot,
  PermissionSet,
  ProductSnapshot,
  RuntimeCommand,
  SessionState,
  SettingItem,
  SettingSection,
  TrustedDevice,
} from "../model";
import { capability, createLocalAdapter } from "./productAdapter";
import type { ProductAdapter } from "./productAdapter";

/** The subset of Tauri's `invoke` that the adapter needs; real or injected for tests. */
export type TauriInvoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>;

type AppErrorCode =
  | "InvalidCommand"
  | "InvalidRequest"
  | "InvalidState"
  | "DeviceUnavailable"
  | "DuplicateRequest"
  | "ExpiredRequest"
  | "PermissionDenied"
  | "AuthenticationRequired"
  | "Unavailable"
  | "Transport"
  | "Internal";

type AppState =
  | "SignedOut"
  | "Authenticating"
  | "Ready"
  | { RequestingConnection: { device_id: string; request_id: string } }
  | { WaitingForApproval: { device_id: string; request_id: string } }
  | { Connecting: { device_id: string } }
  | { Negotiating: { device_id: string } }
  | { Connected: { device_id: string; session_id: string; generation: number } }
  | { Reconnecting: { device_id: string; session_id: string } }
  | { Disconnecting: { device_id: string } }
  | { Failed: { code: AppErrorCode; retryable: boolean; message: string } };

type HostStatus = "Disabled" | "Starting" | "Ready" | { Failed: { message: string; retryable: boolean } };

interface DeviceSummary {
  id: string;
  name: string;
  platform: string;
  online: boolean;
  hosting_enabled: boolean;
  connected_guests: number;
}

interface ConnectionRequest {
  request_id: string;
  device_id: string;
  requested: PermissionSet;
  created_at_ms: number;
  expires_at_ms: number;
}

/// Runtime truth for one probe, decided in Rust. The state is a closed set
/// and the detail is prose for the operator; nothing here is parsed.
export type DiagnosticState =
  | "available"
  | "pending"
  | "experimental"
  | "unavailable"
  | "not_implemented";

export interface Diagnostic {
  state: DiagnosticState;
  detail: string;
}

interface RuntimeDiagnostics {
  signal: Diagnostic;
  direct_udp: Diagnostic;
  stun: Diagnostic;
  relay: Diagnostic;
  turn: Diagnostic;
  capture_backend: Diagnostic;
  encoder: Diagnostic;
  decoder: Diagnostic;
  renderer: Diagnostic;
  audio: Diagnostic;
  input: Diagnostic;
  virtual_devices: Diagnostic;
  last_error: AppErrorCode | null;
}

interface AppSnapshot {
  mode: "Local" | "Secure";
  state: AppState;
  host_status: HostStatus;
  devices: DeviceSummary[];
  pending_request: ConnectionRequest | null;
  active_device_id: string | null;
  active_session_id: string | null;
  active_permissions: PermissionSet;
  diagnostics: RuntimeDiagnostics;
}

export type AppEvent =
  | "AuthenticationStarted"
  | "AuthenticationRequired"
  | { AuthenticationFailed: { retryable: boolean } }
  | "SignedOut"
  | { ApprovalRequired: ConnectionRequest }
  | { ConnectionApproved: { request_id: string; permissions: PermissionSet } }
  | { ConnectionRejected: { request_id: string; reason: "Denied" | "Expired" } }
  | "ConnectionNegotiationStarted"
  | { ConnectionReady: { session_id: string; generation: number } }
  | { ConnectionFailed: { retryable: boolean } }
  | "ReconnectStarted"
  | "DisconnectRequested"
  | "Disconnected"
  | "HostStartRequested"
  | "HostReady"
  | "HostStopRequested"
  | "FailureCleared"
  | { HostFailed: { code: AppErrorCode } };

export type SettingScope = "global" | "client" | "host" | "device" | "session";
export type SettingApplyMode = "live" | "reconnect" | "restart_host" | "restart_application";
export type SettingVisibility = "normal" | "advanced" | "experimental";
export type SettingCapability = "available" | "experimental" | "unavailable" | "not_implemented";

export interface SettingDescriptor {
  key: string;
  scope: SettingScope;
  apply_mode: SettingApplyMode;
  capability: SettingCapability;
  visibility: SettingVisibility;
}

interface DeviceConfig {
  name: string;
  identity_key: string | null;
  control_credential: string | null;
}

interface ClientConfig {
  signal_origin: string;
  profile: string;
  window_mode: string;
  renderer: string;
  decoder: string;
  codec: string;
  vsync: string;
  chroma: string;
  bit_depth: string;
  immersive: boolean;
  show_warnings: boolean;
  bandwidth_cap_mbps: number | null;
  overlay: boolean;
}

interface HostConfig {
  enabled: boolean;
  name: string;
  stay_awake: boolean;
  capture: string;
  encoder: string;
  aggregate_bandwidth_cap_mbps: number | null;
  approval: string;
  max_guests: number;
  selected_display: string | null;
}

interface VideoConfig {
  width: number;
  height: number;
  fps: number;
  bitrate_mbps: number;
  min_bitrate_mbps: number;
  codec: string;
  pixel_format: string;
}

interface AudioConfig {
  enabled: boolean;
  codec: string;
  bitrate_kbps: number;
  latency_mode: string;
}

interface InputConfig {
  enabled: boolean;
  keyboard: boolean;
  mouse: boolean;
  clipboard: boolean;
  gamepad: boolean;
  microphone: boolean;
}

interface NetworkConfig {
  upnp: boolean;
  ice: boolean;
  turn: boolean;
  force_relay: boolean;
  local_no_auth: boolean;
  udp_port: number | null;
  client_port: number | null;
  host_start_port: number | null;
  congestion: string;
}

interface PrivacyConfig {
  redact_diagnostics: boolean;
  remember_last_host: boolean;
}

interface AdvancedConfig {
  ffmpeg_path: string | null;
  ffmpeg_reconfigure: boolean;
  max_session_seconds: number;
}

export interface AppConfig {
  schema_version: number;
  device: DeviceConfig;
  client: ClientConfig;
  host: HostConfig;
  video: VideoConfig;
  audio: AudioConfig;
  input: InputConfig;
  network: NetworkConfig;
  privacy: PrivacyConfig;
  advanced: AdvancedConfig;
}

export interface RuntimeSnapshot {
  app: AppSnapshot;
  settings: AppConfig;
  descriptors: SettingDescriptor[];
  /** True once a change requires an application restart to take effect. */
  restart_required: boolean;
  /** True once a change requires only the host to restart to take effect. */
  host_restart_required: boolean;
  /** Setting keys whose persisted value is not yet reflected in the running application. */
  pending_settings: string[];
  /** Secret-free enrolled-device records loaded by the Rust runtime. */
  trusted_devices?: RuntimeTrustedDevice[];
}

export interface RuntimeTrustedDevice {
  device_id: string;
  name: string;
  platform: string;
  enrolled_at_ms: number;
  trust: "pending" | "trusted" | "revoked";
  last_seen_ms: number | null;
  public_key_fingerprint: string;
}

export interface RuntimeDispatchResult {
  snapshot: RuntimeSnapshot;
  events: AppEvent[];
}

export type RuntimeError =
  | "settings_unavailable"
  | "invalid_settings"
  | "state_unavailable"
  | { command_rejected: { code: AppErrorCode; retryable: boolean } };

interface SettingFieldSpec {
  key: string;
  label: string;
  description: string;
  value: (settings: AppConfig) => string | number | boolean;
  options?: string[];
}

interface SettingSectionSpec {
  id: string;
  label: string;
  description: string;
  fields: SettingFieldSpec[];
}

const SETTING_SECTIONS: SettingSectionSpec[] = [
  {
    id: "client",
    label: "Experience",
    description: "Display and rendering preferences applied by the connected client.",
    fields: [
      {
        key: "client.signal_origin",
        label: "Control-plane endpoint",
        description: "HTTPS endpoint used for account authentication and host discovery.",
        value: (settings) => settings.client.signal_origin,
      },
      {
        key: "client.profile",
        label: "Stream profile",
        description: "Overall latency, quality, and bandwidth profile for a session.",
        value: (settings) => settings.client.profile,
        options: ["performance", "balanced", "quality", "custom"],
      },
      {
        key: "client.window_mode",
        label: "Window mode",
        description: "How the session window is placed on screen.",
        value: (settings) => settings.client.window_mode,
        options: ["windowed", "borderless", "fullscreen"],
      },
      {
        key: "client.renderer",
        label: "Renderer",
        description: "The graphics backend used to present decoded frames.",
        value: (settings) => settings.client.renderer,
        options: ["auto", "software", "metal", "vulkan", "dx12"],
      },
      {
        key: "client.vsync",
        label: "VSync",
        description: "Whether presentation waits for the display refresh.",
        value: (settings) => settings.client.vsync,
        options: ["auto", "on", "off"],
      },
      {
        key: "client.decoder",
        label: "Decoder",
        description: "The decode backend used for incoming video.",
        value: (settings) => settings.client.decoder,
        options: ["auto", "hardware", "software", "videotoolbox"],
      },
      {
        key: "client.codec",
        label: "Codec",
        description: "The preferred video codec for a session.",
        value: (settings) => settings.client.codec,
        options: ["auto", "h264", "h265"],
      },
      {
        key: "client.chroma",
        label: "Chroma sampling",
        description: "Preferred chroma subsampling for decoded video.",
        value: (settings) => settings.client.chroma,
        options: ["auto", "yuv420", "yuv444"],
      },
      {
        key: "client.bit_depth",
        label: "Bit depth",
        description: "Preferred color bit depth for decoded video.",
        value: (settings) => settings.client.bit_depth,
        options: ["auto", "8", "10"],
      },
      {
        key: "client.immersive",
        label: "Immersive mode",
        description: "Hide window chrome while a session is active.",
        value: (settings) => settings.client.immersive,
      },
      {
        key: "client.show_warnings",
        label: "Overlay warnings",
        description: "Show typed network, capture, encode, and decode warnings in the session overlay.",
        value: (settings) => settings.client.show_warnings,
      },
      {
        key: "client.overlay",
        label: "Session overlay",
        description: "Show transport and media diagnostics in the native session window.",
        value: (settings) => settings.client.overlay,
      },
    ],
  },
  {
    id: "host",
    label: "Host",
    description: "Settings that apply when this device hosts a session for a guest.",
    fields: [
      {
        key: "host.enabled",
        label: "Host enabled",
        description: "Allow this device to accept incoming sessions.",
        value: (settings) => settings.host.enabled,
      },
      {
        key: "host.name",
        label: "Host name",
        description: "The name guests see when discovering this device.",
        value: (settings) => settings.host.name,
      },
      {
        key: "host.stay_awake",
        label: "Stay awake while hosting",
        description: "Prevent the system from sleeping while a guest is connected.",
        value: (settings) => settings.host.stay_awake,
      },
      {
        key: "host.encoder",
        label: "Host encoder",
        description: "Select the encoder backend after the host preflight proves it works.",
        value: (settings) => settings.host.encoder,
        options: ["auto", "software", "h264_nvenc", "hevc_nvenc", "h264_vaapi", "hevc_vaapi"],
      },
      {
        key: "host.approval",
        label: "Connection approval",
        description: "Require an explicit host decision before a guest can control the session.",
        value: (settings) => settings.host.approval,
        options: ["auto", "prompt"],
      },
      {
        key: "host.max_guests",
        label: "Maximum guests",
        description: "Bound the number of admitted guests for this host.",
        value: (settings) => settings.host.max_guests,
      },
      {
        key: "host.aggregate_bandwidth_cap_mbps",
        label: "Host bandwidth cap",
        description: "Share one aggregate wire-rate ceiling across connected guests.",
        value: (settings) => settings.host.aggregate_bandwidth_cap_mbps ?? "auto",
      },
      {
        key: "host.selected_display",
        label: "Display",
        description: "Select a host display by stable adapter identifier, or leave automatic.",
        value: (settings) => settings.host.selected_display ?? "auto",
      },
    ],
  },
  {
    id: "input",
    label: "Input and audio",
    description: "Permissions a host can grant to a connected guest.",
    fields: [
      {
        key: "input.enabled",
        label: "Remote input",
        description: "Enable the host input adapter before granting individual input categories.",
        value: (settings) => settings.input.enabled,
      },
      {
        key: "input.keyboard",
        label: "Keyboard input",
        description: "Allow a connected guest to send keyboard input.",
        value: (settings) => settings.input.keyboard,
      },
      {
        key: "input.mouse",
        label: "Mouse input",
        description: "Allow a connected guest to send mouse input.",
        value: (settings) => settings.input.mouse,
      },
      {
        key: "input.gamepad",
        label: "Gamepad input",
        description: "Allow a connected guest to send gamepad input.",
        value: (settings) => settings.input.gamepad,
      },
      {
        key: "input.clipboard",
        label: "Clipboard sharing",
        description: "Allow clipboard contents to sync with a connected guest.",
        value: (settings) => settings.input.clipboard,
      },
      {
        key: "input.microphone",
        label: "Microphone input",
        description: "Allow a connected guest's microphone to be forwarded.",
        value: (settings) => settings.input.microphone,
      },
    ],
  },
  {
    id: "network",
    label: "Network",
    description: "Connectivity preferences negotiated per session.",
    fields: [
      {
        key: "network.client_port",
        label: "Client port",
        description: "The local UDP port used when connecting to a host.",
        value: (settings) => settings.network.client_port ?? "auto",
      },
      {
        key: "network.host_start_port",
        label: "Host start port",
        description: "The first UDP port this device offers while hosting.",
        value: (settings) => settings.network.host_start_port ?? "auto",
      },
      {
        key: "network.upnp",
        label: "UPnP",
        description: "Attempt automatic port mapping on the local router.",
        value: (settings) => settings.network.upnp,
      },
      {
        key: "network.turn",
        label: "TURN relay",
        description: "Allow a TURN relay when a direct path is unavailable.",
        value: (settings) => settings.network.turn,
      },
      {
        key: "network.ice",
        label: "ICE traversal",
        description: "Use standards-based ICE checks when direct candidate probing is insufficient.",
        value: (settings) => settings.network.ice,
      },
      {
        key: "network.force_relay",
        label: "Force relay",
        description: "Use a configured relay for diagnostics or networks that block direct UDP.",
        value: (settings) => settings.network.force_relay,
      },
      {
        key: "network.congestion",
        label: "Congestion policy",
        description: "Choose response behavior without replacing the shared transport controller.",
        value: (settings) => settings.network.congestion,
        options: ["low_latency", "balanced", "throughput"],
      },
    ],
  },
];

function mapCapabilityState(state: SettingCapability): CapabilityState {
  switch (state) {
    case "available":
      return "available";
    case "experimental":
      return "experimental";
    case "unavailable":
      return "unavailable";
    case "not_implemented":
      return "unavailable";
  }
}

function mapSettings(settings: AppConfig, descriptors: SettingDescriptor[]): SettingSection[] {
  return SETTING_SECTIONS.map((section) => ({
    id: section.id,
    label: section.label,
    description: section.description,
    items: section.fields.map((field): SettingItem => {
      const descriptor = descriptors.find((item) => item.key === field.key);
      const item: SettingItem = {
        id: field.key,
        label: field.label,
        description: field.description,
        value: field.value(settings),
        state: descriptor ? mapCapabilityState(descriptor.capability) : "unavailable",
      };
      if (field.options) {
        item.options = field.options;
      }
      if (descriptor) {
        item.scope = descriptor.scope;
        item.applyMode = descriptor.apply_mode;
        item.visibility = descriptor.visibility;
      }
      return item;
    }),
  }));
}

function mapConnection(app: AppSnapshot): ConnectionSnapshot {
  const state = app.state;
  if (state === "SignedOut") {
    return { state: "unavailable", detail: "Sign in to connect to a host." };
  }
  if (state === "Authenticating") {
    return { state: "connecting", detail: "Signing in." };
  }
  if (state === "Ready") {
    return { state: "idle", detail: "Select a discovered computer to begin." };
  }
  if ("RequestingConnection" in state) {
    return {
      state: "connecting",
      detail: "Requesting a connection.",
      computerId: state.RequestingConnection.device_id,
    };
  }
  if ("WaitingForApproval" in state) {
    return {
      state: "connecting",
      detail: "Waiting for the host to approve this connection.",
      computerId: state.WaitingForApproval.device_id,
    };
  }
  if ("Connecting" in state) {
    return { state: "connecting", detail: "Connecting to the host.", computerId: state.Connecting.device_id };
  }
  if ("Negotiating" in state) {
    return { state: "connecting", detail: "Negotiating the session.", computerId: state.Negotiating.device_id };
  }
  if ("Connected" in state) {
    return { state: "connected", detail: "Session connected.", computerId: state.Connected.device_id };
  }
  if ("Reconnecting" in state) {
    return { state: "connecting", detail: "Reconnecting to the host.", computerId: state.Reconnecting.device_id };
  }
  if ("Disconnecting" in state) {
    return { state: "connecting", detail: "Disconnecting.", computerId: state.Disconnecting.device_id };
  }
  return { state: "unavailable", detail: state.Failed.message };
}

function mapComputers(devices: DeviceSummary[]): Computer[] {
  return devices.map((device) => {
    const status: ComputerStatus = !device.online ? "offline" : device.hosting_enabled ? "online" : "unavailable";
    const detail = device.hosting_enabled
      ? `${device.connected_guests} connected guest${device.connected_guests === 1 ? "" : "s"}`
      : "Hosting is disabled on this device.";
    return {
      id: device.id,
      name: device.name,
      platform: device.platform,
      status,
      detail,
      capabilities: [],
    };
  });
}

function mapAccess(app: AppSnapshot, devices: RuntimeTrustedDevice[] = []): AccessSnapshot {
  const pairing =
    app.mode === "Local"
      ? { state: "not-configured" as const, detail: "This desktop runs in local mode and does not require pairing." }
      : app.state === "SignedOut" || app.state === "Authenticating"
        ? { state: "not-configured" as const, detail: "Sign in to configure pairing with a control plane." }
        : { state: "ready" as const, detail: "This device is signed in to the control plane." };

  const controlPlane =
    app.mode === "Local"
      ? capability("control-plane", "Control plane", "available", "Local mode does not require a control plane.")
      : app.state === "SignedOut" || app.state === "Authenticating"
        ? capability("control-plane", "Control plane", "pending", "Waiting for account authentication.")
        : capability("control-plane", "Control plane", "available", "Signed in to the control plane.");

  const trustedDevices: TrustedDevice[] = devices.map((device) => ({
    id: device.device_id,
    name: device.name,
    platform: device.platform,
    addedAt: new Date(device.enrolled_at_ms).toLocaleString(),
    status: device.trust,
    fingerprint: device.public_key_fingerprint,
  }));

  return { pairing, controlPlane, trustedDevices };
}

/// Translate Rust's diagnostic state into the shell's capability state.
///
/// This used to infer the state from the prose: anything that was not
/// literally "unknown" and did not contain "fail", "error", or
/// "unavailable" was rendered as a green Available. That turned "not
/// implemented", "disabled", "pending", "experimental", and "not
/// configured" into working capabilities, which is the worst possible
/// answer to give someone debugging hardware. Rust now decides, and this
/// only renames.
function diagnosticState(value: DiagnosticState): CapabilityState {
  switch (value) {
    case "available":
      return "available";
    case "experimental":
      return "experimental";
    case "unavailable":
      return "unavailable";
    case "not_implemented":
      return "not-implemented";
    case "pending":
      return "pending";
    default:
      // An unrecognised state is not evidence that anything works.
      return "unavailable";
  }
}

function diagnosticCapability(id: string, label: string, value: Diagnostic): Capability {
  return capability(id, label, diagnosticState(value.state), value.detail);
}

function mapSessionState(app: AppSnapshot): DiagnosticsSnapshot["session"] {
  const state = app.state;
  if (typeof state !== "string") {
    if ("Connected" in state) {
      return { state: "running", detail: "A session is connected." };
    }
    if (
      "Negotiating" in state ||
      "Connecting" in state ||
      "RequestingConnection" in state ||
      "WaitingForApproval" in state ||
      "Reconnecting" in state
    ) {
      return { state: "starting", detail: "A session is starting." };
    }
    if ("Failed" in state) {
      return { state: "unavailable", detail: state.Failed.message };
    }
  }

  const hostStatus = app.host_status;
  if (typeof hostStatus !== "string" && "Failed" in hostStatus) {
    return { state: "unavailable", detail: hostStatus.Failed.message };
  }
  if (hostStatus === "Starting") {
    return { state: "starting", detail: "The host is starting." };
  }
  if (hostStatus === "Ready") {
    return { state: "running", detail: "The host is ready." };
  }
  return { state: "idle", detail: "No session has been requested." };
}

function mapDiagnostics(app: AppSnapshot): DiagnosticsSnapshot {
  const diagnostics = app.diagnostics;
  const checks: Capability[] = [
    diagnosticCapability("signal", "Signal channel", diagnostics.signal),
    diagnosticCapability("capture-backend", "Capture backend", diagnostics.capture_backend),
    diagnosticCapability("encoder", "Video encoder", diagnostics.encoder),
    diagnosticCapability("decoder", "Video decoder", diagnostics.decoder),
    diagnosticCapability("renderer", "Renderer", diagnostics.renderer),
    diagnosticCapability("audio", "Audio", diagnostics.audio),
    diagnosticCapability("input", "Input", diagnostics.input),
    diagnosticCapability("virtual-devices", "Virtual devices", diagnostics.virtual_devices),
  ];
  if (diagnostics.last_error) {
    checks.push(capability("last-error", "Last reported error", "unavailable", diagnostics.last_error));
  }

  return {
    session: mapSessionState(app),
    checks,
    transport: [
      diagnosticCapability("direct-udp", "Direct UDP", diagnostics.direct_udp),
      diagnosticCapability("stun", "STUN discovery", diagnostics.stun),
      diagnosticCapability("relay", "Relay", diagnostics.relay),
      diagnosticCapability("turn", "TURN relay", diagnostics.turn),
    ],
  };
}

function mapHostCapability(hostStatus: HostStatus): Capability {
  if (hostStatus === "Disabled") {
    return capability("host-agent", "Host agent", "unavailable", "Hosting is disabled on this device.");
  }
  if (hostStatus === "Starting") {
    return capability("host-agent", "Host agent", "pending", "The host agent is starting.");
  }
  if (hostStatus === "Ready") {
    return capability("host-agent", "Host agent", "available", "The host agent is ready.");
  }
  return capability("host-agent", "Host agent", "unavailable", hostStatus.Failed.message);
}

function mapInputCapability(permissions: PermissionSet): Capability {
  const granted = permissions.keyboard && permissions.mouse;
  return capability(
    "input",
    "Keyboard and mouse",
    granted ? "available" : "unavailable",
    granted
      ? "Keyboard and mouse are permitted for the active session."
      : "Input permissions are not granted because no session is active.",
  );
}

function mapCapabilities(app: AppSnapshot, controlPlane: Capability): Capability[] {
  return [
    controlPlane,
    mapHostCapability(app.host_status),
    diagnosticCapability("video-encoder", "Video encoder", app.diagnostics.encoder),
    mapInputCapability(app.active_permissions),
    diagnosticCapability("audio", "Opus audio", app.diagnostics.audio),
    diagnosticCapability("transport", "Session transport", app.diagnostics.direct_udp),
  ];
}

export function mapRuntimeSnapshot(snapshot: RuntimeSnapshot): ProductSnapshot {
  const app = snapshot.app;
  const access = mapAccess(app, snapshot.trusted_devices ?? []);

  return {
    product: { name: "OpenStream", version: PRODUCT_VERSION, channel: "Desktop shell" },
    connection: mapConnection(app),
    computers: mapComputers(app.devices),
    access,
    settings: mapSettings(snapshot.settings, snapshot.descriptors),
    capabilities: mapCapabilities(app, access.controlPlane),
    diagnostics: mapDiagnostics(app),
    restartRequired: snapshot.restart_required,
    hostRestartRequired: snapshot.host_restart_required,
    pendingSettingKeys: snapshot.pending_settings,
  };
}

function unresolvedSnapshot(): ProductSnapshot {
  const controlPlane = capability("control-plane", "Control plane", "pending", "Waiting for the runtime bridge.");
  return {
    product: { name: "OpenStream", version: PRODUCT_VERSION, channel: "Desktop shell" },
    connection: { state: "idle", detail: "Waiting for the runtime bridge." },
    computers: [],
    access: {
      pairing: { state: "not-configured", detail: "Waiting for the runtime bridge." },
      controlPlane,
      trustedDevices: [],
    },
    settings: [],
    capabilities: [],
    diagnostics: {
      session: { state: "idle", detail: "Waiting for the runtime bridge." },
      checks: [],
      transport: [],
    },
    restartRequired: false,
    hostRestartRequired: false,
    pendingSettingKeys: [],
  };
}

export function createTauriAdapter(invokeFn: TauriInvoke): ProductAdapter {
  let currentSnapshot = unresolvedSnapshot();
  const listeners = new Set<(snapshot: ProductSnapshot) => void>();

  function publish(snapshot: ProductSnapshot): ProductSnapshot {
    currentSnapshot = snapshot;
    for (const listener of listeners) {
      listener(currentSnapshot);
    }
    return currentSnapshot;
  }

  return {
    getSnapshot: () => currentSnapshot,
    subscribe: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    refresh: async () => {
      const raw = (await invokeFn("runtime_snapshot")) as RuntimeSnapshot;
      return publish(mapRuntimeSnapshot(raw));
    },
    dispatch: async (command: RuntimeCommand) => {
      const raw = (await invokeFn("runtime_dispatch", { command })) as RuntimeDispatchResult;
      return publish(mapRuntimeSnapshot(raw.snapshot));
    },
    updateSettings: async (settings: unknown) => {
      const raw = (await invokeFn("runtime_update_settings", { settings })) as RuntimeSnapshot;
      return publish(mapRuntimeSnapshot(raw));
    },
    updateSetting: async (key, value) => {
      const raw = (await invokeFn("runtime_update_setting", { key, value })) as RuntimeSnapshot;
      return publish(mapRuntimeSnapshot(raw));
    },
    setDeviceTrust: async (deviceId, trust) => {
      const raw = (await invokeFn("device_store_set_trust", { device_id: deviceId, trust })) as RuntimeSnapshot;
      return publish(mapRuntimeSnapshot(raw));
    },
    signIn: async (username, password) => {
      const raw = (await invokeFn("control_plane_sign_in", { username, password })) as RuntimeSnapshot;
      return publish(mapRuntimeSnapshot(raw));
    },
    registerAccount: async (username, password) => {
      const raw = (await invokeFn("control_plane_register", { username, password })) as RuntimeSnapshot;
      return publish(mapRuntimeSnapshot(raw));
    },
    signOut: async () => {
      const raw = (await invokeFn("control_plane_sign_out")) as RuntimeSnapshot;
      return publish(mapRuntimeSnapshot(raw));
    },
  };
}

function detectTauriBridge(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function tauriInvoke(command: string, args?: Record<string, unknown>): Promise<unknown> {
  return invoke(command, args);
}

export function createDefaultAdapter(overrides?: { isTauri?: boolean }): ProductAdapter {
  const isTauri = overrides?.isTauri ?? detectTauriBridge();
  return isTauri ? createTauriAdapter(tauriInvoke) : createLocalAdapter();
}
