import type {
  AccessSnapshot,
  Capability,
  DiagnosticsSnapshot,
  ProductSnapshot,
  SettingSection,
} from "../model";

export interface ProductAdapter {
  /** A synchronous, secret-free snapshot suitable for rendering. */
  getSnapshot(): ProductSnapshot;
  subscribe(listener: (snapshot: ProductSnapshot) => void): () => void;
  refresh(): Promise<ProductSnapshot>;
  /** Fixture-only mutation hook; a real transport adapter can omit this. */
  setSnapshot(snapshot: ProductSnapshot): void;
}

function capability(
  id: string,
  label: string,
  state: Capability["state"],
  detail: string,
): Capability {
  return { id, label, state, detail };
}

function defaultSettings(): SettingSection[] {
  return [
    {
      id: "experience",
      label: "Experience",
      description: "Choose how OpenStream should present a session on this device.",
      items: [
        {
          id: "stream-profile",
          label: "Stream profile",
          description: "The selected profile will be applied when a session runner is available.",
          value: "Balanced",
          options: ["Quality", "Balanced", "Low latency"],
          state: "available",
        },
        {
          id: "window-mode",
          label: "Window mode",
          description: "Native fullscreen and window placement require the desktop session runner.",
          value: "Windowed",
          options: ["Windowed", "Fullscreen"],
          state: "unavailable",
        },
        {
          id: "vsync",
          label: "VSync",
          description: "VSync will be exposed when the native renderer reports support.",
          value: "Automatic",
          options: ["Automatic", "On", "Off"],
          state: "pending",
        },
      ],
    },
    {
      id: "input-audio",
      label: "Input and audio",
      description: "Permissions are reported by the host and the connected client at runtime.",
      items: [
        {
          id: "keyboard-input",
          label: "Keyboard input",
          description: "No host session is active to receive keyboard input.",
          value: true,
          state: "unavailable",
        },
        {
          id: "relative-mouse",
          label: "Relative mouse",
          description: "Raw relative motion is available only inside an active session.",
          value: false,
          state: "unavailable",
        },
        {
          id: "audio-output",
          label: "Audio output",
          description: "Opus playback is checked during session startup.",
          value: "Default device",
          state: "pending",
        },
      ],
    },
    {
      id: "network",
      label: "Network",
      description: "Connectivity is negotiated per session; credentials never belong in UI state.",
      items: [
        {
          id: "transport-preference",
          label: "Transport preference",
          description: "The session runner will choose direct UDP, relay, or TURN after discovery.",
          value: "Automatic",
          options: ["Automatic", "Direct", "Relay"],
          state: "pending",
        },
      ],
    },
  ];
}

export function createEmptySnapshot(): ProductSnapshot {
  const controlPlane = capability(
    "control-plane",
    "Control plane",
    "unavailable",
    "Configure a control-plane endpoint to discover computers.",
  );
  const hostAgent = capability(
    "host-agent",
    "Host agent",
    "unavailable",
    "No host agent has reported a ready state.",
  );
  const encoder = capability(
    "video-encoder",
    "Video encoder",
    "unavailable",
    "A session is required before encoder compatibility can be checked.",
  );
  const input = capability(
    "input",
    "Keyboard and mouse",
    "unavailable",
    "Input permissions are not granted because no session is active.",
  );
  const audio = capability(
    "audio",
    "Opus audio",
    "pending",
    "Audio support will be checked during session startup.",
  );
  const transport = capability(
    "transport",
    "Session transport",
    "pending",
    "Direct and relay paths are selected after a host is discovered.",
  );

  const diagnostics: DiagnosticsSnapshot = {
    session: {
      state: "idle",
      detail: "No session has been requested.",
    },
    checks: [controlPlane, hostAgent, encoder, input, audio],
    transport: [
      capability("direct-udp", "Direct UDP", "pending", "Waiting for a discovered host."),
      capability("stun", "STUN discovery", "pending", "Waiting for a control-plane configuration."),
      capability("turn", "TURN relay", "unavailable", "No TURN configuration is present."),
      transport,
    ],
  };

  const access: AccessSnapshot = {
    pairing: {
      state: "not-configured",
      detail: "Pairing is not configured on this desktop.",
    },
    controlPlane,
    trustedDevices: [],
  };

  return {
    product: {
      name: "OpenStream",
      version: "1.0.0",
      channel: "Desktop shell",
    },
    connection: {
      state: "idle",
      detail: "Select a discovered computer to begin.",
    },
    computers: [],
    access,
    settings: defaultSettings(),
    capabilities: [controlPlane, hostAgent, encoder, input, audio, transport],
    diagnostics,
  };
}

export function createLocalAdapter(initialSnapshot: ProductSnapshot = createEmptySnapshot()): ProductAdapter {
  let currentSnapshot = initialSnapshot;
  const listeners = new Set<(snapshot: ProductSnapshot) => void>();

  return {
    getSnapshot: () => currentSnapshot,
    subscribe: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    refresh: async () => currentSnapshot,
    setSnapshot: (snapshot) => {
      currentSnapshot = snapshot;
      for (const listener of listeners) {
        listener(currentSnapshot);
      }
    },
  };
}
