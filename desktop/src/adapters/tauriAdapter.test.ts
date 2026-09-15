import { describe, expect, it } from "vitest";

import { createDefaultAdapter, createTauriAdapter } from "./tauriAdapter";
import type {
  AppConfig,
  Diagnostic,
  RuntimeDispatchResult,
  RuntimeSnapshot,
  SettingApplyMode,
  SettingCapability,
  SettingDescriptor,
  SettingScope,
  SettingVisibility,
} from "./tauriAdapter";

function descriptor(
  key: string,
  scope: SettingScope,
  applyMode: SettingApplyMode,
  capability: SettingCapability,
  visibility: SettingVisibility,
): SettingDescriptor {
  return { key, scope, apply_mode: applyMode, capability, visibility };
}

function runtimeDescriptorsFixture(): SettingDescriptor[] {
  return [
    descriptor("client.profile", "client", "reconnect", "available", "normal"),
    descriptor("client.window_mode", "client", "live", "available", "normal"),
    descriptor("client.renderer", "client", "reconnect", "available", "normal"),
    descriptor("client.vsync", "client", "live", "available", "normal"),
    descriptor("client.decoder", "client", "reconnect", "experimental", "normal"),
    descriptor("client.codec", "session", "reconnect", "available", "normal"),
    descriptor("client.chroma", "session", "reconnect", "experimental", "advanced"),
    descriptor("client.bit_depth", "session", "reconnect", "experimental", "advanced"),
    descriptor("client.immersive", "client", "live", "experimental", "normal"),
    descriptor("host.enabled", "host", "restart_host", "available", "normal"),
    descriptor("host.name", "host", "live", "available", "normal"),
    descriptor("host.capture.drm", "host", "restart_host", "experimental", "experimental"),
    descriptor("host.capture.x11", "host", "restart_host", "available", "normal"),
    descriptor("host.stay_awake", "host", "restart_host", "not_implemented", "advanced"),
    descriptor("input.keyboard", "host", "live", "available", "normal"),
    descriptor("input.mouse", "host", "live", "experimental", "normal"),
    descriptor("input.gamepad", "host", "live", "experimental", "advanced"),
    descriptor("input.clipboard", "host", "live", "available", "advanced"),
    descriptor("input.microphone", "host", "live", "experimental", "advanced"),
    descriptor("network.client_port", "global", "reconnect", "available", "advanced"),
    descriptor("network.host_start_port", "host", "restart_host", "available", "advanced"),
    descriptor("network.upnp", "global", "reconnect", "available", "advanced"),
    descriptor("network.turn", "global", "reconnect", "available", "advanced"),
  ];
}

function runtimeConfigFixture(): AppConfig {
  return {
    schema_version: 2,
    device: { name: "OpenStream device", identity_key: null, control_credential: null },
    client: {
      signal_origin: "http://127.0.0.1:8080",
      profile: "balanced",
      window_mode: "windowed",
      renderer: "auto",
      decoder: "auto",
      codec: "auto",
      vsync: "auto",
      chroma: "auto",
      bit_depth: "auto",
      immersive: false,
      show_warnings: true,
      bandwidth_cap_mbps: null,
      overlay: true,
    },
    host: {
      enabled: false,
      name: "OpenStream host",
      stay_awake: false,
      capture: "auto",
      encoder: "auto",
      aggregate_bandwidth_cap_mbps: null,
      approval: "auto",
      max_guests: 1,
      selected_display: null,
    },
    video: {
      width: 1920,
      height: 1080,
      fps: 60,
      bitrate_mbps: 10,
      min_bitrate_mbps: 1,
      codec: "h264",
      pixel_format: "auto",
    },
    audio: {
      enabled: false,
      codec: "opus",
      bitrate_kbps: 128,
      latency_mode: "balanced",
    },
    input: {
      enabled: false,
      keyboard: false,
      mouse: false,
      clipboard: false,
      gamepad: false,
      microphone: false,
    },
    network: {
      upnp: false,
      ice: false,
      turn: false,
      force_relay: false,
      local_no_auth: true,
      udp_port: null,
      client_port: null,
      host_start_port: null,
      congestion: "balanced",
    },
    privacy: { redact_diagnostics: true, remember_last_host: false },
    advanced: { ffmpeg_path: null, ffmpeg_reconfigure: false, max_session_seconds: 3600 },
  };
}

function pendingDiagnostic(): Diagnostic {
  return { state: "pending", detail: "Not probed yet." };
}

function runtimeSnapshotFixture(): RuntimeSnapshot {
  return {
    app: {
      mode: "Local",
      state: "Ready",
      host_status: "Disabled",
      devices: [],
      pending_request: null,
      active_device_id: null,
      active_session_id: null,
      active_permissions: {
        view: true,
        keyboard: false,
        mouse: false,
        gamepad: false,
        clipboard: false,
        microphone: false,
        tablet: false,
        virtual_usb: false,
      },
      diagnostics: {
        signal: pendingDiagnostic(),
        direct_udp: pendingDiagnostic(),
        stun: pendingDiagnostic(),
        relay: pendingDiagnostic(),
        turn: pendingDiagnostic(),
        capture_backend: pendingDiagnostic(),
        encoder: pendingDiagnostic(),
        decoder: pendingDiagnostic(),
        renderer: pendingDiagnostic(),
        audio: pendingDiagnostic(),
        input: pendingDiagnostic(),
        virtual_devices: pendingDiagnostic(),
        last_error: null,
      },
    },
    settings: runtimeConfigFixture(),
    descriptors: runtimeDescriptorsFixture(),
    restart_required: false,
    host_restart_required: false,
    pending_settings: [],
    trusted_devices: [],
  };
}

describe("tauri adapter", () => {
  /// Look a setting up by its stable key rather than by position. The
  /// sections are presentation order, so indexing into them makes an
  /// unrelated UI reordering look like a mapping regression.
  function settingValue(snapshot: { settings: { items: { id: string; value: unknown }[] }[] }, key: string) {
    for (const section of snapshot.settings) {
      const item = section.items.find((candidate) => candidate.id === key);
      if (item) {
        return item.value;
      }
    }
    throw new Error(`no setting rendered for ${key}`);
  }

  it("loads a Rust snapshot through the Tauri adapter", async () => {
    const adapter = createTauriAdapter(async (command) => {
      expect(command).toBe("runtime_snapshot");
      return runtimeSnapshotFixture();
    });
    const snapshot = await adapter.refresh();
    expect(snapshot.connection.state).toBe("idle");
    expect(settingValue(snapshot, "client.profile")).toBe("balanced");
  });

  it("marks local mode structurally so the notice never depends on prose", async () => {
    const local = createTauriAdapter(async () => runtimeSnapshotFixture());
    expect((await local.refresh()).access.localMode).toBe(true);

    const secureFixture = runtimeSnapshotFixture();
    secureFixture.app.mode = "Secure";
    const secure = createTauriAdapter(async () => secureFixture);
    expect((await secure.refresh()).access.localMode).toBe(false);
  });

  it("keeps the fixture adapter outside Tauri", async () => {
    const adapter = createDefaultAdapter({ isTauri: false });
    expect((await adapter.refresh()).product.channel).toBe("Desktop shell");
  });

  it("detects the Tauri bridge from window.__TAURI_INTERNALS__ when no override is given", () => {
    const globalWindow = window as unknown as Record<string, unknown>;
    globalWindow.__TAURI_INTERNALS__ = {};
    try {
      expect(() => createDefaultAdapter()).not.toThrow();
    } finally {
      delete globalWindow.__TAURI_INTERNALS__;
    }
  });

  it("maps a dispatch result back into the product snapshot", async () => {
    const result: RuntimeDispatchResult = {
      snapshot: runtimeSnapshotFixture(),
      events: ["AuthenticationStarted"],
    };

    const adapter = createTauriAdapter(async (command, args) => {
      expect(command).toBe("runtime_dispatch");
      expect(args).toEqual({ command: "SignIn" });
      return result;
    });

    const snapshot = await adapter.dispatch("SignIn");
    expect(snapshot.connection.state).toBe("idle");
  });

  it("dispatches a Connect command carrying only user intent, with no request id or timestamp", async () => {
    const result: RuntimeDispatchResult = {
      snapshot: runtimeSnapshotFixture(),
      events: [],
    };
    const permissions = {
      view: true,
      keyboard: false,
      mouse: false,
      gamepad: false,
      clipboard: false,
      microphone: false,
      tablet: false,
      virtual_usb: false,
    };

    const adapter = createTauriAdapter(async (command, args) => {
      expect(command).toBe("runtime_dispatch");
      expect(args).toEqual({
        command: { Connect: { device_id: "mac-1", requested: permissions } },
      });
      return result;
    });

    await adapter.dispatch({ Connect: { device_id: "mac-1", requested: permissions } });
  });

  it("sets device trust with the camelCase deviceId key Tauri v2 deserializes", async () => {
    const adapter = createTauriAdapter(async (command, args) => {
      expect(command).toBe("device_store_set_trust");
      // Tauri v2 deserializes command arguments as camelCase; sending the Rust
      // parameter name `device_id` silently fails IPC and no trust change lands.
      expect(args).toEqual({ deviceId: "mac-1", trust: "trusted" });
      return runtimeSnapshotFixture();
    });

    await adapter.setDeviceTrust("mac-1", "trusted");
  });

  it("surfaces restart_required and pending settings from the runtime snapshot", async () => {
    const fixture = runtimeSnapshotFixture();
    const pending: RuntimeSnapshot = {
      ...fixture,
      restart_required: true,
      host_restart_required: true,
      pending_settings: ["network.local_no_auth", "host.enabled"],
    };

    const adapter = createTauriAdapter(async () => pending);
    const snapshot = await adapter.refresh();

    expect(snapshot.restartRequired).toBe(true);
    expect(snapshot.hostRestartRequired).toBe(true);
    expect(snapshot.pendingSettingKeys).toEqual(["network.local_no_auth", "host.enabled"]);
  });

  it("maps an updateSettings result back into the product snapshot", async () => {
    const fixture = runtimeSnapshotFixture();
    const updated: RuntimeSnapshot = {
      ...fixture,
      settings: { ...fixture.settings, client: { ...fixture.settings.client, profile: "performance" } },
    };

    const adapter = createTauriAdapter(async (command, args) => {
      expect(command).toBe("runtime_update_settings");
      expect(args).toEqual({ settings: updated.settings });
      return updated;
    });

    const snapshot = await adapter.updateSettings(updated.settings);
    expect(settingValue(snapshot, "client.profile")).toBe("performance");
  });

  it("renders the diagnostic state Rust reported, never one inferred from its prose", async () => {
    const fixture = runtimeSnapshotFixture();
    const snapshotWithProbes: RuntimeSnapshot = {
      ...fixture,
      app: {
        ...fixture.app,
        diagnostics: {
          ...fixture.app.diagnostics,
          // Prose that the old text-sniffing adapter turned green: none of
          // these contain "fail", "error", or "unavailable", so anything
          // that guesses from the words reports a working capability.
          encoder: { state: "not_implemented", detail: "No native encoder on this platform." },
          renderer: { state: "unavailable", detail: "Disabled by policy." },
          audio: { state: "experimental", detail: "Not covered by the acceptance gates." },
          input: { state: "available", detail: "uinput probe succeeded." },
        },
      },
    };

    const adapter = createTauriAdapter(async () => snapshotWithProbes);
    const snapshot = await adapter.refresh();
    const state = (id: string) =>
      snapshot.diagnostics.checks.find((check) => check.id === id)?.state;

    expect(state("encoder")).toBe("not-implemented");
    expect(state("renderer")).toBe("unavailable");
    expect(state("audio")).toBe("experimental");
    expect(state("input")).toBe("available");

    const detail = snapshot.diagnostics.checks.find((check) => check.id === "encoder")?.detail;
    expect(detail).toBe("No native encoder on this platform.");
  });

  it("propagates a bridge failure instead of fabricating an available snapshot", async () => {
    const adapter = createTauriAdapter(async () => {
      throw { command_rejected: { code: "Unavailable", retryable: true } };
    });

    await expect(adapter.refresh()).rejects.toBeTruthy();
  });
});
