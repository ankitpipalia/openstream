import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { App } from "./App";
import { createEmptySnapshot, createLocalAdapter } from "./adapters/productAdapter";
import type { ProductAdapter } from "./adapters/productAdapter";

describe("OpenStream desktop shell", () => {
  it("renders the honest empty Computers state", async () => {
    render(<App adapter={createLocalAdapter(createEmptySnapshot())} />);

    expect(await screen.findByRole("heading", { name: "Computers" })).toBeInTheDocument();
    expect(screen.getByText("No computers discovered yet")).toBeInTheDocument();
    expect(screen.getByText("Control plane", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
  });

  it("navigates to every product area without a transport dependency", async () => {
    render(<App adapter={createLocalAdapter(createEmptySnapshot())} />);
    const primaryNav = await screen.findByRole("navigation", { name: "Primary" });

    for (const page of ["Access", "Settings", "Diagnostics", "About"]) {
      fireEvent.click(within(primaryNav).getByRole("button", { name: page }));
      expect(screen.getByRole("heading", { name: page })).toBeInTheDocument();
    }
  });

  it("renders capability-aware settings instead of pretending features are ready", async () => {
    const snapshot = createEmptySnapshot();
    snapshot.settings[0].items[0].state = "unavailable";

    render(<App adapter={createLocalAdapter(snapshot)} initialPage="settings" />);

    expect(await screen.findByRole("heading", { name: "Settings" })).toBeInTheDocument();
    expect(screen.getAllByText("Unavailable", { exact: true }).length).toBeGreaterThan(0);
    expect(
      screen.getAllByText("This setting is not available on the current runtime.").length,
    ).toBeGreaterThan(0);
  });

  it("shows a typed unavailable capability when the runtime bridge fails on load", async () => {
    const adapter: ProductAdapter = {
      getSnapshot: () => createEmptySnapshot(),
      subscribe: () => () => {},
      refresh: async () => {
        throw new Error("bridge down");
      },
      dispatch: async () => createEmptySnapshot(),
      updateSettings: async () => createEmptySnapshot(),
      updateSetting: async () => createEmptySnapshot(),
      setDeviceTrust: async () => createEmptySnapshot(),
      signIn: async () => createEmptySnapshot(),
      registerAccount: async () => createEmptySnapshot(),
      signOut: async () => createEmptySnapshot(),
    };

    render(<App adapter={adapter} />);

    expect((await screen.findAllByText("The runtime bridge did not respond.")).length).toBeGreaterThan(0);
  });

  it("surfaces a bridge failure from the Computers refresh action without crashing", async () => {
    let refreshCount = 0;
    const adapter: ProductAdapter = {
      getSnapshot: () => createEmptySnapshot(),
      subscribe: () => () => {},
      refresh: async () => {
        refreshCount += 1;
        if (refreshCount === 1) {
          return createEmptySnapshot();
        }
        throw new Error("bridge down");
      },
      dispatch: async () => createEmptySnapshot(),
      updateSettings: async () => createEmptySnapshot(),
      updateSetting: async () => createEmptySnapshot(),
      setDeviceTrust: async () => createEmptySnapshot(),
      signIn: async () => createEmptySnapshot(),
      registerAccount: async () => createEmptySnapshot(),
      signOut: async () => createEmptySnapshot(),
    };

    render(<App adapter={adapter} />);
    await screen.findByRole("heading", { name: "Computers" });

    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    expect((await screen.findAllByText("The runtime bridge did not respond.")).length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Computers" })).toBeInTheDocument();
  });

  it("keeps the view and shows an inline error when a connect fails, instead of wiping the snapshot", async () => {
    const seeded = createEmptySnapshot();
    seeded.computers = [
      {
        id: "host-1",
        name: "Studio",
        platform: "linux",
        status: "online",
        detail: "Ready",
        capabilities: [],
      },
    ];
    const adapter: ProductAdapter = {
      getSnapshot: () => seeded,
      subscribe: () => () => {},
      refresh: async () => seeded,
      // A recoverable session-start failure, not a dead runtime bridge.
      dispatch: async () => {
        throw new Error("session start failed");
      },
      updateSettings: async () => seeded,
      updateSetting: async () => seeded,
      setDeviceTrust: async () => seeded,
      signIn: async () => seeded,
      registerAccount: async () => seeded,
      signOut: async () => seeded,
    };

    render(<App adapter={adapter} />);
    await screen.findByRole("heading", { name: "Computers" });
    expect(screen.getByRole("heading", { name: "Studio" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Connect" }));

    // The failure is surfaced inline, and the snapshot is not wiped: the
    // computer is still listed and the runtime-unavailable message never shows.
    expect(await screen.findByText(/The session could not be started/)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Studio" })).toBeInTheDocument();
    expect(screen.queryByText("The runtime bridge did not respond.")).toBeNull();
  });
});
