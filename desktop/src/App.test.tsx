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
      screen.getAllByText("This setting is visible, but its backend capability is not available yet.").length,
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
    };

    render(<App adapter={adapter} />);
    await screen.findByRole("heading", { name: "Computers" });

    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    expect((await screen.findAllByText("The runtime bridge did not respond.")).length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Computers" })).toBeInTheDocument();
  });
});
