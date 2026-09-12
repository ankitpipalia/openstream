import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { App } from "./App";
import { createEmptySnapshot, createLocalAdapter } from "./adapters/productAdapter";

describe("OpenStream desktop shell", () => {
  it("renders the honest empty Computers state", () => {
    render(<App adapter={createLocalAdapter(createEmptySnapshot())} />);

    expect(screen.getByRole("heading", { name: "Computers" })).toBeInTheDocument();
    expect(screen.getByText("No computers discovered yet")).toBeInTheDocument();
    expect(screen.getByText("Control plane", { exact: true })).toBeInTheDocument();
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
  });

  it("navigates to every product area without a transport dependency", () => {
    render(<App adapter={createLocalAdapter(createEmptySnapshot())} />);
    const primaryNav = screen.getByRole("navigation", { name: "Primary" });

    for (const page of ["Access", "Settings", "Diagnostics", "About"]) {
      fireEvent.click(within(primaryNav).getByRole("button", { name: page }));
      expect(screen.getByRole("heading", { name: page })).toBeInTheDocument();
    }
  });

  it("renders capability-aware settings instead of pretending features are ready", () => {
    const snapshot = createEmptySnapshot();
    snapshot.settings[0].items[0].state = "unavailable";

    render(<App adapter={createLocalAdapter(snapshot)} initialPage="settings" />);

    expect(screen.getByRole("heading", { name: "Settings" })).toBeInTheDocument();
    expect(screen.getAllByText("Unavailable", { exact: true }).length).toBeGreaterThan(0);
    expect(
      screen.getAllByText("This setting is visible, but its backend capability is not available yet.").length,
    ).toBeGreaterThan(0);
  });
});
