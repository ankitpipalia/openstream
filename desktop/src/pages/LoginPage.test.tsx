import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { LoginPage } from "./LoginPage";
import { createEmptySnapshot, createLocalAdapter } from "../adapters/productAdapter";
import type { ProductSnapshot } from "../model";

const SIGNAL_ORIGIN_SETTING = "client.signal_origin";

/** A snapshot carrying a configured control-plane origin, shaped the way the
 * runtime adapter reports settings. */
function snapshotWithEndpoint(origin: string): ProductSnapshot {
  const snapshot = createEmptySnapshot();
  return {
    ...snapshot,
    settings: [
      {
        id: "client",
        label: "Client",
        items: [
          {
            id: SIGNAL_ORIGIN_SETTING,
            label: "Control-plane endpoint",
            value: origin,
            state: "available",
          },
        ],
      },
    ],
  };
}

/** Reveal the editor. Only safe to call once per render tree: the control is a
 * toggle, so a second click would collapse it again. */
function openEndpointEditor(): void {
  fireEvent.click(screen.getByRole("button", { name: /control-plane endpoint/i }));
}

function endpointField(): HTMLInputElement {
  return screen.getByLabelText(/control-plane endpoint/i) as HTMLInputElement;
}

describe("LoginPage control-plane endpoint", () => {
  /// The adapter's first snapshot is an unresolved placeholder with no
  /// settings, so the field starts empty even when an endpoint is configured.
  /// It has to adopt the real value when that snapshot arrives; otherwise
  /// opening the editor shows nothing and saving writes that nothing over a
  /// working endpoint.
  it("adopts the configured endpoint when the real snapshot arrives", () => {
    const adapter = createLocalAdapter();
    const { rerender } = render(
      <LoginPage snapshot={createEmptySnapshot()} adapter={adapter} onSnapshot={() => {}} />,
    );
    openEndpointEditor();
    expect(endpointField().value).toBe("");

    rerender(
      <LoginPage
        snapshot={snapshotWithEndpoint("https://control.example.com")}
        adapter={adapter}
        onSnapshot={() => {}}
      />,
    );
    expect(endpointField().value).toBe("https://control.example.com");
  });

  /// Adopting a later snapshot must never yank the field out from under
  /// someone mid-edit.
  it("keeps what the operator typed when a later snapshot arrives", () => {
    const adapter = createLocalAdapter();
    const { rerender } = render(
      <LoginPage
        snapshot={snapshotWithEndpoint("https://first.example.com")}
        adapter={adapter}
        onSnapshot={() => {}}
      />,
    );

    openEndpointEditor();
    fireEvent.change(endpointField(), { target: { value: "https://typed.example.com" } });

    rerender(
      <LoginPage
        snapshot={snapshotWithEndpoint("https://second.example.com")}
        adapter={adapter}
        onSnapshot={() => {}}
      />,
    );
    expect(endpointField().value).toBe("https://typed.example.com");
  });
});
