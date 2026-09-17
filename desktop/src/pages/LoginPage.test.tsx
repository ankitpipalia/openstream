import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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
        description: "Control-plane connection.",
        items: [
          {
            id: SIGNAL_ORIGIN_SETTING,
            label: "Control-plane endpoint",
            description: "Where this desktop reaches its control plane.",
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

describe("LoginPage signup availability", () => {
  /// A closed deployment accepts only the very first account, so every later
  /// user was shown a "Create an account" button that could not succeed,
  /// followed by a generic failure. The screen asks the server instead of
  /// assuming.
  it("hides signup when the control plane will not accept a new account", async () => {
    const adapter = createLocalAdapter();
    adapter.registrationOpen = async () => false;
    render(
      <LoginPage snapshot={createEmptySnapshot()} adapter={adapter} onSnapshot={() => {}} />,
    );
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: /create an account/i })).toBeNull();
    });
  });

  it("offers signup when the control plane will accept one", async () => {
    const adapter = createLocalAdapter();
    adapter.registrationOpen = async () => true;
    render(
      <LoginPage snapshot={createEmptySnapshot()} adapter={adapter} onSnapshot={() => {}} />,
    );
    expect(await screen.findByRole("button", { name: /create an account/i })).toBeTruthy();
  });

  /// An unreachable or too-old control plane must not produce a button that
  /// cannot work: unknown is treated as closed.
  it("treats an unanswerable control plane as closed", async () => {
    const adapter = createLocalAdapter();
    adapter.registrationOpen = async () => {
      throw new Error("unreachable");
    };
    render(
      <LoginPage snapshot={createEmptySnapshot()} adapter={adapter} onSnapshot={() => {}} />,
    );
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: /create an account/i })).toBeNull();
    });
  });
});

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
