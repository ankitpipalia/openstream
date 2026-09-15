import {
  fireEvent,
  render,
  screen,
  waitFor,
  waitForElementToBeRemoved,
  within,
} from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { App } from "./App";
import { createEmptySnapshot, createLocalAdapter } from "./adapters/productAdapter";
import type { ProductAdapter } from "./adapters/productAdapter";
import type { ConnectRequest, ProductSnapshot } from "./model";

/** A snapshot where this device is both hosting and signed in -- the only state
 * in which the Secure Connect approval poll runs. */
function hostingAuthedSnapshot(): ProductSnapshot {
  const snapshot = createEmptySnapshot();
  snapshot.diagnostics = {
    ...snapshot.diagnostics,
    session: { state: "running", detail: "The host is ready." },
  };
  snapshot.access = {
    ...snapshot.access,
    pairing: { state: "ready", detail: "Signed in." },
  };
  return snapshot;
}

function approvalAdapter(overrides: Partial<ProductAdapter>): ProductAdapter {
  const snapshot = hostingAuthedSnapshot();
  return {
    getSnapshot: () => snapshot,
    subscribe: () => () => {},
    refresh: async () => snapshot,
    dispatch: async () => snapshot,
    updateSettings: async () => snapshot,
    updateSetting: async () => snapshot,
    setDeviceTrust: async () => snapshot,
    signIn: async () => snapshot,
    registerAccount: async () => snapshot,
    signOut: async () => snapshot,
    hostConnectRequests: async () => [],
    approveConnectRequest: async () => {},
    denyConnectRequest: async () => {},
    ...overrides,
  };
}

const INCOMING: ConnectRequest = {
  requestId: "r1",
  requesterDeviceId: "device-abcdef",
  expiresInSeconds: 60,
};

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
      hostConnectRequests: async () => [],
      approveConnectRequest: async () => {},
      denyConnectRequest: async () => {},
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
      hostConnectRequests: async () => [],
      approveConnectRequest: async () => {},
      denyConnectRequest: async () => {},
    };

    render(<App adapter={adapter} />);
    await screen.findByRole("heading", { name: "Computers" });

    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    expect((await screen.findAllByText("The runtime bridge did not respond.")).length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Computers" })).toBeInTheDocument();
  });

  it("shows an incoming Secure Connect request app-wide, regardless of the active page", async () => {
    const adapter = approvalAdapter({ hostConnectRequests: async () => [INCOMING] });
    render(<App adapter={adapter} initialPage="settings" />);

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("device-abcdef")).toBeInTheDocument();
    // The Settings page is still underneath the modal.
    expect(screen.getByRole("heading", { name: "Settings" })).toBeInTheDocument();
  });

  it("keeps the request visible with an error when approve fails, and closes it on retry", async () => {
    let approved = false;
    let calls = 0;
    const adapter = approvalAdapter({
      hostConnectRequests: async () => (approved ? [] : [INCOMING]),
      approveConnectRequest: async () => {
        calls += 1;
        if (calls === 1) {
          throw new Error("broker refused");
        }
        approved = true;
      },
    });
    render(<App adapter={adapter} />);

    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Approve" }));
    expect(await screen.findByText(/Could not approve/)).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    await waitForElementToBeRemoved(() => screen.queryByRole("dialog"));
  });

  it("closes the modal when a request is denied", async () => {
    let denied = false;
    const adapter = approvalAdapter({
      hostConnectRequests: async () => (denied ? [] : [INCOMING]),
      denyConnectRequest: async () => {
        denied = true;
      },
    });
    render(<App adapter={adapter} />);

    const dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Deny" }));
    await waitForElementToBeRemoved(() => screen.queryByRole("dialog"));
  });

  it("serializes multiple requests, showing one at a time", async () => {
    const second: ConnectRequest = {
      requestId: "r2",
      requesterDeviceId: "device-second",
      expiresInSeconds: 60,
    };
    const answered = new Set<string>();
    const adapter = approvalAdapter({
      hostConnectRequests: async () => [INCOMING, second].filter((r) => !answered.has(r.requestId)),
      approveConnectRequest: async (id) => {
        answered.add(id);
      },
    });
    render(<App adapter={adapter} />);

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("device-abcdef")).toBeInTheDocument();
    expect(screen.getAllByRole("dialog")).toHaveLength(1);

    fireEvent.click(within(dialog).getByRole("button", { name: "Approve" }));
    expect(await screen.findByText("device-second")).toBeInTheDocument();
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
  });

  it("shows a single modal when the same request appears across repeated polls", async () => {
    let polls = 0;
    const adapter = approvalAdapter({
      hostConnectRequests: async () => {
        polls += 1;
        return [INCOMING];
      },
    });
    render(<App adapter={adapter} />);

    await screen.findByRole("dialog");
    // Wait for at least one more poll of the same request; it must stay a single
    // modal, de-duplicated by request id.
    await waitFor(() => expect(polls).toBeGreaterThan(1), { timeout: 4000 });
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
  }, 6000);

  it("drops an expired request without approving or denying it", async () => {
    let approveCalls = 0;
    let denyCalls = 0;
    const brief: ConnectRequest = {
      requestId: "r1",
      requesterDeviceId: "device-abcdef",
      expiresInSeconds: 1,
    };
    const adapter = approvalAdapter({
      hostConnectRequests: async () => [brief],
      approveConnectRequest: async () => {
        approveCalls += 1;
      },
      denyConnectRequest: async () => {
        denyCalls += 1;
      },
    });
    render(<App adapter={adapter} />);

    await screen.findByRole("dialog");
    // Expires at ~1s and is removed before the 2s re-poll would re-add it. The
    // default-deny path is a silent drop, not an explicit deny call.
    await waitForElementToBeRemoved(() => screen.queryByRole("dialog"), { timeout: 1800 });
    expect(approveCalls).toBe(0);
    expect(denyCalls).toBe(0);
  }, 4000);

  it("removes the modal when the device is no longer authenticated", async () => {
    let authed = true;
    const snap = () => {
      const snapshot = hostingAuthedSnapshot();
      if (!authed) {
        snapshot.access = {
          ...snapshot.access,
          pairing: { state: "not-configured", detail: "Signed out." },
        };
      }
      return snapshot;
    };
    const adapter = approvalAdapter({
      getSnapshot: snap,
      refresh: async () => snap(),
      hostConnectRequests: async () => [INCOMING],
    });
    render(<App adapter={adapter} />);

    await screen.findByRole("dialog");
    authed = false;
    // The snapshot poll picks up the lost authentication, the poll gate closes,
    // and the queue is cleared.
    await waitForElementToBeRemoved(() => screen.queryByRole("dialog"), { timeout: 4000 });
  }, 6000);

  it("stops cleanly on unmount and shows the request again on remount", async () => {
    const adapter = approvalAdapter({ hostConnectRequests: async () => [INCOMING] });
    const { unmount } = render(<App adapter={adapter} />);
    await screen.findByRole("dialog");
    unmount();

    render(<App adapter={adapter} />);
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
  });
});
