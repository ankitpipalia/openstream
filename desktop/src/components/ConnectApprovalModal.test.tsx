import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ConnectApprovalModal } from "./ConnectApprovalModal";
import type { ConnectRequest, PermissionSet } from "../model";

const NONE: PermissionSet = {
  view: false,
  keyboard: false,
  mouse: false,
  gamepad: false,
  clipboard: false,
  microphone: false,
  tablet: false,
  virtual_usb: false,
};

function request(requested?: PermissionSet): ConnectRequest {
  return {
    requestId: "r1",
    requesterDeviceId: "device-abcdef",
    expiresInSeconds: 60,
    requested,
  };
}

function noop() {}

describe("ConnectApprovalModal", () => {
  it("lists the requested permission classes, and only those, when the broker carries them", () => {
    const requested: PermissionSet = { ...NONE, view: true, keyboard: true, mouse: true };
    render(
      <ConnectApprovalModal
        request={request(requested)}
        secondsRemaining={30}
        pending={false}
        error={null}
        onApprove={noop}
        onDeny={noop}
      />,
    );

    const list = screen.getByRole("list", { name: "Requested access" });
    expect(within(list).getByText("Screen")).toBeInTheDocument();
    expect(within(list).getByText("Keyboard")).toBeInTheDocument();
    expect(within(list).getByText("Mouse")).toBeInTheDocument();
    // Classes the requester did not ask for are not offered.
    expect(within(list).queryByText("Clipboard")).toBeNull();
    expect(within(list).queryByText("Microphone")).toBeNull();
    expect(screen.getByText(/Approving grants exactly what is listed/)).toBeInTheDocument();
  });

  it("falls back to the host-policy note when the payload carries no permissions", () => {
    render(
      <ConnectApprovalModal
        request={request(undefined)}
        secondsRemaining={null}
        pending={false}
        error={null}
        onApprove={noop}
        onDeny={noop}
      />,
    );

    expect(screen.getByText(/allowed by this host's/)).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Requested access" })).toBeNull();
  });
});
