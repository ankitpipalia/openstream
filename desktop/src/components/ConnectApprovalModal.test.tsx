import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

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
  it("offers a pre-checked checkbox for each requested class, and only those", () => {
    render(
      <ConnectApprovalModal
        request={request({ ...NONE, view: true, keyboard: true, mouse: true })}
        secondsRemaining={30}
        pending={false}
        error={null}
        onApprove={noop}
        onDeny={noop}
      />,
    );

    const list = screen.getByRole("list", { name: "Requested access" });
    expect(within(list).getAllByRole("checkbox")).toHaveLength(3);
    expect(within(list).getByLabelText("Screen")).toBeChecked();
    expect(within(list).getByLabelText("Keyboard")).toBeChecked();
    expect(within(list).getByLabelText("Mouse")).toBeChecked();
    // A class the requester did not ask for is never offered to grant.
    expect(within(list).queryByLabelText("Clipboard")).toBeNull();
  });

  it("grants only the classes the host leaves checked", () => {
    const onApprove = vi.fn();
    render(
      <ConnectApprovalModal
        request={request({ ...NONE, view: true, keyboard: true, mouse: true })}
        secondsRemaining={30}
        pending={false}
        error={null}
        onApprove={onApprove}
        onDeny={noop}
      />,
    );

    // The host narrows the grant: uncheck Mouse, then approve.
    fireEvent.click(screen.getByLabelText("Mouse"));
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));

    expect(onApprove).toHaveBeenCalledTimes(1);
    const granted = onApprove.mock.calls[0][0] as PermissionSet;
    expect(granted.view).toBe(true);
    expect(granted.keyboard).toBe(true);
    expect(granted.mouse).toBe(false);
    expect(granted.clipboard).toBe(false);
  });

  it("falls back to the host-policy default when the payload carries no permissions", () => {
    const onApprove = vi.fn();
    render(
      <ConnectApprovalModal
        request={request(undefined)}
        secondsRemaining={null}
        pending={false}
        error={null}
        onApprove={onApprove}
        onDeny={noop}
      />,
    );

    expect(screen.getByText(/allowed by this host's/)).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Requested access" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    // No request to narrow: the grant is left to the server-derived default.
    expect(onApprove).toHaveBeenCalledWith(undefined);
  });
});
