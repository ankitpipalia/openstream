import { describe, expect, it } from "vitest";

import { createEmptySnapshot, createLocalAdapter } from "./productAdapter";

describe("local product adapter", () => {
  it("starts without claiming a host or session is ready", () => {
    const snapshot = createEmptySnapshot();

    expect(snapshot.computers).toEqual([]);
    expect(snapshot.connection.state).toBe("idle");
    expect(snapshot.diagnostics.session.state).toBe("idle");
    expect(snapshot.capabilities.every((capability) => capability.state !== "available")).toBe(true);
  });

  it("publishes deterministic fixture updates through the adapter boundary", () => {
    const adapter = createLocalAdapter(createEmptySnapshot());
    const updates: string[] = [];
    const unsubscribe = adapter.subscribe((snapshot) => {
      updates.push(snapshot.connection.state);
    });

    adapter.setSnapshot({
      ...createEmptySnapshot(),
      connection: {
        state: "unavailable",
        detail: "The local control plane is not configured.",
      },
    });

    expect(adapter.getSnapshot().connection.state).toBe("unavailable");
    expect(updates).toEqual(["unavailable"]);

    unsubscribe();
    adapter.setSnapshot(createEmptySnapshot());
    expect(updates).toEqual(["unavailable"]);
  });
});
