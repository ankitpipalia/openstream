import { useEffect, useState } from "react";

import { AppShell } from "./components/AppShell";
import { createRuntimeUnavailableSnapshot } from "./adapters/productAdapter";
import type { ProductAdapter } from "./adapters/productAdapter";
import { createDefaultAdapter } from "./adapters/tauriAdapter";
import type { PageId, ProductSnapshot } from "./model";
import { AboutPage } from "./pages/AboutPage";
import { AccessPage } from "./pages/AccessPage";
import { ComputersPage } from "./pages/ComputersPage";
import { DiagnosticsPage } from "./pages/DiagnosticsPage";
import { SettingsPage } from "./pages/SettingsPage";

const defaultAdapter = createDefaultAdapter();
const BRIDGE_UNAVAILABLE_DETAIL = "The runtime bridge did not respond.";
/**
 * How often the shell re-reads the runtime snapshot.
 *
 * Rust reconciles its host state against the real agent on its own clock --
 * a child that crashed, restarted, or exhausted its restart budget is not a
 * reply to anything the operator did -- so a shell that only refreshed on
 * user action would keep rendering whatever was true when the operator last
 * pressed something.
 */
const SNAPSHOT_POLL_INTERVAL_MS = 2_000;

interface AppProps {
  adapter?: ProductAdapter;
  initialPage?: PageId;
}

function Page({
  page,
  adapter,
  snapshot,
  onSnapshot,
}: {
  page: PageId;
  adapter: ProductAdapter;
  snapshot: ProductSnapshot;
  onSnapshot: (snapshot: ProductSnapshot) => void;
}) {
  switch (page) {
    case "computers":
      return <ComputersPage snapshot={snapshot} adapter={adapter} onSnapshot={onSnapshot} />;
    case "access":
      return <AccessPage snapshot={snapshot} adapter={adapter} onSnapshot={onSnapshot} />;
    case "settings":
      return <SettingsPage snapshot={snapshot} adapter={adapter} onSnapshot={onSnapshot} />;
    case "diagnostics":
      return <DiagnosticsPage snapshot={snapshot} adapter={adapter} onSnapshot={onSnapshot} />;
    case "about":
      return <AboutPage snapshot={snapshot} />;
  }
}

export function App({ adapter = defaultAdapter, initialPage = "computers" }: AppProps) {
  const [activePage, setActivePage] = useState<PageId>(initialPage);
  const [snapshot, setSnapshot] = useState(() => adapter.getSnapshot());

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setSnapshot(adapter.getSnapshot());
    const unsubscribe = adapter.subscribe(setSnapshot);

    // Self-scheduling rather than setInterval, so only one refresh is ever
    // in flight. A fixed interval can start a second invoke while the first
    // is still stalled, and whichever resolves last wins -- which is how an
    // older snapshot ends up overwriting a newer one.
    const scheduleNext = () => {
      if (!cancelled) {
        timer = setTimeout(refresh, SNAPSHOT_POLL_INTERVAL_MS);
      }
    };
    const refresh = () =>
      adapter
        .refresh()
        .then((next) => {
          if (!cancelled) {
            setSnapshot(next);
          }
        })
        .catch(() => {
          if (!cancelled) {
            setSnapshot(createRuntimeUnavailableSnapshot(BRIDGE_UNAVAILABLE_DETAIL));
          }
        })
        .finally(scheduleNext);

    refresh();
    return () => {
      cancelled = true;
      if (timer !== undefined) {
        clearTimeout(timer);
      }
      unsubscribe();
    };
  }, [adapter]);

  return (
    <AppShell activePage={activePage} snapshot={snapshot} onNavigate={setActivePage}>
      <Page page={activePage} adapter={adapter} snapshot={snapshot} onSnapshot={setSnapshot} />
    </AppShell>
  );
}
