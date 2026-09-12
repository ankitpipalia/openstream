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
      return <AccessPage snapshot={snapshot} />;
    case "settings":
      return <SettingsPage snapshot={snapshot} />;
    case "diagnostics":
      return <DiagnosticsPage snapshot={snapshot} />;
    case "about":
      return <AboutPage snapshot={snapshot} />;
  }
}

export function App({ adapter = defaultAdapter, initialPage = "computers" }: AppProps) {
  const [activePage, setActivePage] = useState<PageId>(initialPage);
  const [snapshot, setSnapshot] = useState(() => adapter.getSnapshot());

  useEffect(() => {
    let cancelled = false;
    setSnapshot(adapter.getSnapshot());
    const unsubscribe = adapter.subscribe(setSnapshot);
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
      });
    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, [adapter]);

  return (
    <AppShell activePage={activePage} snapshot={snapshot} onNavigate={setActivePage}>
      <Page page={activePage} adapter={adapter} snapshot={snapshot} onSnapshot={setSnapshot} />
    </AppShell>
  );
}
