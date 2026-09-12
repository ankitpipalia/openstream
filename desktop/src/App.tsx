import { useEffect, useState } from "react";

import { AppShell } from "./components/AppShell";
import { createLocalAdapter } from "./adapters/productAdapter";
import type { ProductAdapter } from "./adapters/productAdapter";
import type { PageId } from "./model";
import { AboutPage } from "./pages/AboutPage";
import { AccessPage } from "./pages/AccessPage";
import { ComputersPage } from "./pages/ComputersPage";
import { DiagnosticsPage } from "./pages/DiagnosticsPage";
import { SettingsPage } from "./pages/SettingsPage";

const defaultAdapter = createLocalAdapter();

interface AppProps {
  adapter?: ProductAdapter;
  initialPage?: PageId;
}

function Page({ page, adapterSnapshot }: { page: PageId; adapterSnapshot: ReturnType<ProductAdapter["getSnapshot"]> }) {
  switch (page) {
    case "computers":
      return <ComputersPage snapshot={adapterSnapshot} />;
    case "access":
      return <AccessPage snapshot={adapterSnapshot} />;
    case "settings":
      return <SettingsPage snapshot={adapterSnapshot} />;
    case "diagnostics":
      return <DiagnosticsPage snapshot={adapterSnapshot} />;
    case "about":
      return <AboutPage snapshot={adapterSnapshot} />;
  }
}

export function App({ adapter = defaultAdapter, initialPage = "computers" }: AppProps) {
  const [activePage, setActivePage] = useState<PageId>(initialPage);
  const [snapshot, setSnapshot] = useState(() => adapter.getSnapshot());

  useEffect(() => {
    setSnapshot(adapter.getSnapshot());
    return adapter.subscribe(setSnapshot);
  }, [adapter]);

  return (
    <AppShell activePage={activePage} snapshot={snapshot} onNavigate={setActivePage}>
      <Page page={activePage} adapterSnapshot={snapshot} />
    </AppShell>
  );
}
