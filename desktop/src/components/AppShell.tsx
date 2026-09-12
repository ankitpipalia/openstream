import type { ReactNode } from "react";

import type { ConnectionState, PageId, ProductSnapshot } from "../model";
import { navigationItems } from "../model";
import { StatusBadge } from "./StatusBadge";

interface AppShellProps {
  activePage: PageId;
  snapshot: ProductSnapshot;
  onNavigate: (page: PageId) => void;
  children: ReactNode;
}

function connectionLabel(state: ConnectionState): string {
  switch (state) {
    case "connected":
      return "Session connected";
    case "connecting":
      return "Connecting";
    case "unavailable":
      return "Session unavailable";
    case "idle":
      return "No active session";
  }
}

function connectionTone(state: ConnectionState) {
  switch (state) {
    case "connected":
      return "available" as const;
    case "connecting":
      return "pending" as const;
    case "unavailable":
      return "unavailable" as const;
    case "idle":
      return "idle" as const;
  }
}

function BrandMark() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <span />
      <span />
      <span />
    </span>
  );
}

function NavGlyph({ page }: { page: PageId }) {
  const paths: Record<PageId, string> = {
    computers: "M4 5.5A1.5 1.5 0 0 1 5.5 4h13A1.5 1.5 0 0 1 20 5.5v8A1.5 1.5 0 0 1 18.5 15h-13A1.5 1.5 0 0 1 4 13.5zM8 20h8M12 15v5",
    access: "M8 10V7a4 4 0 1 1 8 0v3M6 10h12v9H6zM12 14v2",
    settings: "M12 8.5a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7zm0-5v2m0 13v2M3.5 12h2m13 0h2M5.9 5.9l1.4 1.4m9.4 9.4 1.4 1.4m0-12.2-1.4 1.4M7.3 16.7l-1.4 1.4",
    diagnostics: "M4 17h3v3H4zM10.5 11h3v9h-3zM17 4h3v16h-3z",
    about: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zm0-10v6m0-9.5v.1",
  };

  return (
    <svg className="nav-glyph" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={paths[page]} />
    </svg>
  );
}

export function AppShell({ activePage, snapshot, onNavigate, children }: AppShellProps) {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <BrandMark />
          <div>
            <div className="brand-name">OpenStream</div>
            <div className="brand-subtitle">Desktop shell</div>
          </div>
        </div>

        <nav className="primary-nav" aria-label="Primary">
          <div className="nav-section-label">Workspace</div>
          {navigationItems.slice(0, 2).map((item) => (
            <button
              className={`nav-item ${activePage === item.id ? "nav-item-active" : ""}`}
              type="button"
              key={item.id}
              onClick={() => onNavigate(item.id)}
              aria-current={activePage === item.id ? "page" : undefined}
              title={item.hint}
            >
              <NavGlyph page={item.id} />
              <span>{item.label}</span>
            </button>
          ))}

          <div className="nav-section-label nav-section-label-spaced">Configure</div>
          {navigationItems.slice(2, 4).map((item) => (
            <button
              className={`nav-item ${activePage === item.id ? "nav-item-active" : ""}`}
              type="button"
              key={item.id}
              onClick={() => onNavigate(item.id)}
              aria-current={activePage === item.id ? "page" : undefined}
              title={item.hint}
            >
              <NavGlyph page={item.id} />
              <span>{item.label}</span>
            </button>
          ))}

          <div className="nav-section-label nav-section-label-spaced">Project</div>
          <button
            className={`nav-item ${activePage === "about" ? "nav-item-active" : ""}`}
            type="button"
            onClick={() => onNavigate("about")}
            aria-current={activePage === "about" ? "page" : undefined}
            title="Version and project details"
          >
            <NavGlyph page="about" />
            <span>About</span>
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className="footer-label">Runtime status</div>
          <StatusBadge label={connectionLabel(snapshot.connection.state)} tone={connectionTone(snapshot.connection.state)} />
          <p>{snapshot.connection.detail}</p>
        </div>
      </aside>

      <div className="shell-content">
        <header className="topbar">
          <div className="topbar-context">OpenStream / {navigationItems.find((item) => item.id === activePage)?.label}</div>
          <div className="topbar-meta">
            <span className="environment-chip">{snapshot.product.channel}</span>
            <span className="version-label">v{snapshot.product.version}</span>
          </div>
        </header>
        <main className="page-content">{children}</main>
      </div>
    </div>
  );
}

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow?: string; title: string; description: string; actions?: ReactNode }) {
  return (
    <div className="page-header">
      <div>
        {eyebrow ? <div className="page-eyebrow">{eyebrow}</div> : null}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </div>
  );
}

export function SectionCard({ title, description, children, className = "" }: { title: string; description?: string; children: ReactNode; className?: string }) {
  return (
    <section className={`section-card ${className}`}>
      <div className="section-card-heading">
        <div>
          <h2>{title}</h2>
          {description ? <p>{description}</p> : null}
        </div>
      </div>
      {children}
    </section>
  );
}

export function EmptyState({ title, description, action }: { title: string; description: string; action?: ReactNode }) {
  return (
    <div className="empty-state">
      <div className="empty-state-orbit" aria-hidden="true">
        <span />
      </div>
      <h2>{title}</h2>
      <p>{description}</p>
      {action ? <div className="empty-state-action">{action}</div> : null}
    </div>
  );
}
