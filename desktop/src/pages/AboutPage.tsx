import type { ProductSnapshot } from "../model";
import { PageHeader, SectionCard } from "../components/AppShell";

export function AboutPage({ snapshot }: { snapshot: ProductSnapshot }) {
  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="Project"
        title="About"
        description="OpenStream is an inspectable, self-hostable remote desktop foundation."
      />

      <SectionCard title={snapshot.product.name} description="Product identity supplied by the local shell configuration.">
        <div className="about-identity">
          <div className="about-mark" aria-hidden="true"><span /><span /><span /></div>
          <div>
            <div className="about-name">{snapshot.product.name}</div>
            <div className="about-version">Version {snapshot.product.version} · {snapshot.product.channel}</div>
          </div>
        </div>
      </SectionCard>

      <div className="two-column-grid">
        <SectionCard title="Shell boundary" description="This UI renders adapter state and does not own transport credentials.">
          <ul className="plain-list">
            <li><span className="list-marker">01</span><span>Discovery, pairing, and session commands arrive through a typed adapter.</span></li>
            <li><span className="list-marker">02</span><span>Secrets and raw pairing payloads stay outside React state.</span></li>
            <li><span className="list-marker">03</span><span>Capabilities are shown as available, pending, unavailable, or experimental.</span></li>
          </ul>
        </SectionCard>

        <SectionCard title="Project links" description="Keep product work connected to the open implementation.">
          <div className="link-stack">
            <a href="https://github.com/ankitpipalia/openstream" target="_blank" rel="noreferrer">OpenStream on GitHub <span aria-hidden="true">↗</span></a>
            <a href="https://github.com/ankitpipalia/openstream/issues" target="_blank" rel="noreferrer">Report an issue <span aria-hidden="true">↗</span></a>
          </div>
        </SectionCard>
      </div>
    </div>
  );
}
