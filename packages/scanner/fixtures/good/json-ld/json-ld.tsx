// JSON-LD via JSON.stringify of a typed object — the canonical SAFE dangerouslySetInnerHTML use.
export function JsonLd({ data }: { data: Record<string, unknown> }) {
  return (
    <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} />
  );
}
