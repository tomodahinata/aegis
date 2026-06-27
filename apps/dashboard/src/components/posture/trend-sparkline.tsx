import type { PostureBucket } from '@aegiskit/observability';
import { Card } from '@/components/ui/card';

const WIDTH = 240;
const HEIGHT = 48;

/** An accessible sparkline: an SVG with role/label + a visually-hidden data table (WCAG 1.1.1). */
export function TrendSparkline({ buckets }: { buckets: readonly PostureBucket[] }) {
  const max = Math.max(1, ...buckets.map((b) => b.weightedVolume));
  const divisor = Math.max(1, buckets.length - 1);
  const points = buckets
    .map((b, i) => {
      const x = (i / divisor) * WIDTH;
      const y = HEIGHT - (b.weightedVolume / max) * HEIGHT;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');

  return (
    <Card>
      <h2 className="font-medium text-muted text-sm">Event volume (24h)</h2>
      <svg
        role="img"
        aria-label={`Severity-weighted event volume across ${buckets.length} hourly buckets over the last 24 hours.`}
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        className="mt-3 h-12 w-full text-primary"
      >
        <polyline fill="none" stroke="currentColor" strokeWidth={2} points={points} />
      </svg>
      <table className="sr-only">
        <caption>Event volume by time bucket</caption>
        <thead>
          <tr>
            <th scope="col">Bucket</th>
            <th scope="col">Weighted volume</th>
          </tr>
        </thead>
        <tbody>
          {buckets.map((b, i) => (
            <tr key={b.start}>
              <td>{i + 1}</td>
              <td>{b.weightedVolume}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}
