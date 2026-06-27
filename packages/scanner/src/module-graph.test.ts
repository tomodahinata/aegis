import { describe, expect, it } from 'vitest';
import { computeReachableFromClient, type GraphNode } from './module-graph';

function graph(edges: Record<string, string[]>): Map<string, GraphNode> {
  const nodes = new Map<string, GraphNode>();
  for (const [path, targets] of Object.entries(edges)) {
    nodes.set(path, { path, importsResolved: new Set(targets) });
  }
  return nodes;
}

describe('computeReachableFromClient', () => {
  it('marks a transitively-imported module reachable (client → mid → leaf)', () => {
    const nodes = graph({
      '/panel.tsx': ['/billing.ts'],
      '/billing.ts': ['/secret.ts'],
      '/secret.ts': [],
    });
    const reachable = computeReachableFromClient(nodes, ['/panel.tsx']);
    expect(reachable.has('/billing.ts')).toBe(true);
    expect(reachable.has('/secret.ts')).toBe(true);
    // The seed itself is classified directly, not via reachability.
    expect(reachable.has('/panel.tsx')).toBe(false);
  });

  it('does not mark modules unreachable from any client seed', () => {
    const nodes = graph({
      '/panel.tsx': ['/billing.ts'],
      '/billing.ts': [],
      '/server-only.ts': ['/db.ts'],
      '/db.ts': [],
    });
    const reachable = computeReachableFromClient(nodes, ['/panel.tsx']);
    expect(reachable.has('/billing.ts')).toBe(true);
    expect(reachable.has('/server-only.ts')).toBe(false);
    expect(reachable.has('/db.ts')).toBe(false);
  });

  it('terminates on import cycles', () => {
    const nodes = graph({
      '/a.tsx': ['/b.ts'],
      '/b.ts': ['/a.tsx'],
    });
    const reachable = computeReachableFromClient(nodes, ['/a.tsx']);
    expect(reachable.has('/b.ts')).toBe(true);
    expect(reachable.has('/a.tsx')).toBe(true); // reached via the cycle back-edge
  });

  it('returns an empty set when there are no client seeds', () => {
    const nodes = graph({ '/a.ts': ['/b.ts'], '/b.ts': [] });
    expect(computeReachableFromClient(nodes, []).size).toBe(0);
  });

  it('prunes a barrier and the subtree reachable only through it', () => {
    // client → B(barrier) → D, and client → C, B → C. C survives via its direct edge.
    const nodes = graph({
      '/client.tsx': ['/B.ts', '/C.ts'],
      '/B.ts': ['/C.ts', '/D.ts'],
      '/C.ts': [],
      '/D.ts': [],
    });
    const reachable = computeReachableFromClient(nodes, ['/client.tsx'], new Set(['/B.ts']));
    expect(reachable.has('/B.ts')).toBe(false); // barrier excluded
    expect(reachable.has('/D.ts')).toBe(false); // reachable only through the barrier
    expect(reachable.has('/C.ts')).toBe(true); // survives via the direct client edge
  });
});
