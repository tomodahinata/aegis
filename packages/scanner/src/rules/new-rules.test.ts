import { describe, expect, it } from 'vitest';
import { scan } from '../engine';

function idsFor(path: string, source: string, ruleId: string): string[] {
  return scan({ files: [path], readFile: () => source })
    .findings.filter((f) => f.ruleId === ruleId)
    .map((f) => f.ruleId);
}

function findingFor(path: string, source: string, ruleId: string) {
  return scan({ files: [path], readFile: () => source }).findings.find((f) => f.ruleId === ruleId);
}

const XSS = 'xss/dangerous-html-unsanitized';

describe('xss/dangerous-html-unsanitized', () => {
  it('flags an unsanitized __html source (high confidence)', () => {
    const finding = findingFor(
      '/a/post.tsx',
      'export const X = (p: { bio: string }) => <div dangerouslySetInnerHTML={{ __html: p.bio }} />;',
      XSS,
    );
    expect(finding?.confidence).toBe('high');
  });

  it('passes JSON.stringify (the json-ld pattern)', () => {
    expect(
      idsFor(
        '/a/ld.tsx',
        'export const X = (d: object) => <script dangerouslySetInnerHTML={{ __html: JSON.stringify(d) }} />;',
        XSS,
      ),
    ).toHaveLength(0);
  });

  it('passes a sanitizer call and a static literal', () => {
    expect(
      idsFor(
        '/a/s.tsx',
        'export const X = (b: string) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(b) }} />;',
        XSS,
      ),
    ).toHaveLength(0);
    expect(
      idsFor(
        '/a/c.tsx',
        "export const X = () => <div dangerouslySetInnerHTML={{ __html: '<b>hi</b>' }} />;",
        XSS,
      ),
    ).toHaveLength(0);
  });
});

const SECRETS = 'secrets/committed-literal';
const STRIPE = "export const k = 'sk_live_FAKEnotReal9';";

describe('secrets/committed-literal', () => {
  it('flags a Stripe live key with masked evidence', () => {
    const finding = findingFor('/a/pay.ts', STRIPE, SECRETS);
    expect(finding?.confidence).toBe('high');
    expect(finding?.evidence).toContain('sk_live_');
    expect(finding?.evidence).not.toContain('FAKEnot'); // the middle is masked
  });

  it('skips test files and the allow pragma', () => {
    expect(idsFor('/a/pay.test.ts', STRIPE, SECRETS)).toHaveLength(0);
    expect(idsFor('/a/ok.ts', `${STRIPE} // aegis-allow-secret`, SECRETS)).toHaveLength(0);
  });

  it('does NOT flag a base62 / base64url encoder ALPHABET constant (charset, not a secret)', () => {
    expect(
      idsFor(
        '/a/base62.ts',
        'const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";',
        SECRETS,
      ),
    ).toHaveLength(0);
    expect(
      idsFor(
        '/a/slug.ts',
        'const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";',
        SECRETS,
      ),
    ).toHaveLength(0);
  });

  it('still flags a genuinely random high-entropy literal (low confidence)', () => {
    const finding = findingFor(
      '/a/cfg.ts',
      'const t = "Zx7Qm2Kp9Lw4Rt6Yb8Hd3Fg5Js1Ac0Dd2Ee9Bf4Gh7";',
      SECRETS,
    );
    expect(finding?.confidence).toBe('low');
  });
});

const DOM_XSS = 'xss/tainted-dom-sink';

describe('xss/tainted-dom-sink — .write() receiver discipline', () => {
  const taint = (sink: string): string =>
    `import { NextRequest } from 'next/server';
     export function GET(req: NextRequest) {
       const u = req.nextUrl.searchParams.get('u') ?? '';
       ${sink};
     }`;

  it('flags document.write() reached by untrusted input', () => {
    expect(idsFor('/app/api/x/route.ts', taint('document.write(u)'), DOM_XSS)).toHaveLength(1);
  });

  it('flags window.document.write() (qualified document receiver)', () => {
    expect(idsFor('/app/api/x/route.ts', taint('window.document.write(u)'), DOM_XSS)).toHaveLength(
      1,
    );
  });

  it("flags window['document'].write() (computed document receiver)", () => {
    expect(
      idsFor('/app/api/x/route.ts', taint("window['document'].write(u)"), DOM_XSS),
    ).toHaveLength(1);
  });

  it('flags el.ownerDocument.write() (ownerDocument is always a Document per the DOM spec)', () => {
    expect(idsFor('/app/api/x/route.ts', taint('el.ownerDocument.write(u)'), DOM_XSS)).toHaveLength(
      1,
    );
  });

  it('does NOT flag a Node stream .write() (process.stderr / res) — not a DOM sink', () => {
    expect(idsFor('/app/api/x/route.ts', taint('process.stderr.write(u)'), DOM_XSS)).toHaveLength(
      0,
    );
    expect(idsFor('/app/api/x/route.ts', taint('res.write(u)'), DOM_XSS)).toHaveLength(0);
  });

  it('does NOT flag a bare non-document identifier .write() (e.g. a stream variable)', () => {
    expect(idsFor('/app/api/x/route.ts', taint('stream.write(u)'), DOM_XSS)).toHaveLength(0);
    expect(idsFor('/app/api/x/route.ts', taint("obj['outStream'].write(u)"), DOM_XSS)).toHaveLength(
      0,
    );
  });
});

const PUBLIC_SECRET = 'env/public-secret';

describe('env/public-secret — known-public keys', () => {
  const env = (key: string): string => `export const v = process.env.${key};`;

  it('does NOT flag NEXT_PUBLIC_INDEXNOW_KEY (public by protocol design)', () => {
    expect(idsFor('/a/seo.ts', env('NEXT_PUBLIC_INDEXNOW_KEY'), PUBLIC_SECRET)).toHaveLength(0);
  });

  it('does NOT flag a NEXT_PUBLIC_*_SITE_KEY (captcha public site key)', () => {
    expect(
      idsFor('/a/captcha.ts', env('NEXT_PUBLIC_RECAPTCHA_SITE_KEY'), PUBLIC_SECRET),
    ).toHaveLength(0);
  });

  it('STILL flags a real secret behind the NEXT_PUBLIC_ prefix', () => {
    expect(idsFor('/a/leak.ts', env('NEXT_PUBLIC_STRIPE_SECRET_KEY'), PUBLIC_SECRET)).toHaveLength(
      1,
    );
  });

  it('STILL flags NEXT_PUBLIC_WEBSITE_KEY (the SITE_KEY allowlist is anchored, WEBSITE has no `_`)', () => {
    expect(idsFor('/a/leak.ts', env('NEXT_PUBLIC_WEBSITE_KEY'), PUBLIC_SECRET)).toHaveLength(1);
  });

  it('STILL flags NEXT_PUBLIC_INDEXNOW_SECRET (only INDEXNOW_KEY is public, not every INDEXNOW name)', () => {
    expect(idsFor('/a/leak.ts', env('NEXT_PUBLIC_INDEXNOW_SECRET'), PUBLIC_SECRET)).toHaveLength(1);
  });
});

const CSRF = 'csrf/missing-origin-check';

describe('csrf/missing-origin-check — cookie-auth detection ignores comments', () => {
  it('does NOT flag a route whose only @supabase/ssr mention is in a comment', () => {
    // A Sentry-tunnel-style handler that merely documents the import exception is not cookie-authed.
    expect(
      idsFor(
        '/app/monitoring/route.ts',
        `// the same status as @supabase/ssr in middleware — documented exception
         export const POST = (req: Request) => new Response('ok');`,
        CSRF,
      ),
    ).toHaveLength(0);
  });

  it('STILL flags a genuinely cookie-authed POST handler with no origin check', () => {
    expect(
      idsFor(
        '/app/api/x/route.ts',
        `import { createServerClient } from '@supabase/ssr';
         export async function POST(req: Request) {
           const supabase = createServerClient('u', 'k', { cookies: {} as never });
           await supabase.from('t').insert({});
           return new Response('ok');
         }`,
        CSRF,
      ),
    ).toHaveLength(1);
  });
});
