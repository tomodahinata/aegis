import { describe, expect, it } from 'vitest';
import { scan } from '../engine';

function findingFor(source: string) {
  return scan({ files: ['/app/post.tsx'], readFile: () => source }).findings.find(
    (f) => f.ruleId === 'xss/dangerous-html-unsanitized',
  );
}

describe('xss/dangerous-html-unsanitized — variable resolution (precision)', () => {
  it('flags an inline unsanitized __html source', () => {
    expect(
      findingFor(
        'export const P = (p: { bio: string }) => <div dangerouslySetInnerHTML={{ __html: p.bio }} />;',
      ),
    ).toBeDefined();
  });

  it('passes an inline sanitized __html source', () => {
    expect(
      findingFor(
        "import DOMPurify from 'dompurify'; export const P = (p: { bio: string }) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(p.bio) }} />;",
      ),
    ).toBeUndefined();
  });

  it('does NOT false-positive when the value was sanitized into a variable first', () => {
    expect(
      findingFor(
        `import DOMPurify from 'dompurify';
         export function P({ bio }: { bio: string }) {
           const html = DOMPurify.sanitize(bio);
           return <div dangerouslySetInnerHTML={{ __html: html }} />;
         }`,
      ),
    ).toBeUndefined();
  });

  it('still flags an unsanitized value carried through a variable', () => {
    expect(
      findingFor(
        `export function P({ bio }: { bio: string }) {
           const html = bio;
           return <div dangerouslySetInnerHTML={{ __html: html }} />;
         }`,
      ),
    ).toBeDefined();
  });
});
