import { Linter } from 'eslint';
import { describe, expect, it } from 'vitest';
import { aegisSecurityRules } from './index';

function lint(code: string): string[] {
  const linter = new Linter();
  const messages = linter.verify(code, {
    languageOptions: { ecmaVersion: 2023, sourceType: 'module' },
    rules: aegisSecurityRules as Linter.RulesRecord,
  });
  return messages.map((m) => m.message);
}

describe('aegisSecurityRules', () => {
  it('flags a NEXT_PUBLIC_ secret', () => {
    const messages = lint('export const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;');
    expect(messages).toHaveLength(1);
    expect(messages[0]).toContain('NEXT_PUBLIC_');
  });

  it('flags eval and new Function', () => {
    expect(lint('eval("danger");')).toHaveLength(1);
    expect(lint('const f = new Function("a", "return a");')).toHaveLength(1);
  });

  it('flags a committed provider secret literal', () => {
    expect(lint("const k = 'sk_live_FAKEnotReal9';")).toHaveLength(1);
    expect(lint("const k = 'AKIAIOSFODNN7EXAMPLE';")).toHaveLength(1);
  });

  it('does NOT flag safe code (no false positives)', () => {
    expect(lint('export const url = process.env.NEXT_PUBLIC_SUPABASE_URL;')).toHaveLength(0);
    expect(lint('export const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;')).toHaveLength(0);
    expect(lint('const x = 1 + 2; const s = "hello world";')).toHaveLength(0);
  });
});
