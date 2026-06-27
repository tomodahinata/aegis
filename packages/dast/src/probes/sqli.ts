import { toHttpExchange } from '../http/evidence';
import { bodySignature, docsUrlFor, dynamicFinding, getOk, pathOf, withQuery } from './helpers';
import type { Probe, ProbeMeta } from './types';

const CANDIDATE_PARAMS = ['id', 'q', 'slug'];
const DB_ERROR =
  /\bSQL syntax\b|syntax error at or near|\bPostgresError\b|SQLSTATE|\bPG::|unterminated quoted string|sqlite3[._]|ORA-\d{5}|mysql_fetch|valid MySQL result/i;

const meta: ProbeMeta = {
  id: 'dast/sql-injection',
  title: 'SQL injection (runtime-confirmed)',
  severity: 'BLOCKER',
  owasp: 'A03:2021 Injection',
  blastRadius: 'passive',
  docsUrl: docsUrlFor('dast/sql-injection'),
};

export const sqlInjection: Probe = {
  meta,
  appliesTo: (target) => target.methods.has('GET') || target.methods.size === 0,
  async run(ctx) {
    for (const param of CANDIDATE_PARAMS) {
      const baseline = await getOk(ctx, withQuery(ctx.target.url, param, '1'));
      if (!baseline) {
        continue;
      }

      // Error-based: a single quote provokes a database error signature.
      const errorUrl = withQuery(ctx.target.url, param, "1'");
      const errored = await getOk(ctx, errorUrl);
      if (errored && DB_ERROR.test(errored.body)) {
        ctx.report(
          dynamicFinding(meta, ctx, {
            confidence: 'high',
            message: `${ctx.target.path} returned a database error when "?${param}=" carried a single quote — input reaches a SQL query unparameterized (SQL injection).`,
            remediation:
              'Use bound parameters / a parameterized query builder; never concatenate input into SQL.',
            evidence: `?${param}=1' → DB error`,
            target: toHttpExchange('GET', pathOf(errorUrl), errored),
          }),
        );
        return;
      }

      // Boolean-based: a TRUE condition matches the baseline while a FALSE one differs — reproduced twice.
      const base = bodySignature(baseline);
      const pairMatches = async (truthy: string, falsy: string): Promise<boolean> => {
        const t = await getOk(ctx, withQuery(ctx.target.url, param, truthy));
        const f = await getOk(ctx, withQuery(ctx.target.url, param, falsy));
        return (
          t !== undefined &&
          f !== undefined &&
          bodySignature(t) === base &&
          bodySignature(f) !== base
        );
      };
      if (
        (await pairMatches("1' AND '1'='1", "1' AND '1'='2")) &&
        (await pairMatches("1' AND '7'='7", "1' AND '7'='8"))
      ) {
        const confirmUrl = withQuery(ctx.target.url, param, "1' AND '1'='1");
        const confirm = await getOk(ctx, confirmUrl);
        ctx.report(
          dynamicFinding(meta, ctx, {
            confidence: 'high',
            message: `${ctx.target.path} is SQL-injectable via "?${param}=": a true vs false boolean condition produces a reproducible, controlled difference in the response (blind SQL injection).`,
            remediation:
              'Use bound parameters / a parameterized query builder; never concatenate input into SQL.',
            evidence: `?${param}= boolean differential (reproduced)`,
            target: toHttpExchange('GET', pathOf(confirmUrl), confirm ?? baseline),
          }),
        );
        return;
      }
    }
  },
};
