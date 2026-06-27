import type { CapturedResponse } from '../http/evidence';
import { toHttpExchange } from '../http/evidence';
import { bodySignature, docsUrlFor, dynamicFinding, getOk, pathOf } from './helpers';
import type { Identity, Probe, ProbeContext, ProbeMeta } from './types';

function authHeaders(identity: Identity): Record<string, string> {
  switch (identity.auth.kind) {
    case 'cookie':
      return { cookie: identity.auth.cookie };
    case 'bearer':
      return { authorization: `Bearer ${identity.auth.token}` };
    case 'header':
      return { [identity.auth.name]: identity.auth.value };
  }
}

async function getAs(
  ctx: ProbeContext,
  url: string,
  identity: Identity,
): Promise<CapturedResponse | undefined> {
  const result = await ctx.http.send({ method: 'GET', url, headers: authHeaders(identity) });
  return result.ok ? result.response : undefined;
}

function isOk(response: CapturedResponse): boolean {
  return response.status >= 200 && response.status < 300;
}

const authMeta: ProbeMeta = {
  id: 'dast/auth-required',
  title: 'Protected route reachable without authentication',
  severity: 'HIGH',
  owasp: 'A01:2021 Broken Access Control',
  blastRadius: 'active',
  docsUrl: docsUrlFor('dast/auth-required'),
};

export const authRequired: Probe = {
  meta: authMeta,
  // Only probe routes the operator explicitly marked as protected — never guess that a 200 should be gated.
  appliesTo: () => true,
  async run(ctx) {
    const protectedPaths = ctx.identities?.protectedPaths ?? [];
    if (!protectedPaths.includes(ctx.target.path)) {
      return;
    }
    const response = await getOk(ctx, ctx.target.url); // no credentials
    if (response && isOk(response)) {
      ctx.report(
        dynamicFinding(authMeta, ctx, {
          confidence: 'high',
          message: `${ctx.target.path} is marked protected but returned ${response.status} to an UNAUTHENTICATED request — the authorization check is missing or bypassable.`,
          remediation:
            'Verify the session on this route (and return 401/redirect for anonymous callers) before returning any data.',
          evidence: `unauthenticated → HTTP ${response.status}`,
          target: toHttpExchange('GET', pathOf(ctx.target.url), response),
        }),
      );
    }
  },
};

const idorMeta: ProbeMeta = {
  id: 'dast/idor',
  title: 'Insecure direct object reference (cross-identity read)',
  severity: 'BLOCKER',
  owasp: 'A01:2021 Broken Access Control',
  blastRadius: 'active',
  docsUrl: docsUrlFor('dast/idor'),
};

export const idor: Probe = {
  meta: idorMeta,
  appliesTo: () => true,
  async run(ctx) {
    const config = ctx.identities;
    if (!config || config.identities.length < 2) {
      return;
    }
    const [owner, other] = config.identities;
    if (!owner || !other) {
      return;
    }
    for (const objectPath of owner.ownsObjectAt ?? []) {
      const objectUrl = `${ctx.origin.replace(/\/$/, '')}${objectPath}`;
      const asOwner = await getAs(ctx, objectUrl, owner);
      if (!asOwner || !isOk(asOwner)) {
        continue; // the owner can't even read it — nothing to compare
      }
      const asOther = await getAs(ctx, objectUrl, other);
      // Unauthorized access = a DIFFERENT identity receives the SAME object body with a success status.
      if (asOther && isOk(asOther) && bodySignature(asOther) === bodySignature(asOwner)) {
        ctx.report(
          dynamicFinding(idorMeta, ctx, {
            confidence: 'high',
            message: `${objectPath} returns "${owner.label}"'s object to "${other.label}" — there is no per-object authorization, so any user can read another user's data (IDOR).`,
            remediation:
              'Scope every object read to the caller (e.g. filter by owner id / enforce an RLS policy); never trust a client-supplied object id alone.',
            evidence: `${objectPath} readable across identities`,
            target: toHttpExchange('GET', objectPath, asOther),
          }),
        );
        return;
      }
    }
  },
};
