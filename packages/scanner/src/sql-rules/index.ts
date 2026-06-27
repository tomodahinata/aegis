import type { SqlRule } from '../sql-rule';
import {
  anonTableGrant,
  anonWritablePolicy,
  permissiveWritePolicy,
  policyNotOwnerScoped,
  securityDefinerSearchPath,
  tableWithoutRls,
  writePolicyWithoutCheck,
} from './rls';

/** The built-in Supabase RLS verification rules (zero-false-positive on a correct RLS design). */
export const ALL_SQL_RULES: readonly SqlRule[] = [
  tableWithoutRls,
  securityDefinerSearchPath,
  writePolicyWithoutCheck,
  permissiveWritePolicy,
  policyNotOwnerScoped,
  anonWritablePolicy,
  anonTableGrant,
];

export {
  anonTableGrant,
  anonWritablePolicy,
  permissiveWritePolicy,
  policyNotOwnerScoped,
  securityDefinerSearchPath,
  tableWithoutRls,
  writePolicyWithoutCheck,
};
