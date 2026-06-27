import type { SqlRule } from '../sql-rule';
import {
  anonTableGrant,
  permissiveWritePolicy,
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
  anonTableGrant,
];

export {
  anonTableGrant,
  permissiveWritePolicy,
  securityDefinerSearchPath,
  tableWithoutRls,
  writePolicyWithoutCheck,
};
