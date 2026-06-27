import { z } from 'zod';

// SAFE: comparing two user-entered values for equality ("passwords must match") is form validation,
// NOT a timing-sensitive secret verification. The crypto rule must not flag `password === confirmPassword`.
export const SignUpInput = z
  .object({ password: z.string().min(8), confirmPassword: z.string().min(1) })
  .refine((v) => v.password === v.confirmPassword, { path: ['confirmPassword'], message: 'mismatch' });
