/** A caller mistake (bad flag or argument). The CLI entrypoint maps it to EXIT.USAGE (2). */
export class UsageError extends Error {}
