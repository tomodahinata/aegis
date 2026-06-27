export function relativeTime(at: number, now: number = Date.now()): string {
  const seconds = Math.floor(Math.max(0, now - at) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export function percent(fraction: number): string {
  return `${Math.round(fraction * 100)}%`;
}
