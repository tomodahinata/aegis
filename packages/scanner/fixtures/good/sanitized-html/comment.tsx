import DOMPurify from 'dompurify';

// Sanitized HTML — DOMPurify.sanitize is recognized as safe.
export function Comment({ body }: { body: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(body) }} />;
}
