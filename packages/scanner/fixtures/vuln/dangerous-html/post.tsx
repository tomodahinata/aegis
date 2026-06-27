export function Post({ bio }: { bio: string }) {
  // Unsanitized user content injected as HTML → stored/reflected XSS.
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}
