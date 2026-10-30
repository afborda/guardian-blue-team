/** Visible answer from an NVIDIA chat message. Reasoning models often leave content empty. */
export function readNvidiaMessage(message: {
  content?: string | null;
  reasoning?: string | null;
  reasoning_content?: string | null;
} | null | undefined): string | null {
  const content = message?.content?.trim() ?? '';
  if (content) return content;
  const reasoning = (message?.reasoning ?? message?.reasoning_content ?? '').trim();
  return reasoning || null;
}
