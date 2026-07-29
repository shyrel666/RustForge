export interface UpdateNotesPresentation {
  title: string;
  highlights: string[];
  fallback: string;
}

const DEFAULT_TITLE = "更新说明";
const DEFAULT_FALLBACK = "该版本暂未提供详细说明，安装前仍会校验发布签名。";
const MAX_HIGHLIGHTS = 8;

function stripInlineMarkdown(value: string): string {
  return value
    .replace(/!\[([^\]]*)\]\([^)]+\)/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/(\*\*|__|`)/g, "")
    .replace(/<[^>]+>/g, "")
    .trim();
}

function cleanHighlight(value: string): string {
  return stripInlineMarkdown(value)
    .replace(/^\s*[-*+]\s+/, "")
    .replace(/^\s*\d+[.)、]\s+/, "")
    .replace(/[；;。.\s]+$/u, "")
    .trim();
}

function appendHighlight(target: string[], value: string) {
  const cleaned = cleanHighlight(value);
  if (!cleaned || target.includes(cleaned)) return;
  target.push(cleaned);
}

function parseMarkdownSection(source: string): UpdateNotesPresentation | null {
  const lines = source.split(/\r?\n/);
  const headings = lines
    .map((line, index) => {
      const match = line.match(/^\s*(#{1,6})\s+(.+?)\s*$/);
      return match
        ? {
            index,
            level: match[1].length,
            title: stripInlineMarkdown(match[2]),
          }
        : null;
    })
    .filter(
      (
        heading,
      ): heading is { index: number; level: number; title: string } =>
        heading !== null,
    );

  const preferred =
    headings.find((heading) => /核心|更新/.test(heading.title)) ?? headings[0];
  const start = preferred ? preferred.index + 1 : 0;
  const title = preferred?.title || DEFAULT_TITLE;
  const highlights: string[] = [];

  for (let index = start; index < lines.length; index += 1) {
    const line = lines[index].trim();
    if (!line) continue;

    const nextHeading = line.match(/^\s*(#{1,6})\s+/);
    if (nextHeading && preferred && nextHeading[1].length <= preferred.level) {
      break;
    }
    if (nextHeading) continue;

    if (/^[-*+]\s+/.test(line) || /^\d+[.)、]\s+/.test(line)) {
      appendHighlight(highlights, line);
    } else if (preferred && !/^>/.test(line)) {
      appendHighlight(highlights, line);
    }
    if (highlights.length >= MAX_HIGHLIGHTS) break;
  }

  if (!preferred && highlights.length === 0) return null;
  return {
    title,
    highlights,
    fallback: highlights.length === 0 ? DEFAULT_FALLBACK : "",
  };
}

function parseCompactSummary(source: string): UpdateNotesPresentation | null {
  const normalized = source.replace(/\r?\n/g, " ").trim();
  const separator = normalized.match(/^([^：:\n]{2,24})[：:]\s*(.+)$/u);
  if (!separator) return null;

  const title = stripInlineMarkdown(separator[1]);
  const highlights: string[] = [];
  for (const part of separator[2].split(/[；;•]+/u)) {
    appendHighlight(highlights, part);
    if (highlights.length >= MAX_HIGHLIGHTS) break;
  }
  if (highlights.length === 0) return null;
  return { title, highlights, fallback: "" };
}

export function parseUpdateNotes(
  notes: string | null | undefined,
): UpdateNotesPresentation {
  const source = notes?.trim() ?? "";
  if (!source) {
    return {
      title: DEFAULT_TITLE,
      highlights: [],
      fallback: DEFAULT_FALLBACK,
    };
  }

  const markdown = parseMarkdownSection(source);
  if (markdown?.highlights.length) return markdown;

  const compact = parseCompactSummary(source);
  if (compact) return compact;

  const highlights: string[] = [];
  for (const paragraph of source.split(/\r?\n+/)) {
    appendHighlight(highlights, paragraph);
    if (highlights.length >= MAX_HIGHLIGHTS) break;
  }

  return {
    title: markdown?.title || DEFAULT_TITLE,
    highlights,
    fallback: highlights.length === 0 ? DEFAULT_FALLBACK : "",
  };
}

export function formatUpdateVersion(
  version: string | null | undefined,
): string {
  const normalized = version?.trim().replace(/^v/i, "") ?? "";
  return normalized ? `v${normalized}` : "—";
}
