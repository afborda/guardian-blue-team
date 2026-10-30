/**
 * Form that UFW prints. IPv4 is unchanged. IPv6 follows RFC 5952
 * (lowercase, no leading zeros, longest zero run compressed, first run on a tie).
 * The block table stores the fully expanded address from the logs, so a raw
 * grep of that string never matches `ufw status`.
 */
export function canonicalIp(ip: string): string {
  const trimmed = ip.trim();
  if (trimmed.includes('.')) return trimmed;
  return compressIpv6(trimmed);
}

function compressIpv6(ip: string): string {
  const halves = ip.split('::');
  if (halves.length > 2) return ip.toLowerCase();

  const expand = (part: string): string[] => (part ? part.split(':') : []);
  let groups: string[];
  if (halves.length === 1) {
    groups = expand(halves[0]);
    if (groups.length !== 8) return ip.toLowerCase();
  } else {
    const left = expand(halves[0]);
    const right = expand(halves[1]);
    const missing = 8 - left.length - right.length;
    if (missing < 0) return ip.toLowerCase();
    groups = [...left, ...Array(missing).fill('0'), ...right];
  }

  const stripped = groups.map(stripHextet);
  if (stripped.some((g) => g === null)) return ip.toLowerCase();
  const hextets = stripped as string[];

  let bestStart = -1;
  let bestLen = 0;
  let i = 0;
  while (i < 8) {
    if (hextets[i] !== '0') {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && hextets[j] === '0') j++;
    const len = j - i;
    if (len > bestLen) {
      bestStart = i;
      bestLen = len;
    }
    i = j;
  }

  if (bestLen < 2) return hextets.join(':');
  const left = hextets.slice(0, bestStart).join(':');
  const right = hextets.slice(bestStart + bestLen).join(':');
  return `${left}::${right}`;
}

function stripHextet(part: string): string | null {
  if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return null;
  const trimmed = part.toLowerCase().replace(/^0+/, '');
  return trimmed === '' ? '0' : trimmed;
}
