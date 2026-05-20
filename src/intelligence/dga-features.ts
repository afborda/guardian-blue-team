/**
 * Feature extraction for DGA (Domain Generation Algorithm) classification.
 *
 * The features here MUST match `scripts/train_dga.py` byte-for-byte. If you
 * change a feature definition, retrain the model — the ONNX input layout is
 * positional, and a mismatch will silently produce nonsense scores.
 *
 * Features were chosen to discriminate between human-chosen domains
 * (memorable, pronouncable, English-bigram-frequent) and algorithmically-
 * generated ones (random-looking, entropy-high, bigram-rare).
 *
 * The bigram log-likelihood is the strongest single signal: legit domains
 * land in regions of bigram space dense with English digrams (`th`, `er`,
 * `in`); DGAs spread across rare digrams (`xq`, `kf`, `vw`).
 */
export interface DgaFeatures {
  // Index 0
  length: number;
  // Index 1: shannon entropy of character distribution
  entropy: number;
  // Index 2: ratio of vowels to total chars (excluding dots)
  vowelRatio: number;
  // Index 3: ratio of digits to total chars
  digitRatio: number;
  // Index 4: ratio of hyphens to total chars
  hyphenRatio: number;
  // Index 5: longest run of consecutive consonants
  maxConsonantRun: number;
  // Index 6: longest run of consecutive digits
  maxDigitRun: number;
  // Index 7: number of distinct character classes used (lowercase, digit, hyphen)
  charClasses: number;
  // Index 8: mean log-likelihood of bigrams under English bigram distribution
  bigramLL: number;
  // Index 9: number of dot-separated labels (subdomains + sld + tld)
  labelCount: number;
  // Index 10: length of the second-level domain (longest content label)
  sldLength: number;
}

export const FEATURE_ORDER: ReadonlyArray<keyof DgaFeatures> = [
  'length',
  'entropy',
  'vowelRatio',
  'digitRatio',
  'hyphenRatio',
  'maxConsonantRun',
  'maxDigitRun',
  'charClasses',
  'bigramLL',
  'labelCount',
  'sldLength',
];

const VOWELS = new Set(['a', 'e', 'i', 'o', 'u', 'y']);
const DIGITS = new Set(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']);

/**
 * Extract numeric features from a domain string. The input is normalized to
 * lowercase and stripped of trailing dots before extraction.
 */
export function extractFeatures(domainRaw: string, bigramTable: Float32Array): DgaFeatures {
  const domain = domainRaw.toLowerCase().replace(/\.+$/, '');
  const labels = domain.split('.');
  const sld = pickSld(labels);
  const stripped = domain.replace(/\./g, '');
  const len = stripped.length || 1;

  // Character class counts.
  let vowels = 0, digits = 0, hyphens = 0, lowers = 0;
  let maxConsRun = 0, curConsRun = 0;
  let maxDigRun = 0, curDigRun = 0;

  for (const ch of stripped) {
    const isDigit = DIGITS.has(ch);
    const isVowel = VOWELS.has(ch);
    const isLower = ch >= 'a' && ch <= 'z';
    const isHyphen = ch === '-';

    if (isVowel) vowels++;
    if (isDigit) { digits++; curDigRun++; if (curDigRun > maxDigRun) maxDigRun = curDigRun; }
    else { curDigRun = 0; }
    if (isHyphen) hyphens++;
    if (isLower) lowers++;

    // Consonant = lowercase letter that isn't a vowel.
    if (isLower && !isVowel) { curConsRun++; if (curConsRun > maxConsRun) maxConsRun = curConsRun; }
    else { curConsRun = 0; }
  }

  const charClasses = (lowers > 0 ? 1 : 0) + (digits > 0 ? 1 : 0) + (hyphens > 0 ? 1 : 0);

  return {
    length: stripped.length,
    entropy: shannonEntropy(stripped),
    vowelRatio: vowels / len,
    digitRatio: digits / len,
    hyphenRatio: hyphens / len,
    maxConsonantRun: maxConsRun,
    maxDigitRun: maxDigRun,
    charClasses,
    bigramLL: bigramLogLikelihood(sld, bigramTable),
    labelCount: labels.length,
    sldLength: sld.length,
  };
}

/**
 * Convert a feature object to a Float32Array in the canonical order. ONNX
 * inference expects a positional vector, so this function is the contract
 * between the extractor and the model.
 */
export function featuresToVector(f: DgaFeatures): Float32Array {
  const vec = new Float32Array(FEATURE_ORDER.length);
  for (let i = 0; i < FEATURE_ORDER.length; i++) {
    vec[i] = f[FEATURE_ORDER[i]];
  }
  return vec;
}

/**
 * The "second-level domain" — the label that most likely carries the
 * generated content. For `foo.bar.example.co.uk` this picks `example`. We
 * pick the longest non-trivial label rather than relying on a public-suffix
 * list, which would add a dependency for marginal accuracy gain.
 */
function pickSld(labels: string[]): string {
  if (labels.length === 0) return '';
  if (labels.length === 1) return labels[0];
  // Skip the last label (TLD) and pick the longest remaining.
  const candidates = labels.slice(0, -1);
  let longest = candidates[0];
  for (const l of candidates) if (l.length > longest.length) longest = l;
  return longest;
}

function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of freq.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Mean log-likelihood of bigrams in `s` under a precomputed English bigram
 * distribution. The table is a flat 27×27 array (a-z + '-') indexed by
 * `row * 27 + col`. Values are log-probabilities; OOV bigrams use the
 * smallest table value as a floor.
 *
 * Why mean and not sum: domains have wildly different lengths, and we want
 * the score to be comparable across them.
 */
const ALPHA_INDEX = (() => {
  const m = new Map<string, number>();
  for (let i = 0; i < 26; i++) m.set(String.fromCharCode(97 + i), i); // a..z
  m.set('-', 26);
  return m;
})();

function bigramLogLikelihood(s: string, table: Float32Array): number {
  if (s.length < 2 || table.length === 0) return 0;
  let sum = 0;
  let count = 0;
  let floor = table[0];
  for (let i = 1; i < table.length; i++) if (table[i] < floor) floor = table[i];

  for (let i = 0; i < s.length - 1; i++) {
    const a = ALPHA_INDEX.get(s[i]);
    const b = ALPHA_INDEX.get(s[i + 1]);
    if (a === undefined || b === undefined) {
      sum += floor;
    } else {
      sum += table[a * 27 + b];
    }
    count++;
  }
  return count > 0 ? sum / count : 0;
}
