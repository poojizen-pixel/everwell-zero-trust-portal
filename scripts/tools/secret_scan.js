'use strict';
// Secret scanner for this project (scripts\check-secrets.ps1 runs it). Read-only against the scanned folder.
// It writes reports only to --out (which may be inside the scanned root only under <root>/build) and it never prints or
// stores a secret value: findings carry the length, a per-run keyed fingerprint and a redacted excerpt.
// usage: node secret_scan.js scan     --root <dir> --out <dir> [--pptx <extracted dir> --pptxrel <name>] [--gitignore <file>] [--fail-on possible]
//        node secret_scan.js selftest --root <empty controls dir> --out <dir>
// exit code of scan: 0 = no confirmed findings, 1 = confirmed findings (or possible ones with --fail-on possible), 2 = usage error.
// Waiver (deliberately narrow): a comment on the same line that holds secret-scan, a colon, the word allow and a reason
// waives ONLY an unnamed hex literal of a standard digest length (40, 64, 96 or 128 hex characters) in a file inside a
// folder named tests (public test vectors). It never waives a secret-named constant, a key header, a token format,
// a credential hash, a demo credential, a base64 literal, a hex literal of any other length, or anything outside tests.
// Every waived literal is still listed as ALLOWED in the report and counted in the summary line.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cp = require('child_process');

const argv = process.argv.slice(2);
const MODE = argv[0];
const OPT = {};
for (let i = 1; i + 1 < argv.length; i += 2) OPT[argv[i].replace(/^--/, '')] = argv[i + 1];
const ROOT = path.resolve(OPT.root || '.');
const OUT = path.resolve(OPT.out || '.');
const within = (child, parent) => (child + path.sep).toLowerCase().startsWith((parent + path.sep).toLowerCase());
if (within(OUT, ROOT) && !within(OUT, path.join(ROOT, 'build'))) {
  console.error('Refusing: the output folder is inside the scanned root (only <root>/build is allowed).');
  process.exit(2);
}
fs.mkdirSync(OUT, { recursive: true });

const MAX_LINE = 4000;
const VENDOR = new Set(['shared/include/json.hpp']);

const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
// Fingerprints are keyed with a random per-run key that is never stored, so a short fingerprint cannot be brute-forced
// offline (an unkeyed hash prefix of a 4-digit code can be). They only cross-reference findings within one run.
const FP_KEY = crypto.randomBytes(16);
const fpOf = (s) => crypto.createHmac('sha256', FP_KEY).update(Buffer.from(s, 'utf8')).digest('hex').slice(0, 6);
function entropy(s) {
  const m = new Map();
  for (const ch of s) m.set(ch, (m.get(ch) || 0) + 1);
  let h = 0;
  for (const c of m.values()) { const p = c / s.length; h -= p * Math.log2(p); }
  return h;
}

// ---------- name and value heuristics ----------
function identWords(id) {
  return id.replace(/([a-z0-9])([A-Z])/g, '$1_$2').split(/[^A-Za-z0-9]+/).filter(Boolean).map((w) => w.toLowerCase());
}
const STRONG = new Set(['secret', 'password', 'passwd', 'pwd', 'passphrase', 'pin', 'token', 'apikey', 'credential', 'credentials', 'hmac', 'privatekey']);
const KEYCOMP = new Set(['hmac', 'shared', 'signing', 'sign', 'secret', 'private', 'aes', 'api', 'encryption', 'crypto', 'master', 'agent', 'pep', 'telemetry', 'auth', 'session', 'cipher', 'symmetric', 'data', 'pdp', 'app', 'service', 'device']);
function nameInfo(id) {
  const w = identWords(id || '');
  const has = (x) => w.includes(x);
  let hit = w.some((x) => STRONG.has(x));
  if (!hit && has('key') && w.some((x) => KEYCOMP.has(x))) hit = true;
  if (!hit && has('pass')) hit = true;
  if (!hit && has('salt')) hit = true;
  let cat = 'secret';
  if (has('pin')) cat = 'pin';
  else if (has('password') || has('passwd') || has('pwd') || has('pass')) cat = (has('store') || has('keystore')) ? 'keystore-password' : 'password';
  else if (has('passphrase')) cat = 'encryption-passphrase';
  else if (has('hmac') || has('sign') || has('signing')) cat = 'hmac-signing-key';
  else if (has('aes') || has('cipher') || has('encryption') || has('crypto')) cat = 'encryption-key';
  else if (has('token')) cat = 'token';
  else if (has('api')) cat = 'api-key';
  else if (has('shared') || has('telemetry') || has('agent')) cat = 'shared-key';
  return { hit, cat };
}
const ALGO_RE = /^(?:hmac)?sha-?\d+(?:with\w+)?$|^aes(?:\/.*)?$|^rsa(?:\/.*)?$|^ec(?:dsa)?$|^pkcs\d+$|^jks$|^tls(?:v?[\d.]+)?$|^sunx509$|^x\.?509$|^ed25519$|^nopadding$|^gcm$|^utf-?8$|^bearer$|^basic$|^md5$/i;
const HEADER_RE = /^(?:authorization|content-type|content-length|set-cookie|cookie|accept|origin|host|x-[a-z0-9-]+)$/i;
const WEAK = new Set(['changeme', 'password', 'secret', 'admin', 'test', 'demo', 'default', 'letmein', '12345', '123456', 'qwerty']);
const PATH_RE = /^(?:[A-Za-z]:[\\/]|\.{1,2}[\\/]|\/)|[\\/].*\.\w{2,5}$|\.(?:jks|p12|pfx|pem|crt|cer|key|db|json|html|txt|log|exe|dll)$/i;

function judge(id, value, flags) {
  flags = flags || {};
  const len = value.length;
  if (len < 4) return null;
  const ni = nameInfo(id);
  const nameHit = ni.hit || !!flags.forceName;
  const cat = flags.forceName === 'password' ? 'password' : flags.forceName === 'key' ? 'encryption-key' : ni.cat;
  const H = entropy(value);
  const isHex = /^[0-9a-fA-F]+$/.test(value);
  const hexLong = isHex && len >= 32;
  const b64ish = /^[A-Za-z0-9+/_\-]{20,}={0,2}$/.test(value);
  if (nameHit && PATH_RE.test(value)) return { status: 'ENV_PATH', cat: 'environment-path', reason: 'file path' };
  if (flags.sqlHashContext && hexLong) return { status: 'CONFIRMED', cat: 'credential-hash', reason: 'hex hash in a users/credential INSERT' };
  if (!nameHit) {
    if (hexLong) return { status: 'POSSIBLE', cat: 'hex-literal', reason: 'long hex literal without a secret-like name' };
    if (len >= 24 && H >= 4.0 && b64ish) return { status: 'POSSIBLE', cat: 'high-entropy-literal', reason: 'high-entropy literal without a secret-like name' };
    return null;
  }
  if (ALGO_RE.test(value) || HEADER_RE.test(value)) return { status: 'DISMISSED', cat, reason: 'algorithm or header name', safe: true };
  if (!/pass(word|phrase)|secret|key/i.test(id || '') && /\s/.test(value) && value.trim().split(/\s+/).length > 3) return { status: 'DISMISSED', cat, reason: 'message text' };
  if (/^[a-z][a-z0-9_.\-]{0,30}$/.test(value) && !WEAK.has(value.toLowerCase()) && H < 3.4 && !/\d/.test(value)) return { status: 'DISMISSED', cat, reason: 'looks like a field or property name' };
  if (WEAK.has(value.toLowerCase())) return { status: 'CONFIRMED', cat, reason: 'well-known weak default value' };
  if (hexLong) return { status: 'CONFIRMED', cat, reason: 'hex key material in a secret-named constant' };
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(value)).length;
  if (len >= 12 && H >= 3.0) return { status: 'CONFIRMED', cat, reason: 'secret-named constant with high-entropy value' };
  if (len >= 8 && classes >= 2) return { status: 'CONFIRMED', cat, reason: 'secret-named constant with non-trivial value' };
  return { status: 'POSSIBLE', cat, reason: 'secret-named constant with a short or low-variety value (manual review)' };
}

const PATTERNS = [
  { id: 'pem-private-key', cat: 'private-key-pem', re: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/g, status: 'CONFIRMED', reason: 'PEM private key header', redact: false, needle: false },
  { id: 'pem-certificate', cat: 'public-certificate', re: new RegExp('-----BEGIN ' + 'CERTIFICATE-----', 'g'), status: 'INFO', reason: 'public certificate (not secret)', redact: false, needle: false },
  { id: 'aws-access-key', cat: 'cloud-api-key', re: /\bAKIA[0-9A-Z]{16}\b/g, status: 'CONFIRMED', reason: 'AWS access key id format', redact: true, needle: true },
  { id: 'github-token', cat: 'api-token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, status: 'CONFIRMED', reason: 'GitHub token format', redact: true, needle: true },
  { id: 'slack-token', cat: 'api-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, status: 'CONFIRMED', reason: 'Slack token format', redact: true, needle: true },
  { id: 'google-api-key', cat: 'api-key', re: /\bAIza[0-9A-Za-z_\-]{35}\b/g, status: 'CONFIRMED', reason: 'Google API key format', redact: true, needle: true },
  { id: 'jwt', cat: 'token-jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g, status: 'CONFIRMED', reason: 'JWT format', redact: true, needle: true },
  { id: 'bearer-literal', cat: 'token', re: /\bBearer\s+[A-Za-z0-9._~+\/-]{20,}=*/g, status: 'POSSIBLE', reason: 'long literal after "Bearer"', redact: true, needle: true },
  { id: 'url-credentials', cat: 'url-embedded-credentials', re: /\b[a-z][a-z0-9+.-]*:\/\/[^\/\s:@"']{1,64}:[^\/\s@"']{1,64}@/gi, status: 'CONFIRMED', reason: 'credentials inside a URL', redact: true, needle: false },
  { id: 'ssn-shape', cat: 'ssn-shaped-value', re: /\b\d{3}-\d{2}-\d{4}\b/g, status: 'INFO', reason: 'SSN-shaped value (should be clearly synthetic)', redact: true, needle: false },
  { id: 'email', cat: 'email-address', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, status: 'INFO', reason: 'email address (personal data, not a secret)', redact: true, needle: false },
];
const DEMO_STOP = new Set(['hash', 'hashed', 'hashes', 'policy', 'field', 'column', 'is', 'are', 'the', 'and', 'for', 'of', 'to', 'in', 'used', 'stored', 'store', 'shared', 'same', 'all', 'none', 'null', 'required', 'minimum', 'min', 'max', 'length', 'salted', 'unsalted', 'sha256', 'sha-256', 'plaintext', 'plain', 'text', 'not', 'no', 'never', 'must', 'should', 'will', 'can', 'with', 'without', 'via', 'or', 'a', 'an', 'as', 'by', 'on', 'at', 'user', 'users', 'account', 'accounts', 'demo', 'default', 'set', 'value', 'here', 'below', 'above', 'change', 'reset', 'prompt', 'step-up', 'stepup', 'verification', 'check', 'attempts', 'lockout', 'login']);
const RE_DEMO1 = /\b(password|passwd|pwd|passcode|pin)\b[^:=\n]{0,40}?[:=]\s*["'`\u201c]?([^\s"'`\u201d;,)<>]{3,40})/gi;
const RE_DEMO2 = /\b(password|passwd|pwd|passcode|pin)\s+["'`\u201c]([^"'`\u201d]{3,40})["'`\u201d]/gi;

function literalsInLine(line, qm) {
  const out = [];
  const re = qm === 'dq' ? /(?:u8|L)?"((?:[^"\\]|\\.)*)"/g : /(?:u8|L)?(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|`((?:[^`\\]|\\.)*)`)/g;
  let m;
  while ((m = re.exec(line)) !== null) {
    const value = m[1] !== undefined ? m[1] : (m[2] !== undefined ? m[2] : m[3]);
    out.push({ start: m.index, end: m.index + m[0].length, value: value === undefined ? '' : value });
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}
function identBefore(prefix) {
  let m;
  if ((m = /#\s*define\s+([A-Za-z_]\w*)\s+$/.exec(prefix))) return m[1];
  if ((m = /(?:getProperty|getOrDefault|getenv|orElse)\s*\(\s*["']([^"']*)["']\s*,\s*$/.exec(prefix))) return m[1];
  if ((m = /["']([\w.\-]+)["']\s*[:=]\s*$/.exec(prefix))) {
    // `cond ? 'a' : 'b'` is a ternary, not a "key": "value" pair
    if (!/\?\s*$/.test(prefix.slice(0, m.index))) return m[1];
  }
  if ((m = /([A-Za-z_][\w.\-]*)\s*(?:\[\s*\])?\s*(?:\+?=|:|\{)\s*(?:[A-Za-z_:][\w:<>]*\s*\(\s*)?$/.exec(prefix))) return m[1];
  return null;
}
function makeExcerpt(line, red) {
  const rs = red.slice().sort((a, b) => a.start - b.start);
  let out = '';
  let pos = 0;
  for (const r of rs) {
    if (r.start < pos) continue;
    out += line.slice(pos, r.start) + '\u00abREDACTED len=' + r.len + ' fp=' + r.fp + '\u00bb';
    pos = r.end;
  }
  out += line.slice(pos);
  // belt and braces: mask any other quoted literal that is not obviously benign
  out = out.replace(/(["'])([^"'\n]{8,})\1/g, (m, q, v) => (ALGO_RE.test(v) || HEADER_RE.test(v) || PATH_RE.test(v) ? m : q + '\u00abstr len=' + v.length + '\u00bb' + q));
  out = out.trim().replace(/\s+/g, ' ');
  return out.length > 220 ? out.slice(0, 217) + '...' : out;
}

// ---------- file handling ----------
// Never scanned: version-control metadata and build output (build output embeds the secrets of the sources).
const SKIP_TOP = new Set(['.git', 'build', 'node_modules']);
// Waiver limits: standard digest lengths in hex, and a folder named tests (the scan root itself counts) above the file.
const DIGEST_HEX_LENGTHS = new Set([40, 64, 96, 128]);
const inTestsDir = (rel, root) => [path.basename(root)].concat(rel.split('/').slice(0, -1)).some((s) => s.toLowerCase() === 'tests');
function walk(root) {
  const out = [];
  (function rec(dir) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (dir === root && SKIP_TOP.has(e.name)) continue;
        rec(full);
      } else if (e.isFile()) out.push(full);
    }
  })(root);
  return out.sort();
}
function readHead(file, n) {
  const fd = fs.openSync(file, 'r');
  try { const b = Buffer.alloc(n); const r = fs.readSync(fd, b, 0, n, 0); return b.subarray(0, r); } finally { fs.closeSync(fd); }
}
function classifyHead(head, rel) {
  const ext = path.extname(rel).toLowerCase();
  if (head.length >= 15 && head.subarray(0, 15).toString('latin1') === 'SQLite format 3') return 'sqlite-db';
  if (/\.db-wal$/i.test(rel)) return 'sqlite-wal';
  if (/\.db-shm$/i.test(rel)) return 'sqlite-shm';
  if (['.jks', '.p12', '.pfx', '.keystore'].includes(ext)) {
    if (head.length >= 4 && head.readUInt32BE(0) === 0xFEEDFEED) return 'keystore-jks';
    if (head.length >= 2 && head[0] === 0x30) return 'keystore-pkcs12';
    return 'keystore-unknown';
  }
  if (head.length >= 4) {
    const m = head.readUInt32BE(0);
    if (m === 0xFEEDFEED) return 'keystore-jks';
    if (m === 0xCECECECE) return 'keystore-jceks';
    if (m === 0xCAFEBABE) return 'java-class';
  }
  if (head.length >= 2 && head[0] === 0x4D && head[1] === 0x5A) return 'pe-binary';
  if (head.length >= 2 && head[0] === 0x50 && head[1] === 0x4B) return ext === '.pptx' ? 'pptx' : (ext === '.jar' ? 'jar' : 'zip');
  if (head.length >= 4 && head[0] === 0x89 && head[1] === 0x50 && head[2] === 0x4E) return 'png';
  if (ext === '.p12' || ext === '.pfx') return 'keystore-pkcs12';
  const utf16 = head.length >= 2 && head[0] === 0xFF && head[1] === 0xFE;
  if (!utf16 && head.includes(0)) return ['.cer', '.crt', '.der'].includes(ext) ? 'certificate-der' : 'binary';
  return 'text';
}
function decode(buf) {
  if (buf.length >= 2 && buf[0] === 0xFF && buf[1] === 0xFE) return buf.toString('utf16le');
  if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) return buf.toString('utf8', 3);
  return buf.toString('utf8');
}
function countOcc(buf, needle) {
  let c = 0;
  let i = 0;
  while ((i = buf.indexOf(needle, i)) !== -1) { c++; i += needle.length; }
  return c;
}
const DQ_ONLY = new Set(['.java', '.cpp', '.h', '.hpp', '.c', '.cc', '.cs']);

// ---------- the scan ----------
function runScan(root, opts) {
  opts = opts || {};
  const R = { findings: [], inventory: [], needles: [], stats: { text: 0, binary: 0, longSkipped: [] } };
  const docs = new Map();
  const seen = new Set();
  const needleMap = new Map();

  function addNeedle(value, cat, file, label, isPin) {
    if (needleMap.has(value)) return;
    const n = { value, len: value.length, fp: fpOf(value), cat, origin: { file, label }, isPin: !!isPin };
    needleMap.set(value, n);
    R.needles.push(n);
  }
  function push(f) {
    const key = [f.file, f.label, f.category, f.fp || ''].join('|');
    if (seen.has(key)) return null;
    seen.add(key);
    R.findings.push(f);
    return f;
  }

  function scanLines(rel, lines, ext, labelOf, vendored, waiverOk) {
    const qm = DQ_ONLY.has(ext) ? 'dq' : 'all';
    const isSql = ext === '.sql';
    let sqlTable = null;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const label = labelOf(i);
      if (line.length > MAX_LINE) { R.stats.longSkipped.push(rel + ':' + label); continue; }
      if (isSql) {
        const mi = /insert\s+(?:or\s+\w+\s+)?into\s+["`\[]?(\w+)/i.exec(line);
        if (mi) sqlTable = mi[1].toLowerCase();
      }
      const pending = [];
      const red = [];
      const redact = (start, end, value) => red.push({ start, end, len: value.length, fp: fpOf(value) });
      const add = (f) => { f.file = rel; f.label = label; f.line = typeof label === 'number' ? label : null; pending.push(f); };

      for (const p of PATTERNS) {
        if (vendored && p.id === 'email') continue;
        p.re.lastIndex = 0;
        let m;
        while ((m = p.re.exec(line)) !== null) {
          const val = m[0];
          if (p.redact) redact(m.index, m.index + val.length, val);
          if (p.needle) addNeedle(val, p.cat, rel, label, false);
          add({ kind: 'pattern', pattern: p.id, category: p.cat, status: p.status, len: val.length, fp: fpOf(val), reason: p.reason });
          if (m.index === p.re.lastIndex) p.re.lastIndex++;
        }
      }

      for (const lit of literalsInLine(line, qm)) {
        const value = lit.value;
        if (value.length < 4) continue;
        const prefix = line.slice(0, lit.start);
        const suffix = line.slice(lit.end);
        const flags = {};
        if (/^\s*\.toCharArray\s*\(/.test(suffix)) flags.forceName = 'password';
        if (/SecretKeySpec\s*\(\s*$/.test(prefix)) flags.forceName = 'key';
        if (isSql && (['users', 'credentials', 'accounts'].includes(sqlTable) || /password|pin_hash|hash/i.test(line))) flags.sqlHashContext = true;
        const id = identBefore(prefix);
        const j = judge(id, value, flags);
        if (!j) continue;
        if (j.status === 'ENV_PATH') { add({ kind: 'literal', name: id, category: 'environment-path', status: 'INFO', reason: j.reason }); continue; }
        if (j.safe !== true) redact(lit.start, lit.end, value);
        if ((j.status === 'CONFIRMED' || j.status === 'POSSIBLE') && j.cat !== 'credential-hash' && j.cat !== 'hex-literal') addNeedle(value, j.cat, rel, label, false);
        const f = { kind: 'literal', name: id || null, category: j.cat, status: j.status, len: value.length, fp: fpOf(value), reason: j.reason };
        Object.defineProperty(f, '_value', { value, enumerable: false });
        add(f);
      }

      if (!vendored) {
        const docLine = ext === '.pptx' || ext === '.md' || ext === '.txt' || /^\s*(?:--|\/\/|#|\*|\/\*|<!--)/.test(line);
        for (const re of docLine ? [RE_DEMO1, RE_DEMO2] : []) {
          re.lastIndex = 0;
          let m;
          while ((m = re.exec(line)) !== null) {
            const word = m[1].toLowerCase();
            const val = m[2];
            const lv = val.toLowerCase().replace(/[.,]+$/, '');
            if (!DEMO_STOP.has(lv)) {
              const isPin = word === 'pin';
              const ok = !/[(){}\[\]=<>;]/.test(val) && (isPin ? /^\d{3,8}$/.test(val) : (/\d|[^A-Za-z]/.test(val) || WEAK.has(lv)));
              if (ok) {
                const vstart = m.index + m[0].lastIndexOf(val);
                redact(vstart, vstart + val.length, val);
                const cat = isPin ? 'demo-pin-plaintext' : 'demo-password-plaintext';
                addNeedle(val, cat, rel, label, isPin);
                const f = { kind: 'text', category: cat, status: 'CONFIRMED', len: val.length, fp: fpOf(val), reason: 'credential value written in a comment or document' };
                Object.defineProperty(f, '_value', { value: val, enumerable: false });
                add(f);
              }
            }
            if (m.index === re.lastIndex) re.lastIndex++;
          }
        }
        if (/(?<![A-Za-z0-9])[A-Za-z]:[\\/](?![\\/])[^\s"'<>|]*/.test(line)) add({ kind: 'text', category: 'environment-path', status: 'INFO', reason: 'absolute path tied to this machine' });
        const dev = /\bDEV-[A-Z0-9_-]{3,}\b/.exec(line);
        if (dev) { redact(dev.index, dev.index + dev[0].length, dev[0]); add({ kind: 'text', category: 'machine-name-identifier', status: 'INFO', len: dev[0].length, fp: fpOf(dev[0]), reason: 'hostname-derived device id' }); }
      }

      if (pending.length) {
        const excerpt = makeExcerpt(line, red);
        // Narrow waiver (see the header): comment token + marker + a reason, inside a tests folder, hex digest length only.
        const waived = waiverOk && /(?:\/\/|#|--|\/\*)\s*secret-scan:\s*allow\s+\S/.test(line);
        for (const f of pending) {
          f.excerpt = excerpt;
          if (waived && f.category === 'hex-literal' && f.status === 'POSSIBLE' && DIGEST_HEX_LENGTHS.has(f.len)) {
            f.status = 'ALLOWED';
            f.reason += ' (waived by an inline allow marker with a reason, inside a tests folder)';
          }
          push(f);
        }
      }
      if (isSql && /;\s*$/.test(line.trim())) sqlTable = null;
    }
  }

  for (const full of walk(root)) {
    const rel = path.relative(root, full).split(path.sep).join('/');
    const size = fs.statSync(full).size;
    const head = readHead(full, Math.min(size, 16384));
    let type = classifyHead(head, rel);
    if (type === 'java-class' && size > 5 * 1024 * 1024) type = 'binary';
    const ext = path.extname(rel).toLowerCase();
    R.inventory.push({ file: rel, size, type });
    if (type === 'text') {
      R.stats.text++;
      const text = decode(fs.readFileSync(full));
      const lines = text.split(/\r?\n/);
      docs.set(rel, { type, lines, labelOf: (i) => i + 1 });
      scanLines(rel, lines, ext, (i) => i + 1, VENDOR.has(rel), inTestsDir(rel, root));
    } else {
      R.stats.binary++;
      if (['java-class', 'pe-binary', 'sqlite-db', 'sqlite-wal', 'sqlite-shm', 'keystore-jks', 'keystore-jceks', 'keystore-pkcs12', 'certificate-der'].includes(type) && size <= 64 * 1024 * 1024) {
        docs.set(rel, { type, buf: fs.readFileSync(full) });
      }
    }
  }

  // PowerPoint (extracted copy supplied by the caller): paragraph-level text of each slide and note
  if (opts.pptxDir && fs.existsSync(opts.pptxDir)) {
    const pptxRel = opts.pptxRel || 'deck.pptx';
    const dec = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
    const parts = [];
    for (const sub of ['ppt/slides', 'ppt/notesSlides']) {
      const d = path.join(opts.pptxDir, sub);
      if (!fs.existsSync(d)) continue;
      for (const f of fs.readdirSync(d).filter((x) => x.endsWith('.xml')).sort()) parts.push({ sub, f });
    }
    for (const p of parts) {
      const xml = fs.readFileSync(path.join(opts.pptxDir, p.sub, p.f), 'utf8');
      const paras = [];
      const pre = /<a:p>([\s\S]*?)<\/a:p>|<a:p [^>]*>([\s\S]*?)<\/a:p>/g;
      let pm;
      while ((pm = pre.exec(xml)) !== null) {
        const inner = pm[1] !== undefined ? pm[1] : pm[2];
        let t = '';
        const tr = /<a:t[^>]*>([^<]*)<\/a:t>/g;
        let tm;
        while ((tm = tr.exec(inner)) !== null) t += dec(tm[1]);
        if (t.trim()) paras.push(t);
      }
      const num = (p.f.match(/(\d+)/) || [0, '?'])[1];
      const kind = p.sub === 'ppt/slides' ? 'slide' : 'notes of slide';
      const rel = pptxRel + '!/' + p.sub + '/' + p.f;
      const labelOf = (i) => kind + ' ' + num + ', paragraph ' + (i + 1);
      docs.set(rel, { type: 'pptx-text', lines: paras, labelOf, pptx: true });
      scanLines(rel, paras, '.pptx', labelOf, false);
    }
    for (const meta of ['docProps/core.xml', 'docProps/app.xml']) {
      const mp = path.join(opts.pptxDir, meta);
      if (!fs.existsSync(mp)) continue;
      const xml = fs.readFileSync(mp, 'utf8');
      for (const tag of ['dc:creator', 'cp:lastModifiedBy', 'Company', 'Manager']) {
        const m = new RegExp('<' + tag + '>([^<]+)</' + tag + '>').exec(xml);
        if (m && m[1].trim()) {
          push({ file: pptxRel + '!/' + meta, label: tag, line: null, kind: 'metadata', category: 'document-metadata-person', status: 'INFO', len: m[1].length, fp: fpOf(m[1]), reason: 'author/company name stored in document properties', excerpt: '<' + tag + '> \u00abREDACTED len=' + m[1].length + ' fp=' + fpOf(m[1]) + '\u00bb' });
        }
      }
    }
  }

  // needle propagation: where else do the same values appear?
  for (const n of R.needles) {
    if (!n.isPin && n.len < 6) continue;
    for (const [rel, d] of docs) {
      if (d.lines) {
        for (let i = 0; i < d.lines.length; i++) {
          const ln = d.lines[i];
          if (ln.length > MAX_LINE) continue;
          if (!ln.includes(n.value)) continue;
          if (n.isPin && !/\bpin\b/i.test(ln)) continue;
          const label = d.labelOf(i);
          if (rel === n.origin.file && label === n.origin.label) continue;
          const at = ln.indexOf(n.value);
          const ex = makeExcerpt(ln, [{ start: at, end: at + n.value.length, len: n.len, fp: n.fp }]);
          push({ file: rel, label, line: typeof label === 'number' ? label : null, kind: 'propagated', category: n.cat, status: 'CONFIRMED', len: n.len, fp: n.fp, reason: 'same value as ' + n.origin.file + ':' + n.origin.label, excerpt: ex });
        }
      } else if (d.buf && !n.isPin && n.len >= 8) {
        const c1 = countOcc(d.buf, Buffer.from(n.value, 'utf8'));
        const c2 = d.type === 'pe-binary' ? countOcc(d.buf, Buffer.from(n.value, 'utf16le')) : 0;
        if (c1 + c2 > 0) {
          const dbish = d.type.startsWith('sqlite');
          push({ file: rel, label: 'binary x' + (c1 + c2), line: null, kind: 'binary-embedded', category: dbish ? 'plaintext-secret-in-database-file' : 'compiled-artifact-embeds-secret', status: 'CONFIRMED', len: n.len, fp: n.fp, reason: 'value fp=' + n.fp + ' (' + n.cat + ') found ' + (c1 + c2) + ' time(s) in a ' + d.type + ' file', excerpt: '(binary file; no excerpt)' });
        }
      }
    }
  }

  // credential hashes that are SHA-256 of a learned plaintext value
  for (const f of R.findings) {
    if (f.category !== 'credential-hash' || !f._value) continue;
    const h = f._value.toLowerCase();
    for (const n of R.needles) {
      if (sha256(Buffer.from(n.value, 'utf8')) === h) { f.linkedTo = 'SHA-256 of the ' + n.cat + ' value fp=' + n.fp; break; }
    }
  }

  // file-level findings
  for (const inv of R.inventory) {
    const t = inv.type;
    const base = { file: inv.file, label: 'file', line: null, kind: 'file', len: inv.size };
    if (t === 'keystore-jks' || t === 'keystore-jceks' || t === 'keystore-pkcs12' || t === 'keystore-unknown') push(Object.assign({}, base, { category: 'private-keystore-file', status: 'CONFIRMED', reason: 'password-protected container for private key material (' + t + ')', excerpt: '(binary file)' }));
    else if (t === 'sqlite-db') push(Object.assign({}, base, { category: 'database-file', status: 'CONFIRMED', reason: 'holds credential hashes, encrypted identifiers and audit data', excerpt: '(binary file)' }));
    else if (t === 'sqlite-wal' || t === 'sqlite-shm') push(Object.assign({}, base, { category: 'database-file', status: 'CONFIRMED', reason: 'database journal: holds recent committed data not yet in the .db', excerpt: '(binary file)' }));
    else if (t === 'certificate-der') push(Object.assign({}, base, { category: 'public-certificate', status: 'INFO', reason: 'DER certificate (public, not secret)', excerpt: '(binary file)' }));
    else if (t === 'jar') push(Object.assign({}, base, { category: 'third-party-binary', status: 'INFO', reason: 'third-party jar; not scanned for secrets', excerpt: '(binary file)' }));
  }

  // order and number
  R.findings.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : (typeof a.label === 'number' ? a.label : 1e9) - (typeof b.label === 'number' ? b.label : 1e9) || String(a.label).localeCompare(String(b.label))));
  R.findings.forEach((f, i) => { f.id = 'F' + String(i + 1).padStart(3, '0'); });
  return R;
}

// ---------- risk and remediation ----------
const RISK = {
  'hmac-signing-key': ['HIGH', 'EXT'], 'shared-key': ['HIGH', 'EXT'], 'encryption-key': ['HIGH', 'EXT'], 'encryption-passphrase': ['HIGH', 'EXT'],
  'keystore-password': ['HIGH', 'EXT'], 'password': ['HIGH', 'EXT'], 'pin': ['HIGH', 'EXT'], 'token': ['HIGH', 'EXT'], 'api-key': ['HIGH', 'EXT'],
  'cloud-api-key': ['HIGH', 'EXT'], 'api-token': ['HIGH', 'EXT'], 'token-jwt': ['HIGH', 'EXT'], 'secret': ['HIGH', 'EXT'],
  'demo-password-plaintext': ['HIGH', 'SAN'], 'demo-pin-plaintext': ['HIGH', 'SAN'], 'credential-hash': ['MEDIUM', 'HASH'],
  'private-keystore-file': ['HIGH', 'IGN+REGEN'], 'private-key-pem': ['HIGH', 'IGN+REGEN'], 'database-file': ['MEDIUM', 'IGN'],
  'compiled-artifact-embeds-secret': ['MEDIUM', 'IGN+EXT'], 'plaintext-secret-in-database-file': ['HIGH', 'IGN+SAN'], 'url-embedded-credentials': ['HIGH', 'EXT'],
  'ssn-shaped-value': ['LOW', 'REVIEW'], 'environment-path': ['LOW', 'PATH'], 'machine-name-identifier': ['LOW', 'SAN'], 'email-address': ['LOW', 'SAN'], 'document-metadata-person': ['LOW', 'DOC'],
  'hex-literal': ['MEDIUM', 'REVIEW'], 'high-entropy-literal': ['MEDIUM', 'REVIEW'], 'public-certificate': ['NONE', '-'], 'third-party-binary': ['NONE', '-'],
};
function riskFix(f) {
  const r = RISK[f.category] || ['MEDIUM', 'REVIEW'];
  let risk = r[0];
  if (f.status === 'POSSIBLE' && risk === 'HIGH') risk = 'MEDIUM';
  if (f.status === 'DISMISSED' || f.status === 'ALLOWED') risk = 'NONE';
  return { risk, fix: (f.status === 'DISMISSED' || f.status === 'ALLOWED') ? '-' : r[1] };
}

// ---------- minimal .gitignore simulation (the proposal only uses simple patterns) ----------
function globToRe(p) {
  let re = '';
  for (let i = 0; i < p.length; i++) {
    const ch = p[i];
    if (ch === '*') { if (p[i + 1] === '*') { re += '.*'; i++; } else re += '[^/]*'; }
    else if (ch === '?') re += '[^/]';
    else re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp('^' + re + '$');
}
function parseIgnore(text) {
  const rules = [];
  for (let raw of text.split(/\r?\n/)) {
    raw = raw.replace(/\s+$/, '');
    if (!raw || raw.startsWith('#')) continue;
    let p = raw;
    const dirOnly = p.endsWith('/');
    if (dirOnly) p = p.slice(0, -1);
    const anchored = p.startsWith('/') || p.includes('/');
    if (p.startsWith('/')) p = p.slice(1);
    rules.push({ raw, dirOnly, anchored, re: globToRe(p) });
  }
  return rules;
}
function ignoredBy(rel, rules) {
  const segs = rel.split('/');
  for (const r of rules) {
    for (let i = 0; i < segs.length - 1; i++) {
      const sub = segs.slice(0, i + 1).join('/');
      if (r.anchored ? r.re.test(sub) : r.re.test(segs[i])) return r.raw;
    }
    if (!r.dirOnly && (r.anchored ? r.re.test(rel) : r.re.test(segs[segs.length - 1]))) return r.raw;
  }
  return null;
}

// ---------- output ----------
function renderText(R, title) {
  const L = [];
  L.push(title);
  const order = { CONFIRMED: 0, POSSIBLE: 1, INFO: 2, DISMISSED: 3 };
  for (const st of ['CONFIRMED', 'POSSIBLE', 'ALLOWED', 'INFO', 'DISMISSED']) {
    const fs_ = R.findings.filter((f) => f.status === st);
    L.push('');
    L.push('=== ' + st + ' (' + fs_.length + ') ===');
    for (const f of fs_) {
      const rf = riskFix(f);
      L.push(f.id + '  ' + f.file + (f.line ? ':' + f.line : ' [' + f.label + ']') + '  ' + f.category + '  risk=' + rf.risk + '  fix=' + rf.fix);
      L.push('      ' + [f.name ? 'name=' + f.name : null, f.len !== undefined && f.kind !== 'file' ? 'len=' + f.len : null, f.fp ? 'fp=' + f.fp : null, 'why: ' + f.reason].filter(Boolean).join('  '));
      if (f.linkedTo) L.push('      linked: ' + f.linkedTo);
      if (f.unlock) L.push('      unlock-test: ' + f.unlock);
      if (f.excerpt && f.excerpt !== '(binary file)') L.push('      > ' + f.excerpt);
    }
  }
  return L.join('\n') + '\n';
}

function probeKeystores(R, classesDir) {
  const ks = R.inventory.filter((i) => i.type.startsWith('keystore'));
  if (!ks.length || !classesDir) return;
  const cands = [];
  for (const f of R.findings) {
    if (!f._value) continue;
    if (['keystore-password', 'password', 'encryption-passphrase', 'secret', 'shared-key', 'encryption-key', 'hmac-signing-key', 'pin', 'token'].includes(f.category) && (f.status === 'CONFIRMED' || f.status === 'POSSIBLE')) {
      cands.push(f.file + ':' + f.line + ':' + (f.name || f.category) + '\t' + f._value);
    }
  }
  const args = ['--enable-native-access=ALL-UNNAMED', '-cp', classesDir, 'Cp1KeystoreProbe'].concat(ks.map((k) => path.join(ROOT, k.file)));
  const r = cp.spawnSync('java', args, { input: cands.join('\n') + '\n', encoding: 'utf8', maxBuffer: 1 << 24 });
  const lines = (r.stdout || '').split(/\r?\n/).filter(Boolean);
  for (const ln of lines) {
    const parts = ln.split('\t');
    const rel = path.relative(ROOT, parts[1]).split(path.sep).join('/');
    const f = R.findings.find((x) => x.file === rel && x.category === 'private-keystore-file');
    if (!f) continue;
    f.unlock = parts[0] === 'OPENS'
      ? 'OPENS with constant ' + parts[2] + ' (' + parts[3] + ', ' + parts[4] + ') ' + (parts[5] || '')
      : 'did not open with any discovered constant';
  }
  if (r.status !== 0) R.stats.probeError = (r.stderr || '').slice(0, 300);
}

// ---------- modes ----------
if (MODE === 'selftest') {
  // Fixture values are assembled at run time so that this source file holds no literal that looks like a secret
  // (the project scan scans this file too).
  const Q = String.fromCharCode(34);
  const q = (v) => Q + v + Q;
  const planted = {
    hmac: ['planted', 'fake', 'secret', 'Zk3x9QpL7vTn2'].join('-'),
    ksPass: ['Pl@nted', 'Store', '9Xq'].join('-'),
    demoPw: ['Planted', 'Demo', 'Pass', '1'].join('-'),
    demoPin: String(4000 + 821),
    aws: 'AKIA' + 'Z'.repeat(16),
  };
  const winPath = ['C:', 'Ap project', 'certs', 'x.jks'].join('/');
  fs.mkdirSync(ROOT, { recursive: true });
  fs.writeFileSync(path.join(ROOT, 'Planted.java'), [
    'public class Planted {',
    '    private static final String HMAC_SECRET = ' + q(planted.hmac) + ';',
    '    static final String AWS_KEY = ' + q(planted.aws) + ';',
    '    static final String HMAC_ALGORITHM = ' + q('HmacSHA256') + ';',
    '    static final String KEYSTORE_PASSWORD = ' + q(planted.ksPass) + ';',
    '    static final String KEYSTORE_PATH = ' + q(winPath) + ';',
    '    // ' + '-----BEGIN ' + 'PRIVATE KEY' + '-----',
    '}',
  ].join('\n'));
  fs.writeFileSync(path.join(ROOT, 'planted.sql'), [
    '-- Demo credentials: password = ' + planted.demoPw + ' and PIN = ' + planted.demoPin,
    "INSERT INTO users(username, password_hash, step_up_pin_hash) VALUES ('u1', '" + sha256(Buffer.from(planted.demoPw)) + "', '" + sha256(Buffer.from(planted.demoPin)) + "');",
  ].join('\n'));
  fs.writeFileSync(path.join(ROOT, 'planted_copy.txt'), 'notes: ' + planted.hmac + ' appears here too\n');
  fs.writeFileSync(path.join(ROOT, 'Clean.java'), [
    'public class Clean {',
    '    static final String HMAC_ALGORITHM = ' + q('HmacSHA256') + ';',
    '    static final String HEADER_AUTH = ' + q('Authorization') + ';',
    '    static final String TOKEN_FIELD = ' + q('token') + ';',
    '    static final int PORT = 5000;',
    '    // password policy: minimum 12 characters',
    '    String message = ' + q('Invalid password, try again') + ';',
    '}',
  ].join('\n'));
  // Waiver abuse fixtures. A valid marker is: a comment token, the marker words and a reason.
  const hex64 = 'ab'.repeat(32);
  planted.hex64 = hex64;
  planted.hmac2 = ['another', 'fake', 'secret', 'Qw8e7Rt6Yu'].join('-');
  planted.jwt = ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiJ0ZXN0In0', 'abcDEF123xyz'].join('.');
  planted.bearer = 'Bearer ' + 'Qw8e7Rt6Yu'.repeat(3);
  planted.b64 = ['Zm9vYmFy', 'QmF6UXV4', 'MTIzNDU2', 'Nzg5MEFC'].join('');
  const MARK = ' // secret-scan: allow public vector';
  const lineOf = {};
  const fixture = (file, entries) => {
    const out = [];
    entries.forEach((e) => { out.push(e[1]); lineOf[file + ':' + e[0]] = out.length; });
    fs.mkdirSync(path.dirname(path.join(ROOT, file)), { recursive: true });
    fs.writeFileSync(path.join(ROOT, file), out.join('\n'));
  };
  fixture('tests/Allow.java', [
    ['head', 'public class Allow {'],
    ['vector', '    static final String VECTOR = ' + q(hex64) + ';' + MARK],
    ['named', '    static final String HMAC_SECRET2 = ' + q(planted.hmac2) + ';' + MARK],
    ['tail', '}'],
  ]);
  fixture('tests/Narrow.java', [
    ['head', 'public class Narrow {'],
    ['aws', '    String a = ' + q(planted.aws) + ';' + MARK],
    ['pem', '    // ' + '-----BEGIN ' + 'PRIVATE KEY' + '-----' + MARK],
    ['jwt', '    String c = ' + q(planted.jwt) + ';' + MARK],
    ['demo', '    // ' + 'pass' + 'word = ' + planted.demoPw + MARK],
    ['bearer', '    String d = verifier.check(' + q(planted.bearer) + ');' + MARK],
    ['len48', '    String e = verifier.check(' + q('ab'.repeat(24)) + ');' + MARK],
    ['b64', '    String f = verifier.check(' + q(planted.b64) + ');' + MARK],
    ['nomarker', '    String g = verifier.check(' + q(hex64) + ');'],
    ['noreason', '    String h = verifier.check(' + q(hex64) + '); // secret-scan: allow'],
    ['noreasonspaces', '    String h2 = verifier.check(' + q(hex64) + '); // secret-scan: allow   '],
    ['blockcomment', '    String i = verifier.check(' + q(hex64) + '); /* secret-scan: allow public vector */'],
    ['tail', '}'],
  ]);
  fixture('tests/narrow.sql', [
    ['insert', "INSERT INTO users(user_id, username, password_hash, step_up_pin_hash, role) VALUES ('u1', 'n1', '" + sha256(Buffer.from(planted.demoPw)) + "', '" + sha256(Buffer.from(planted.demoPin)) + "', 'doctor'); -- secret-scan: allow public vector"],
  ]);
  fixture('Outside.java', [
    ['head', 'public class Outside {'],
    ['vector', '    String k = verifier.check(' + q(hex64) + ');' + MARK],
    ['tail', '}'],
  ]);
  fs.mkdirSync(path.join(ROOT, 'build'), { recursive: true });
  fs.writeFileSync(path.join(ROOT, 'build', 'Skipped.java'), '    static final String HMAC_SECRET3 = ' + q(planted.hmac) + ';\n');
  const R = runScan(ROOT, {});
  const txt = renderText(R, 'SELFTEST FINDINGS (redacted)');
  const json = JSON.stringify(R.findings, null, 1);
  const by = (file) => R.findings.filter((f) => f.file === file);
  const checks = [];
  const chk = (name, ok) => checks.push({ name, ok: !!ok });
  chk('C1 planted HMAC constant -> CONFIRMED hmac-signing-key', by('Planted.java').some((f) => f.name === 'HMAC_SECRET' && f.status === 'CONFIRMED' && f.category === 'hmac-signing-key'));
  chk('C2 planted AWS key format -> CONFIRMED', by('Planted.java').some((f) => f.pattern === 'aws-access-key' && f.status === 'CONFIRMED'));
  chk('C3 planted keystore password -> CONFIRMED keystore-password', by('Planted.java').some((f) => f.name === 'KEYSTORE_PASSWORD' && f.status === 'CONFIRMED' && f.category === 'keystore-password'));
  chk('C4 planted PEM private key header -> CONFIRMED', by('Planted.java').some((f) => f.pattern === 'pem-private-key' && f.status === 'CONFIRMED'));
  chk('C5 demo password and PIN in an SQL comment -> both CONFIRMED', by('planted.sql').some((f) => f.category === 'demo-password-plaintext') && by('planted.sql').some((f) => f.category === 'demo-pin-plaintext'));
  chk('C6 both hashes in the INSERT are linked to the learned values', by('planted.sql').filter((f) => f.category === 'credential-hash' && f.linkedTo).length === 2);
  chk('C7 same secret in another file -> propagated finding', by('planted_copy.txt').some((f) => f.kind === 'propagated' && f.status === 'CONFIRMED'));
  chk('C8 environment path is reported as INFO, not as a secret', by('Planted.java').some((f) => f.category === 'environment-path' && f.status === 'INFO'));
  const at = (file, key) => R.findings.filter((f) => f.file === file && f.line === lineOf[file + ':' + key]);
  const N = 'tests/Narrow.java';
  chk('C9 a public hex digest with a valid marker inside a tests folder is ALLOWED', at('tests/Allow.java', 'vector').some((f) => f.category === 'hex-literal' && f.status === 'ALLOWED'));
  chk('C10 the marker does not waive a secret-named constant', at('tests/Allow.java', 'named').some((f) => f.name === 'HMAC_SECRET2' && f.status === 'CONFIRMED'));
  chk('M1 marker next to an AWS key format: still CONFIRMED', at(N, 'aws').some((f) => f.pattern === 'aws-access-key' && f.status === 'CONFIRMED'));
  chk('M2 marker next to a PEM private key header: still CONFIRMED', at(N, 'pem').some((f) => f.pattern === 'pem-private-key' && f.status === 'CONFIRMED'));
  chk('M3 marker next to a JWT: still CONFIRMED', at(N, 'jwt').some((f) => f.pattern === 'jwt' && f.status === 'CONFIRMED'));
  chk('M4 marker next to a demo credential in a comment: still CONFIRMED', at(N, 'demo').some((f) => f.category === 'demo-password-plaintext' && f.status === 'CONFIRMED'));
  chk('M5 marker next to credential hashes in a users INSERT: both still CONFIRMED', at('tests/narrow.sql', 'insert').filter((f) => f.category === 'credential-hash' && f.status === 'CONFIRMED').length === 2);
  chk('M6 marker next to a Bearer literal: not waived (stays POSSIBLE)', at(N, 'bearer').some((f) => f.pattern === 'bearer-literal' && f.status === 'POSSIBLE'));
  chk('M7 marker next to a hex literal of a non-digest length (48): not waived', at(N, 'len48').some((f) => f.category === 'hex-literal' && f.status === 'POSSIBLE'));
  chk('M8 marker next to a base64 literal: not waived', at(N, 'b64').some((f) => f.category === 'high-entropy-literal' && f.status === 'POSSIBLE'));
  chk('M9 a digest-length hex literal WITHOUT a marker stays POSSIBLE', at(N, 'nomarker').some((f) => f.category === 'hex-literal' && f.status === 'POSSIBLE'));
  chk('M10 a marker without a reason is not waived (also with trailing spaces)', at(N, 'noreason').some((f) => f.status === 'POSSIBLE') && at(N, 'noreasonspaces').some((f) => f.status === 'POSSIBLE'));
  chk('M11 a valid marker in a block comment is ALLOWED', at(N, 'blockcomment').some((f) => f.category === 'hex-literal' && f.status === 'ALLOWED'));
  chk('M12 a valid marker OUTSIDE a tests folder is not waived', at('Outside.java', 'vector').some((f) => f.category === 'hex-literal' && f.status === 'POSSIBLE'));
  chk('C11 the build folder is not scanned', !R.inventory.some((i) => i.file.startsWith('build/')) && !R.findings.some((f) => f.file.startsWith('build/')));
  chk('N1 clean file -> zero CONFIRMED/POSSIBLE findings', by('Clean.java').filter((f) => f.status === 'CONFIRMED' || f.status === 'POSSIBLE').length === 0);
  chk('N2 algorithm/header/field-name constants are dismissed, not reported as secrets', by('Clean.java').every((f) => f.status === 'DISMISSED' || f.status === 'INFO'));
  const blob = txt + json;
  chk('N3 redaction: none of the planted values appears in any output', !Object.values(planted).some((v) => blob.includes(v)));
  const lines = ['SCANNER CONTROLS (self-test on planted fake secrets and a clean file; scratch folder, not the project)'];
  for (const c of checks) lines.push((c.ok ? 'PASS  ' : 'FAIL  ') + c.name);
  const allOk = checks.every((c) => c.ok);
  lines.push('');
  lines.push('OVERALL: ' + (allOk ? 'PASS' : 'FAIL') + ' (' + checks.filter((c) => c.ok).length + '/' + checks.length + ')');
  fs.writeFileSync(path.join(OUT, 'scanner_controls.txt'), lines.join('\n') + '\n');
  fs.writeFileSync(path.join(OUT, 'scanner_controls_findings_redacted.txt'), txt);
  console.log(lines.join('\n'));
  process.exit(allOk ? 0 : 1);
} else if (MODE === 'scan') {
  const R = runScan(ROOT, { pptxDir: OPT.pptx, pptxRel: OPT.pptxrel });
  probeKeystores(R, OPT['probe-classes']);

  // git simulation
  let sim = null;
  if (OPT.gitignore && fs.existsSync(OPT.gitignore)) {
    const rules = parseIgnore(fs.readFileSync(OPT.gitignore, 'utf8'));
    const FORBID = new Set(['keystore-jks', 'keystore-jceks', 'keystore-pkcs12', 'sqlite-db', 'sqlite-wal', 'sqlite-shm', 'java-class', 'pe-binary', 'jar', 'pptx', 'certificate-der']);
    sim = { tracked: [], ignored: [], trackedForbidden: [], trackedWithSecrets: [] };
    for (const inv of R.inventory) {
      const by = ignoredBy(inv.file, rules);
      if (by) { sim.ignored.push({ file: inv.file, by }); continue; }
      sim.tracked.push(inv.file);
      if (FORBID.has(inv.type)) sim.trackedForbidden.push(inv.file + ' (' + inv.type + ')');
      const conf = R.findings.filter((f) => f.file === inv.file && f.status === 'CONFIRMED' && f.category !== 'public-certificate');
      if (conf.length) sim.trackedWithSecrets.push({ file: inv.file, count: conf.length, lines: conf.map((f) => f.line || f.label).slice(0, 40) });
    }
    // pptx inner parts belong to the (ignored or not) deck
    const deckIgnored = R.inventory.filter((i) => i.type === 'pptx').every((i) => ignoredBy(i.file, rules));
    sim.deckIgnored = deckIgnored;
  }

  fs.writeFileSync(path.join(OUT, 'findings_redacted.json'), JSON.stringify(R.findings.map((f) => Object.assign({}, f, riskFix(f))), null, 1));
  fs.writeFileSync(path.join(OUT, 'findings_redacted.txt'), renderText(R, 'SECRET SCAN - redacted findings (values are never printed; fp = keyed per-run fingerprint, only comparable inside this report)'));
  fs.writeFileSync(path.join(OUT, 'inventory_files.txt'), R.inventory.map((i) => i.type.padEnd(16) + String(i.size).padStart(10) + '  ' + i.file).join('\n') + '\n');
  if (sim) {
    const S = [];
    S.push('SIMULATION of a .gitignore against the ' + R.inventory.length + ' scanned files (a simple matcher for simple patterns; git itself was NOT run)');
    S.push('tracked: ' + sim.tracked.length + '   ignored: ' + sim.ignored.length);
    S.push('forbidden-type files that would still be tracked: ' + sim.trackedForbidden.length);
    for (const x of sim.trackedForbidden) S.push('   ' + x);
    S.push('tracked files that contain CONFIRMED findings (blockers for the first commit): ' + sim.trackedWithSecrets.length);
    for (const x of sim.trackedWithSecrets) S.push('   ' + x.file + '  findings=' + x.count + '  at ' + x.lines.join(','));
    S.push('');
    S.push('IGNORED (' + sim.ignored.length + '):');
    for (const x of sim.ignored) S.push('   ' + x.file + '   <- ' + x.by);
    S.push('');
    S.push('TRACKED (' + sim.tracked.length + '):');
    for (const x of sim.tracked) S.push('   ' + x);
    fs.writeFileSync(path.join(OUT, 'gitignore_simulation.txt'), S.join('\n') + '\n');
  }

  // console summary (redacted)
  const cnt = (st) => R.findings.filter((f) => f.status === st).length;
  console.log('files scanned: text=' + R.stats.text + ' binary=' + R.stats.binary + ' total=' + R.inventory.length + (R.stats.probeError ? '  probeError=' + R.stats.probeError : ''));
  console.log('findings: CONFIRMED=' + cnt('CONFIRMED') + ' POSSIBLE=' + cnt('POSSIBLE') + ' ALLOWED=' + cnt('ALLOWED') + ' INFO=' + cnt('INFO') + ' DISMISSED=' + cnt('DISMISSED') + ' (long lines skipped: ' + R.stats.longSkipped.length + ')');
  const byCat = {};
  for (const f of R.findings.filter((x) => x.status === 'CONFIRMED' || x.status === 'POSSIBLE')) byCat[f.category + '/' + f.status] = (byCat[f.category + '/' + f.status] || 0) + 1;
  console.log('by category: ' + JSON.stringify(byCat));
  console.log('');
  console.log(renderText(R, 'REDACTED FINDINGS').split('\n').filter((l) => !/^=== (INFO|DISMISSED)/.test(l)).join('\n'));
  if (sim) {
    console.log('--- gitignore simulation: tracked=' + sim.tracked.length + ' ignored=' + sim.ignored.length + ' forbidden-type-tracked=' + sim.trackedForbidden.length + ' tracked-with-confirmed-findings=' + sim.trackedWithSecrets.length);
  }
  const failOnPossible = OPT['fail-on'] === 'possible';
  process.exitCode = (cnt('CONFIRMED') > 0 || (failOnPossible && cnt('POSSIBLE') > 0)) ? 1 : 0;
} else {
  console.error('usage: scan | selftest');
  process.exit(2);
}
