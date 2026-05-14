import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import { createDecipheriv, createHash } from 'crypto';
import { parse } from 'csv-parse/sync';
import { stringify } from 'csv-stringify/sync';
import { readFileSync } from 'fs';
import path from 'path';

const app = express();
const PORT = process.env.PORT || 4001;
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 100 * 1024 * 1024 } });

app.use(express.json());
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:5173' }));

// ── Crypto helpers ──────────────────────────────────────────────────────────

/**
 * Derive the AES key from the SecurityKey string.
 * Tries approaches in order until one works.
 * Returns an array of candidate key buffers to try.
 */
function deriveKeyCandidates(securityKey) {
  const raw = Buffer.from(securityKey, 'utf8');
  const candidates = [];

  // 1. Raw UTF-8 bytes, truncated/zero-padded to exactly 32 bytes (most common .NET pattern)
  const padded = Buffer.alloc(32, 0);
  raw.copy(padded, 0, 0, Math.min(raw.length, 32));
  candidates.push(padded);

  // 2. SHA-256 hash of the key (second most common)
  candidates.push(createHash('sha256').update(securityKey, 'utf8').digest());

  // 3. Raw bytes if key is exactly 16 or 24 bytes (AES-128 / AES-192)
  if (raw.length === 16 || raw.length === 24 || raw.length === 32) {
    candidates.push(raw);
  }

  return candidates;
}

function deriveKey(securityKey) {
  // For backwards compatibility, return the most common approach
  const raw = Buffer.from(securityKey, 'utf8');
  const padded = Buffer.alloc(32, 0);
  raw.copy(padded, 0, 0, Math.min(raw.length, 32));
  return padded;
}

/**
 * Decrypt a single field, trying every supplied key (current + rotated old keys).
 * For each key, tries multiple derivation approaches (raw bytes, SHA-256).
 */
function decryptField(encryptedValue, keys) {
  if (!encryptedValue || !encryptedValue.includes('¤')) return encryptedValue;

  const keyList = Array.isArray(keys) ? keys : [keys];
  const [ivB64, cipherB64] = encryptedValue.split('¤');
  const iv = Buffer.from(ivB64, 'base64');
  const ciphertext = Buffer.from(cipherB64, 'base64');

  for (const key of keyList) {
    for (const keyBuffer of deriveKeyCandidates(key)) {
      try {
        const decipher = createDecipheriv('aes-256-cbc', keyBuffer, iv);
        decipher.setAutoPadding(true);
        const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        const text = decrypted.toString('utf8');
        // Validate the result looks like real data (printable UTF-8, not binary garbage)
        // A simple heuristic: if >20% of chars are control/non-printable, it's garbage
        const nonPrintable = (text.match(/[\x00-\x08\x0e-\x1f\x7f-\x9f]/g) || []).length;
        if (nonPrintable / text.length > 0.1) continue; // likely wrong key, try next
        return text;
      } catch (_) {
        // padding error = wrong key, try next
      }
    }
  }
  return `[DECRYPTION_FAILED: tried ${keyList.length} key(s) — add old SecurityKey if key was rotated]`;
}

// ── Routes ──────────────────────────────────────────────────────────────────

// Health check
app.get('/api/health', (_, res) => res.json({ ok: true }));

/**
 * POST /api/decrypt
 * Body: multipart/form-data
 *   - securityKey: string  (from appsettings.json)
 *   - csvFile: file        (exported AuditLogs CSV)
 * Returns: JSON { rows, columns, totalRows, decryptedRows, errors }
 * Or downloadable CSV if ?format=csv
 */
app.post('/api/decrypt', upload.single('csvFile'), (req, res) => {
  try {
    const { securityKey, additionalKeys } = req.body;
    const format = req.query.format || 'json';

    if (!securityKey?.trim()) {
      return res.status(400).json({ error: 'SecurityKey is required.' });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'CSV file is required.' });
    }

    // Build full list of keys to try: current key + any additional (old rotated) keys
    const allKeys = [securityKey.trim()];
    if (additionalKeys) {
      // additionalKeys comes as JSON array string or newline-separated string
      try {
        const parsed = JSON.parse(additionalKeys);
        if (Array.isArray(parsed)) parsed.forEach(k => k.trim() && allKeys.push(k.trim()));
      } catch {
        additionalKeys.split('\n').forEach(k => k.trim() && allKeys.push(k.trim()));
      }
    }
    console.log('[decrypt] Using', allKeys.length, 'key(s)');

    // SQL Server SSMS can export CSVs as UTF-8, UTF-8 BOM, or Latin-1/Windows-1252.
    // The ¤ separator (U+00A4) is 0xC2 0xA4 in UTF-8 but only 0xA4 in Latin-1.
    // Reading as latin1 preserves 0xA4 as U+00A4 correctly in all cases.
    const csvText = req.file.buffer.toString('latin1');

    // Parse CSV — handle BOM (UTF-8 BOM appears as \xEF\xBB\xBF in latin1)
    const cleaned = csvText.replace(/^(\uFEFF|\xEF\xBB\xBF)/, '');
    let records;
    try {
      records = parse(cleaned, {
        columns: true,
        skip_empty_lines: true,
        relax_quotes: true,
        trim: true,
      });
    } catch (parseErr) {
      return res.status(400).json({ error: `CSV parse error: ${parseErr.message}` });
    }

    if (records.length === 0) {
      return res.status(400).json({ error: 'CSV file is empty or has no data rows.' });
    }

    const columns = Object.keys(records[0]);

    // Match encrypted columns case-insensitively — SQL Server exports may use
    // different casing (e.g. ENCRYPTEDOLDDATA, encryptedolddata, EncryptedOldData)
    const ENCRYPTED_COLS = ['encryptedolddata', 'encryptednewdata'];
    const encryptedCols = columns.filter(c =>
      ENCRYPTED_COLS.includes(c.toLowerCase())
    );

    console.log('[decrypt] CSV columns:', columns);
    console.log('[decrypt] Matched encrypted cols:', encryptedCols);

    let decryptedCount = 0;
    let errorCount = 0;

    const decryptedRecords = records.map((row, idx) => {
      const newRow = { ...row };
      for (const col of encryptedCols) {
        const val = newRow[col];
        // The ¤ separator (U+00A4) may survive as-is or as the latin1 byte 0xA4
        // Check both the unicode character and its latin1 representation
        const hasSeparator = val && (val.includes('\u00a4') || val.includes('¤'));
        if (hasSeparator) {
          const normalised = val.replace(/\u00a4/g, '¤');
          const result = decryptField(normalised, allKeys);
          if (result.startsWith('[DECRYPTION_FAILED')) {
            errorCount++;
          } else {
            decryptedCount++;
          }
          newRow[col] = result;
        }
      }
      return newRow;
    });

    if (format === 'csv') {
      const csvOut = stringify(decryptedRecords, { header: true, columns });
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="audit_logs_decrypted.csv"');
      return res.send(csvOut);
    }

    return res.json({
      columns,
      rows: decryptedRecords,
      totalRows: records.length,
      decryptedRows: decryptedCount,
      encryptedColumns: encryptedCols,
      errors: errorCount,
    });

  } catch (err) {
    console.error('[decrypt error]', err);
    return res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/read-appsettings
 * Body: multipart/form-data — appsettingsFile: file
 * Extracts SecurityKey from uploaded appsettings.json
 */
app.post('/api/read-appsettings', upload.single('appsettingsFile'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });
    const json = JSON.parse(req.file.buffer.toString('utf8'));
    const key = json.SecurityKey || json.securityKey || json.security_key;
    if (!key) return res.status(400).json({ error: 'SecurityKey not found in appsettings.json.' });
    return res.json({ securityKey: key });
  } catch (err) {
    return res.status(400).json({ error: `Could not parse file: ${err.message}` });
  }
});

app.listen(PORT, () => {
  console.log(`\n🔓 Audit Decryptor API running on http://localhost:${PORT}\n`);
});