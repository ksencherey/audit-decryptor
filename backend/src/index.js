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
 * Derive a 32-byte AES key from the SecurityKey string.
 * The C-TWO app uses SHA-256 of the UTF-8 key as the AES key.
 */
function deriveKey(securityKey) {
  return createHash('sha256').update(securityKey, 'utf8').digest();
}

/**
 * Decrypt a single field value.
 * Format: <base64-IV>¤<base64-ciphertext>
 * Algorithm: AES-256-CBC, PKCS7 padding.
 */
function decryptField(encryptedValue, keyBuffer) {
  if (!encryptedValue || !encryptedValue.includes('¤')) {
    return encryptedValue; // not encrypted, return as-is
  }
  try {
    const [ivB64, cipherB64] = encryptedValue.split('¤');
    const iv = Buffer.from(ivB64, 'base64');
    const ciphertext = Buffer.from(cipherB64, 'base64');
    const decipher = createDecipheriv('aes-256-cbc', keyBuffer, iv);
    decipher.setAutoPadding(true);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
  } catch (err) {
    return `[DECRYPTION_FAILED: ${err.message}]`;
  }
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
    const { securityKey } = req.body;
    const format = req.query.format || 'json';

    if (!securityKey?.trim()) {
      return res.status(400).json({ error: 'SecurityKey is required.' });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'CSV file is required.' });
    }

    const keyBuffer = deriveKey(securityKey.trim());
    const csvText = req.file.buffer.toString('utf8');

    // Parse CSV — handle BOM
    const cleaned = csvText.replace(/^\uFEFF/, '');
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
    const ENCRYPTED_COLS = ['EncryptedOldData', 'EncryptedNewData'];
    const encryptedCols = ENCRYPTED_COLS.filter(c => columns.includes(c));

    let decryptedCount = 0;
    let errorCount = 0;

    const decryptedRecords = records.map((row, idx) => {
      const newRow = { ...row };
      for (const col of encryptedCols) {
        if (newRow[col] && newRow[col].includes('¤')) {
          const result = decryptField(newRow[col], keyBuffer);
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
