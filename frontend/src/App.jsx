import { useState, useRef } from 'react';
import toast from 'react-hot-toast';
import {
  Lock, Unlock, Upload, Download, FileText, Key, AlertCircle,
  CheckCircle2, X, ChevronDown, ChevronUp, Eye, EyeOff, FileJson
} from 'lucide-react';

const ENCRYPTED_COLS = ['EncryptedOldData', 'EncryptedNewData'];

// ── Step indicator ─────────────────────────────────────────────────────────
function Step({ n, label, done, active }) {
  return (
    <div className={`flex items-center gap-2 text-sm ${active ? 'text-white' : done ? 'text-green-400' : 'text-slate-500'}`}>
      <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold border
        ${active ? 'border-blue-500 bg-blue-500/20 text-blue-400' : done ? 'border-green-500 bg-green-500/20' : 'border-slate-600 bg-slate-800'}`}>
        {done ? <CheckCircle2 size={14} /> : n}
      </div>
      <span className="hidden sm:inline">{label}</span>
    </div>
  );
}

// ── File drop zone ─────────────────────────────────────────────────────────
function DropZone({ label, accept, icon: Icon, file, onFile, hint }) {
  const ref = useRef();
  const [dragging, setDragging] = useState(false);

  const handleDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) onFile(f);
  };

  return (
    <div
      onClick={() => ref.current.click()}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      className={`relative cursor-pointer rounded-xl border-2 border-dashed transition-all duration-150 p-6 text-center
        ${dragging ? 'border-blue-500 bg-blue-500/10' : file ? 'border-green-500/50 bg-green-500/5' : 'border-slate-700 hover:border-slate-500 bg-slate-800/40'}`}
    >
      <input ref={ref} type="file" accept={accept} className="hidden" onChange={e => e.target.files[0] && onFile(e.target.files[0])} />
      <div className="flex flex-col items-center gap-2">
        {file ? (
          <>
            <CheckCircle2 size={24} className="text-green-400" />
            <p className="text-sm font-medium text-green-300">{file.name}</p>
            <p className="text-xs text-slate-500">{(file.size / 1024).toFixed(1)} KB — click to change</p>
          </>
        ) : (
          <>
            <Icon size={24} className="text-slate-500" />
            <p className="text-sm font-medium text-slate-300">{label}</p>
            {hint && <p className="text-xs text-slate-500">{hint}</p>}
          </>
        )}
      </div>
    </div>
  );
}

// ── Results table ──────────────────────────────────────────────────────────
function ResultsTable({ columns, rows, encryptedColumns }) {
  const [expandedRows, setExpandedRows] = useState(new Set());

  const toggleRow = (i) => setExpandedRows(prev => {
    const n = new Set(prev);
    n.has(i) ? n.delete(i) : n.add(i);
    return n;
  });

  const isEncCol = (col) => encryptedColumns.includes(col);

  return (
    <div className="table-wrapper rounded-xl border border-slate-700">
      <table>
        <thead>
          <tr>
            <th style={{ width: 40 }}>#</th>
            {columns.map(c => (
              <th key={c} className={isEncCol(c) ? 'text-green-400' : ''}>
                {isEncCol(c) ? '🔓 ' : ''}{c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => {
            const expanded = expandedRows.has(i);
            return (
              <tr key={i} onClick={() => toggleRow(i)} className="cursor-pointer">
                <td className="plain text-slate-500 text-center">{i + 1}</td>
                {columns.map(col => {
                  const val = row[col] ?? '';
                  const enc = isEncCol(col);
                  const failed = enc && val.startsWith('[DECRYPTION_FAILED');
                  const truncate = val.length > 120 && !expanded;
                  return (
                    <td key={col} className={enc ? (failed ? 'failed' : 'decrypted') : 'plain'}>
                      {truncate ? val.slice(0, 120) + '…' : val || <span className="text-slate-600">—</span>}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────────────────
export default function App() {
  const [securityKey, setSecurityKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [appSettingsFile, setAppSettingsFile] = useState(null);
  const [csvFile, setCsvFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadingSettings, setLoadingSettings] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const step = !securityKey ? 1 : !csvFile ? 2 : 3;
  const done1 = !!securityKey;
  const done2 = !!csvFile;

  // Load key from appsettings.json
  const handleLoadFromFile = async () => {
    if (!appSettingsFile) return;
    setLoadingSettings(true);
    try {
      const fd = new FormData();
      fd.append('appsettingsFile', appSettingsFile);
      const res = await fetch('/api/read-appsettings', { method: 'POST', body: fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setSecurityKey(data.securityKey);
      toast.success('SecurityKey loaded from appsettings.json');
    } catch (e) {
      toast.error(e.message);
    } finally {
      setLoadingSettings(false);
    }
  };

  // Decrypt
  const handleDecrypt = async () => {
    if (!securityKey.trim() || !csvFile) return;
    setError('');
    setResult(null);
    setLoading(true);
    try {
      const fd = new FormData();
      fd.append('securityKey', securityKey.trim());
      fd.append('csvFile', csvFile);
      const res = await fetch('/api/decrypt', { method: 'POST', body: fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setResult(data);
      toast.success(`Decrypted ${data.decryptedRows} fields across ${data.totalRows} rows`);
    } catch (e) {
      setError(e.message);
      toast.error('Decryption failed');
    } finally {
      setLoading(false);
    }
  };

  // Download CSV
  const handleDownload = async () => {
    if (!securityKey.trim() || !csvFile) return;
    const fd = new FormData();
    fd.append('securityKey', securityKey.trim());
    fd.append('csvFile', csvFile);
    const res = await fetch('/api/decrypt?format=csv', { method: 'POST', body: fd });
    if (!res.ok) { toast.error('Download failed'); return; }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'audit_logs_decrypted.csv'; a.click();
    URL.revokeObjectURL(url);
    toast.success('CSV downloaded');
  };

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-20">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center">
            <Unlock size={16} className="text-white" />
          </div>
          <div>
            <h1 className="font-semibold text-white text-sm leading-tight">C-TWO Audit Log Decryptor</h1>
            <p className="text-xs text-slate-500">AES-256-CBC · EncryptedOldData & EncryptedNewData</p>
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-7xl mx-auto w-full px-6 py-8">

        {/* Step progress */}
        <div className="flex items-center gap-4 mb-8">
          <Step n="1" label="Security Key" done={done1} active={step === 1} />
          <div className="flex-1 h-px bg-slate-800" />
          <Step n="2" label="Upload CSV" done={done2} active={step === 2} />
          <div className="flex-1 h-px bg-slate-800" />
          <Step n="3" label="Decrypt" done={!!result} active={step === 3} />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">

          {/* Panel 1: Security Key */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <Key size={16} className="text-blue-400" />
              <h2 className="font-semibold text-sm text-white">Step 1 — Security Key</h2>
            </div>

            {/* Option A: paste key */}
            <div className="mb-4">
              <label className="block text-xs text-slate-500 mb-1.5 font-medium">Paste SecurityKey</label>
              <div className="relative">
                <input
                  type={showKey ? 'text' : 'password'}
                  value={securityKey}
                  onChange={e => setSecurityKey(e.target.value)}
                  placeholder="Paste your SecurityKey value here"
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2.5 pr-10
                             text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500
                             font-mono"
                />
                <button onClick={() => setShowKey(!showKey)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">
                  {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
              {securityKey && (
                <p className="text-xs text-green-400 mt-1 flex items-center gap-1">
                  <CheckCircle2 size={11} /> Key set ({securityKey.length} chars)
                </p>
              )}
            </div>

            <div className="relative flex items-center gap-2 my-4">
              <div className="flex-1 h-px bg-slate-700" />
              <span className="text-xs text-slate-500">or</span>
              <div className="flex-1 h-px bg-slate-700" />
            </div>

            {/* Option B: load from file */}
            <div>
              <label className="block text-xs text-slate-500 mb-1.5 font-medium">Load from appsettings.json</label>
              <DropZone
                label="Drop appsettings.json"
                accept=".json"
                icon={FileJson}
                file={appSettingsFile}
                onFile={setAppSettingsFile}
                hint="C:\Program Files\C TWO\{client}\Server\appsettings.json"
              />
              {appSettingsFile && (
                <button
                  onClick={handleLoadFromFile}
                  disabled={loadingSettings}
                  className="mt-2 w-full py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-sm text-white
                             font-medium transition-colors disabled:opacity-50"
                >
                  {loadingSettings ? 'Reading…' : 'Extract Key from File'}
                </button>
              )}
            </div>
          </div>

          {/* Panel 2: Upload CSV */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <FileText size={16} className="text-purple-400" />
              <h2 className="font-semibold text-sm text-white">Step 2 — Upload Audit Log CSV</h2>
            </div>
            <DropZone
              label="Drop your AuditLogs CSV"
              accept=".csv"
              icon={Upload}
              file={csvFile}
              onFile={setCsvFile}
              hint='Export via: SELECT * FROM AuditLogs → Save as CSV'
            />
            {csvFile && (
              <button onClick={() => { setCsvFile(null); setResult(null); }}
                className="mt-2 w-full py-1.5 rounded-lg border border-slate-700 hover:bg-slate-800 text-xs text-slate-400 transition-colors flex items-center justify-center gap-1">
                <X size={12} /> Remove file
              </button>
            )}
            <div className="mt-4 p-3 rounded-lg bg-slate-800/60 border border-slate-700">
              <p className="text-xs text-slate-400 font-medium mb-1">Expected encrypted columns:</p>
              <div className="flex flex-wrap gap-1">
                {ENCRYPTED_COLS.map(c => (
                  <span key={c} className="text-xs px-2 py-0.5 rounded-full bg-green-500/10 text-green-400 border border-green-500/20 font-mono">
                    {c}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Panel 3: Decrypt */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <Unlock size={16} className="text-green-400" />
              <h2 className="font-semibold text-sm text-white">Step 3 — Decrypt & Export</h2>
            </div>

            {/* Summary */}
            <div className="space-y-2 mb-6">
              <div className={`flex items-center justify-between p-2.5 rounded-lg ${done1 ? 'bg-green-500/10 border border-green-500/20' : 'bg-slate-800 border border-slate-700'}`}>
                <span className="text-xs text-slate-400">Security Key</span>
                {done1 ? <span className="text-xs text-green-400 flex items-center gap-1"><CheckCircle2 size={12} /> Ready</span>
                       : <span className="text-xs text-slate-500">Not set</span>}
              </div>
              <div className={`flex items-center justify-between p-2.5 rounded-lg ${done2 ? 'bg-green-500/10 border border-green-500/20' : 'bg-slate-800 border border-slate-700'}`}>
                <span className="text-xs text-slate-400">CSV File</span>
                {done2 ? <span className="text-xs text-green-400 flex items-center gap-1"><CheckCircle2 size={12} /> {csvFile?.name}</span>
                       : <span className="text-xs text-slate-500">Not uploaded</span>}
              </div>
            </div>

            <button
              onClick={handleDecrypt}
              disabled={!done1 || !done2 || loading}
              className="w-full py-3 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-40
                         disabled:cursor-not-allowed text-white font-semibold text-sm transition-all
                         flex items-center justify-center gap-2 mb-3"
            >
              {loading ? (
                <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Decrypting…</>
              ) : (
                <><Unlock size={16} /> Decrypt Audit Logs</>
              )}
            </button>

            {result && (
              <button
                onClick={handleDownload}
                className="w-full py-2.5 rounded-xl bg-green-600/20 hover:bg-green-600/30 border border-green-500/30
                           text-green-400 font-medium text-sm transition-all flex items-center justify-center gap-2"
              >
                <Download size={15} /> Download Decrypted CSV
              </button>
            )}

            {result && (
              <div className="mt-4 grid grid-cols-2 gap-2 text-center">
                <div className="bg-slate-800 rounded-lg p-3">
                  <p className="text-xl font-bold text-white">{result.totalRows}</p>
                  <p className="text-xs text-slate-500">Total rows</p>
                </div>
                <div className="bg-slate-800 rounded-lg p-3">
                  <p className="text-xl font-bold text-green-400">{result.decryptedRows}</p>
                  <p className="text-xs text-slate-500">Fields decrypted</p>
                </div>
                {result.errors > 0 && (
                  <div className="col-span-2 bg-red-500/10 border border-red-500/20 rounded-lg p-2">
                    <p className="text-xs text-red-400 flex items-center justify-center gap-1">
                      <AlertCircle size={12} /> {result.errors} field(s) failed — check your key
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Error banner */}
        {error && (
          <div className="mb-6 flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/10 px-5 py-4">
            <AlertCircle size={16} className="text-red-400 mt-0.5 shrink-0" />
            <div>
              <p className="text-sm font-medium text-red-300">Decryption failed</p>
              <p className="text-sm text-red-400/80 mt-0.5">{error}</p>
            </div>
          </div>
        )}

        {/* Results table */}
        {result && (
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="font-semibold text-white flex items-center gap-2">
                <CheckCircle2 size={16} className="text-green-400" />
                Decrypted Results
                <span className="text-xs text-slate-500 font-normal">({result.totalRows} rows)</span>
              </h2>
              <div className="flex items-center gap-2">
                {result.encryptedColumns.map(c => (
                  <span key={c} className="text-xs px-2 py-0.5 rounded-full bg-green-500/10 text-green-400 border border-green-500/20 font-mono">
                    🔓 {c}
                  </span>
                ))}
              </div>
            </div>
            <ResultsTable
              columns={result.columns}
              rows={result.rows}
              encryptedColumns={result.encryptedColumns}
            />
            <p className="text-xs text-slate-600 mt-2 text-center">
              Click any row to expand · Green columns = decrypted · Scroll horizontally for all columns
            </p>
          </div>
        )}

      </main>

      <footer className="border-t border-slate-800 py-4 text-center text-xs text-slate-600">
        C-TWO Audit Log Decryptor · AES-256-CBC · Data never leaves your machine
      </footer>
    </div>
  );
}
