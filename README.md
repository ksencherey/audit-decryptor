# C-TWO Audit Log Decryptor

Decrypts the `EncryptedOldData` and `EncryptedNewData` columns from the C-TWO AuditLogs table.

## How it works

The C-TWO app encrypts audit fields using **AES-256-CBC**. Each encrypted value is stored as:
```
<Base64-IV>¤<Base64-ciphertext>
```
The AES key is derived by taking a **SHA-256 hash** of the `SecurityKey` value from `appsettings.json`.

---

## Folder Structure

```
audit-decryptor/
├── backend/
│   ├── src/index.js      ← Express API (decryption logic lives here)
│   ├── .env.example
│   └── package.json
└── frontend/
    ├── src/App.jsx        ← React UI
    ├── index.html
    ├── vite.config.js
    └── package.json
```

---

## Setup & Run

### 1. Install dependencies

```bash
# Backend
cd audit-decryptor/backend
npm install

# Frontend
cd ../frontend
npm install
```

### 2. Start both servers (two terminals)

**Terminal 1 — Backend (port 4001):**
```bash
cd audit-decryptor/backend
npm run dev
```

**Terminal 2 — Frontend (port 5173):**
```bash
cd audit-decryptor/frontend
npm run dev
```

Open **http://localhost:5173**

---

## How to use

### Step 1 — Provide the Security Key

**Option A:** Copy the `SecurityKey` value from the client's `appsettings.json` and paste it directly.

**Option B:** Click "Drop appsettings.json", upload the file, then click **Extract Key from File**.

The file is located at:
```
C:\Program Files\C TWO\{ClientName}\Server\appsettings.json
```

Look for:
```json
{
  "SecurityKey": "your-key-value-here"
}
```

### Step 2 — Upload the CSV

Export the AuditLogs table from the client's SQL Server database:
```sql
SELECT * FROM AuditLogs
```
Save the result as a `.csv` file and upload it.

### Step 3 — Decrypt

- Click **Decrypt Audit Logs** to view results in the browser table
- Click **Download Decrypted CSV** to save the fully decrypted file

---

## Notes

- Data is processed entirely on your local machine — nothing is sent to the internet
- If decryption fails, check that the SecurityKey is correct and hasn't been truncated
- The green-highlighted columns in the results table are the decrypted fields
- Click any row in the table to expand long values
