import React from 'react';
import ReactDOM from 'react-dom/client';
import { Toaster } from 'react-hot-toast';
import App from './App.jsx';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
    <Toaster position="bottom-right" toastOptions={{
      style: { background: '#1e2537', color: '#e2e8f0', border: '1px solid #2d3748', fontSize: '13px' },
      success: { iconTheme: { primary: '#4ade80', secondary: '#0f1117' } },
      error: { iconTheme: { primary: '#f87171', secondary: '#0f1117' } },
    }} />
  </React.StrictMode>
);
