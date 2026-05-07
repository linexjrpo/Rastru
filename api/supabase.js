// api/supabase.js — Vercel serverless proxy for Supabase
// Bypasses CORS entirely — server-side calls only

const SB_URL = 'https://wsjfelnpxuxvpiorupsl.supabase.co/rest/v1';
const SB_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndzamZlbG5weHV4dnBpb3J1cHNsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzgwODUxNzksImV4cCI6MjA5MzY2MTE3OX0.w27LsRWiglhPF8mNVeVV1kGgWzH2ETNbk41wlQgY39Q';

const SB_HEADERS = {
  'apikey': SB_KEY,
  'Authorization': `Bearer ${SB_KEY}`,
  'Content-Type': 'application/json'
};

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();

  const action = req.query.action || 'load';

  try {
    // ── LOAD ──────────────────────────────────────────────
    if (action === 'load') {
      const r = await fetch(`${SB_URL}/campaigns?select=*&order=created_at.desc`, {
        headers: SB_HEADERS
      });
      if (!r.ok) {
        const err = await r.text();
        return res.status(200).json({ ok: false, error: `Supabase ${r.status}: ${err}` });
      }
      const data = await r.json();
      return res.status(200).json({ ok: true, camps: Array.isArray(data) ? data : [] });
    }

    // ── SAVE ──────────────────────────────────────────────
    if (action === 'save') {
      // Parse body manually (Vercel serverless)
      let camp = req.body;
      if (!camp || typeof camp !== 'object') {
        const raw = await new Promise((resolve) => {
          let data = '';
          req.on('data', chunk => { data += chunk; });
          req.on('end', () => resolve(data));
        });
        try { camp = JSON.parse(raw); } catch(e) {
          return res.status(400).json({ ok: false, error: 'Invalid JSON body' });
        }
      }
      if (!camp || !camp.id) return res.status(400).json({ ok: false, error: 'Missing camp.id' });

      const r = await fetch(`${SB_URL}/campaigns`, {
        method: 'POST',
        headers: { ...SB_HEADERS, 'Prefer': 'resolution=merge-duplicates,return=minimal' },
        body: JSON.stringify(camp)
      });
      const ok = r.status >= 200 && r.status < 300;
      if (!ok) {
        const err = await r.text();
        return res.status(200).json({ ok: false, error: `Supabase ${r.status}: ${err}` });
      }
      return res.status(200).json({ ok: true, status: r.status });
    }

    // ── DELETE ────────────────────────────────────────────
    if (action === 'delete') {
      const id = req.query.id;
      if (!id) return res.status(400).json({ ok: false, error: 'Missing id' });
      const r = await fetch(`${SB_URL}/campaigns?id=eq.${encodeURIComponent(id)}`, {
        method: 'DELETE',
        headers: SB_HEADERS
      });
      return res.status(200).json({ ok: r.ok, status: r.status });
    }

    return res.status(400).json({ ok: false, error: `Unknown action: ${action}` });

  } catch(err) {
    console.error('[Rastru proxy] error:', err.message);
    return res.status(500).json({ ok: false, error: err.message });
  }
};
