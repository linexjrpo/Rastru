// api/supabase.js — Vercel serverless proxy for Supabase
// Bypasses CORS entirely — all calls go server-side

const SB_URL = 'https://wsjfelnpxuxvpiorupsl.supabase.co/rest/v1';
const SB_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndzamZlbG5weHV4dnBpb3J1cHNsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzgwODUxNzksImV4cCI6MjA5MzY2MTE3OX0.w27LsRWiglhPF8mNVeVV1kGgWzH2ETNbk41wlQgY39Q';

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();

  const action = req.query.action || 'load';

  try {
    if (action === 'load') {
      const r = await fetch(`${SB_URL}/campaigns?select=*&order=created_at.desc`, {
        headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
      });
      const data = await r.json();
      return res.status(200).json({ ok: true, camps: Array.isArray(data) ? data : [] });
    }

    if (action === 'save') {
      const camp = req.body;
      if (!camp || !camp.id) return res.status(400).json({ ok: false, error: 'No data' });
      const r = await fetch(`${SB_URL}/campaigns`, {
        method: 'POST',
        headers: {
          'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}`,
          'Content-Type': 'application/json',
          'Prefer': 'resolution=merge-duplicates,return=minimal'
        },
        body: JSON.stringify(camp)
      });
      const ok = r.status === 200 || r.status === 201 || r.status === 204;
      return res.status(200).json({ ok, status: r.status });
    }

    if (action === 'delete') {
      const id = req.query.id;
      if (!id) return res.status(400).json({ ok: false, error: 'No id' });
      const r = await fetch(`${SB_URL}/campaigns?id=eq.${encodeURIComponent(id)}`, {
        method: 'DELETE',
        headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
      });
      return res.status(200).json({ ok: r.ok, status: r.status });
    }

    return res.status(400).json({ ok: false, error: 'Unknown action' });
  } catch(err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
};
