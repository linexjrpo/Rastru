// Vercel Serverless Function — Notion API Proxy
// Token somente via env var NOTION_TOKEN (nunca hardcoded)

const ALLOWED_ORIGINS = ['https://rastru.vercel.app'];
const ALLOWED_METHODS = ['GET', 'POST', 'PATCH', 'DELETE'];

module.exports = async function handler(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', ALLOWED_METHODS.join(', '));
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (!ALLOWED_METHODS.includes(req.method)) return res.status(405).end();

  const TOKEN = process.env.NOTION_TOKEN || '';

  const urlObj = new URL(req.url, 'https://rastru.vercel.app');
  const notionPath = urlObj.pathname.replace(/^\/api\/notion/, '');

  if (notionPath === '/health') {
    return res.status(200).json({ ok: TOKEN.length > 10, timestamp: new Date().toISOString() });
  }

  if (!TOKEN) {
    return res.status(500).json({ error: 'notion_token_not_configured' });
  }

  // Só repassa para a API v1 do Notion, sem path traversal
  if (!/^\/v1\/[A-Za-z0-9_\-\/]+$/.test(notionPath) || notionPath.includes('..')) {
    return res.status(400).json({ error: 'invalid_notion_path' });
  }

  const notionUrl = 'https://api.notion.com' + notionPath + urlObj.search;
  const body = (req.method !== 'GET' && req.body) ? JSON.stringify(req.body) : undefined;

  try {
    const upstream = await fetch(notionUrl, {
      method: req.method,
      headers: {
        'Authorization': 'Bearer ' + TOKEN,
        'Notion-Version': '2022-06-28',
        'Content-Type': 'application/json'
      },
      body,
    });
    const data = await upstream.text();
    res.status(upstream.status).setHeader('Content-Type', 'application/json').send(data);
  } catch (err) {
    res.status(502).json({ error: 'upstream_error' });
  }
};
