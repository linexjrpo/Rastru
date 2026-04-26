// Vercel Serverless Function — Notion API Proxy
// Token via env var NOTION_TOKEN (primary) ou fallback hardcoded
// Internal Integration tokens NÃO expiram — são permanentes

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();

  // Token: env var tem prioridade, fallback hardcoded
  const TOKEN = process.env.NOTION_TOKEN || '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';

  // Health check
  if (req.url && req.url.includes('/health')) {
    return res.status(200).json({
      ok: true,
      tokenPresent: TOKEN.length > 10,
      tokenPrefix: TOKEN.slice(0, 8) + '...',
      timestamp: new Date().toISOString()
    });
  }

  const urlObj = new URL(req.url, 'https://rastru.vercel.app');
  const notionPath = urlObj.pathname.replace(/^\/api\/notion/, '');

  if (!notionPath || notionPath === '/') {
    return res.status(400).json({ error: 'Missing Notion API path' });
  }

  const notionUrl = 'https://api.notion.com' + notionPath;
  const body = (req.method !== 'GET' && req.body) ? JSON.stringify(req.body) : undefined;

  try {
    const upstream = await fetch(notionUrl, {
      method: req.method,
      headers: {
        'Authorization': 'Bearer ' + TOKEN,
        'Notion-Version': '2022-06-28',
        'Content-Type': 'application/json',
      },
      body,
    });

    const data = await upstream.text();

    if (upstream.status === 401) {
      let parsed = {};
      try { parsed = JSON.parse(data); } catch(e) {}
      return res.status(401).json({
        ...parsed,
        _diagnostic: {
          tokenPrefix: TOKEN.slice(0, 8) + '...',
          tokenLength: TOKEN.length,
          hint: 'Verifique: (1) workspace correta, (2) integração não deletada, (3) database compartilhado via Connect to'
        }
      });
    }

    res.status(upstream.status).setHeader('Content-Type', 'application/json').send(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
