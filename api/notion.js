// Vercel Serverless Function — Notion API Proxy
// Token via env var NOTION_TOKEN (nunca hardcoded)

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  const TOKEN = process.env.NOTION_TOKEN || '';

  // Health check endpoint
  if (req.url === '/api/notion/health' || req.url.endsWith('/health')) {
    const hasToken = TOKEN.length > 10;
    return res.status(200).json({
      ok: hasToken,
      tokenPresent: hasToken,
      tokenPrefix: hasToken ? TOKEN.slice(0, 8) + '...' : 'MISSING',
      timestamp: new Date().toISOString()
    });
  }

  if (!TOKEN) {
    return res.status(500).json({
      error: 'NOTION_TOKEN environment variable not set on Vercel',
      fix: 'Go to vercel.com/linexjrpos-projects/rastru/settings/environment-variables and add NOTION_TOKEN'
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

    // On 401, add diagnostic info
    if (upstream.status === 401) {
      let parsed = {};
      try { parsed = JSON.parse(data); } catch(e) {}
      return res.status(401).json({
        ...parsed,
        _diagnostic: {
          tokenPrefix: TOKEN.slice(0, 8) + '...',
          tokenLength: TOKEN.length,
          hint: 'Token is invalid. Check: (1) Correct workspace, (2) Integration not deleted, (3) No extra spaces in token'
        }
      });
    }

    res.status(upstream.status).setHeader('Content-Type', 'application/json').send(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
