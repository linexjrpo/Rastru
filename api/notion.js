// Vercel Serverless Function — Notion API Proxy
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();

  const TOKEN = process.env.NOTION_TOKEN || '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';

  if (req.url && req.url.includes('/health')) {
    return res.status(200).json({ ok: true, tokenPrefix: TOKEN.slice(0,8)+'...', timestamp: new Date().toISOString() });
  }

  const urlObj = new URL(req.url, 'https://rastru.vercel.app');
  const notionPath = urlObj.pathname.replace(/^\/api\/notion/, '');
  if (!notionPath || notionPath === '/') return res.status(400).json({ error: 'Missing path' });

  const notionUrl = 'https://api.notion.com' + notionPath;
  const body = (req.method !== 'GET' && req.body) ? JSON.stringify(req.body) : undefined;

  try {
    const r = await fetch(notionUrl, {
      method: req.method,
      headers: {
        'Authorization': 'Bearer ' + TOKEN,
        'Notion-Version': '2022-06-28',
        'Content-Type': 'application/json'
      },
      body,
    });
    const data = await r.text();
    res.status(r.status).setHeader('Content-Type', 'application/json').send(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
