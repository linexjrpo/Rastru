// Vercel Serverless Function — Notion API Proxy (CommonJS)
const TOKEN = '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';

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  const notionPath = req.url.replace(/^\/api\/notion/, '');
  const notionUrl = 'https://api.notion.com' + notionPath;

  const body = req.method !== 'GET' ? JSON.stringify(req.body) : undefined;

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
  res.status(upstream.status).setHeader('Content-Type', 'application/json').send(data);
};
