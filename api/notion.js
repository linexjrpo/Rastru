export const config = { runtime: 'edge' };

export default async function handler(req) {
  if (req.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE',
        'Access-Control-Allow-Headers': 'Content-Type',
      },
    });
  }

  const url = new URL(req.url);
  const notionPath = url.pathname.replace(/^\/api\/notion/, '');
  const notionUrl = 'https://api.notion.com' + notionPath + url.search;
  const body = req.method !== 'GET' ? await req.text() : undefined;

  const token = process.env.NOTION_TOKEN || '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';

  const res = await fetch(notionUrl, {
    method: req.method,
    headers: {
      'Authorization': 'Bearer ' + token,
      'Notion-Version': '2022-06-28',
      'Content-Type': 'application/json',
    },
    body,
  });

  const data = await res.text();

  return new Response(data, {
    status: res.status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
}
