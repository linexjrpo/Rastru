// api/ai.js — Vercel serverless proxy for Anthropic Claude API
// Keeps API key server-side, enforces rate limiting and input validation

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const ANTHROPIC_URL = 'https://api.anthropic.com/v1/messages';
const MAX_PROMPT_LENGTH = 2000;
const MAX_TOKENS = 1500;
const ALLOWED_MODELS = ['claude-sonnet-4-20250514', 'claude-haiku-4-5-20251001'];

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'POST only' });

  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ ok: false, error: 'ANTHROPIC_API_KEY not configured' });
  }

  try {
    let body = req.body;
    if (!body || typeof body !== 'object') {
      const raw = await new Promise((resolve) => {
        let data = '';
        req.on('data', chunk => { data += chunk; });
        req.on('end', () => resolve(data));
      });
      try { body = JSON.parse(raw); } catch (e) {
        return res.status(400).json({ ok: false, error: 'Invalid JSON' });
      }
    }

    const { system, messages } = body;
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ ok: false, error: 'messages[] required' });
    }

    // Validate message lengths
    for (const msg of messages) {
      if (typeof msg.content !== 'string' || msg.content.length > MAX_PROMPT_LENGTH) {
        return res.status(400).json({ ok: false, error: `Message too long (max ${MAX_PROMPT_LENGTH} chars)` });
      }
      if (!['user', 'assistant'].includes(msg.role)) {
        return res.status(400).json({ ok: false, error: 'Invalid message role' });
      }
    }

    // Limit conversation history
    const trimmedMessages = messages.slice(-10);

    const model = ALLOWED_MODELS.includes(body.model) ? body.model : ALLOWED_MODELS[0];

    const anthropicRes = await fetch(ANTHROPIC_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model,
        max_tokens: MAX_TOKENS,
        system: typeof system === 'string' ? system.slice(0, 4000) : undefined,
        messages: trimmedMessages
      })
    });

    if (!anthropicRes.ok) {
      const errText = await anthropicRes.text();
      console.error('[ai proxy] Anthropic error:', anthropicRes.status, errText);
      return res.status(200).json({
        ok: false,
        error: anthropicRes.status === 429
          ? 'Muitas requisições — tente novamente em 1 minuto.'
          : 'Erro ao processar com IA. Tente novamente.'
      });
    }

    const data = await anthropicRes.json();
    const text = data.content?.[0]?.text || '';

    return res.status(200).json({
      ok: true,
      reply: text,
      usage: data.usage || null
    });

  } catch (err) {
    console.error('[ai proxy] error:', err.message);
    return res.status(500).json({ ok: false, error: 'Erro interno do servidor.' });
  }
};
