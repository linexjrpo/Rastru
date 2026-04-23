# Rastru — Deploy no Vercel

## Estrutura
```
rastru-vercel/
  api/notion.js       ← Edge Function proxy (sem CORS)
  public/index.html   ← App Rastru completo
  vercel.json         ← Config de rotas
  package.json
```

## Deploy em 3 passos

### 1. Instalar Vercel CLI
```bash
npm i -g vercel
```

### 2. Deploy
```bash
cd rastru-vercel
vercel deploy --prod
```
Vai pedir login na primeira vez.

### 3. Adicionar variável de ambiente
No dashboard Vercel → Project → Settings → Environment Variables:
```
NOTION_TOKEN = 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
```

Depois: Settings → Functions → Redeploy

## URL final
`https://rastru.vercel.app` (ou o nome que você escolher)
