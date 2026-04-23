#!/bin/bash
# Rastru — Deploy automático no Vercel
# Execute: bash deploy.sh

echo "🚀 Rastru Deploy"
echo "================"

# Install vercel CLI if needed
if ! command -v vercel &> /dev/null; then
  echo "Instalando Vercel CLI..."
  npm install -g vercel
fi

# Deploy
echo ""
echo "Fazendo deploy... (vai abrir o browser para login na primeira vez)"
vercel deploy --prod --yes \
  --name rastru \
  --build-env NOTION_TOKEN="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"

echo ""
echo "✅ Deploy concluído!"
echo "Adicionando variável de ambiente Notion..."

vercel env add NOTION_TOKEN production << 'ENVEOF'
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
ENVEOF

echo "Redeploy com token ativo..."
vercel deploy --prod --yes

echo ""
echo "✅ Rastru no ar! Acesse a URL acima."
