// Pure functions extracted from js/app.js for testability
// This file is auto-generated — do not edit directly

const _eSanitizeEl = typeof document !== 'undefined'
  ? document.createElement('div')
  : { textContent: '', get innerHTML() { let s=this.textContent; return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); } };

function eSanitize(str) {
  if(str == null) return '';
  // DOM textContent escapa apenas os chars realmente perigosos para HTML
  if(typeof document !== 'undefined' && _eSanitizeEl) {
    _eSanitizeEl.textContent = String(str);
    return _eSanitizeEl.innerHTML;
  }
  // Fallback: escapa APENAS os chars que criam tags HTML
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
  // = { } $ ( ) são SEGUROS em texto HTML — não escapar
}

function eSanitizeUrl(url) {
  // Valida URLs externas — permite apenas http/https
  if(!url) return '#';
  const clean = String(url).trim();
  if(/^https?:\/\//i.test(clean)) return clean;
  return '#';
}

function eSanitizeInt(val, min, max, def) {
  // Sanitiza inteiros com bounds
  const n = parseInt(val);
  if(isNaN(n)) return def;
  return Math.max(min, Math.min(max, n));
}

function eSanitizeCity(str) {
  if(!str) return '';
  return String(str)
    .replace(/[<>"'`\\]/g, '')          // remove tags, aspas, backtick, backslash
    .replace(/javascript:/gi, '')        // bloqueia javascript: URI
    .replace(/data:/gi, '')              // bloqueia data: URI
    .replace(/vbscript:/gi, '')          // bloqueia vbscript:
    .replace(/on\w+\s*=/gi, '')          // bloqueia event handlers
    .replace(/--/g, '')                  // bloqueia SQL comment
    .replace(/;\s*(?:DROP|ALTER|DELETE|INSERT|UPDATE|CREATE|TRUNCATE)/gi, '') // bloqueia SQL
    .replace(/UNION\s+SELECT/gi, '')     // bloqueia SQL UNION
    .replace(/\bOR\b\s+[\d'"]/gi, '')    // bloqueia SQL OR injection
    .replace(/\bAND\b\s+[\d'"]/gi, '')   // bloqueia SQL AND injection
    .replace(/\bUPDATE\b.*?\bSET\b/gi, '') // bloqueia UPDATE SET
    .replace(/;/g, '')                       // remove ponto-vírgula (stacked queries)
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // remove control chars
    .trim()
    .slice(0, 100);
}

function eSanitizePrompt(str) {
  if(!str) return '';
  return String(str)
    // Bloquear prompt injection direto
    .replace(/\[SYSTEM\]/gi, '[blocked]')
    .replace(/\[INST\]/gi, '[blocked]')
    .replace(/\[\/?SYS\]/gi, '[blocked]')
    .replace(/###\s*System/gi, '[blocked]')
    .replace(/###\s*Instruction/gi, '[blocked]')
    .replace(/Ignore (previous|all|above|prior) instructions/gi, '[blocked]')
    .replace(/Disregard (previous|all|above|prior)/gi, '[blocked]')
    .replace(/Forget (everything|all|previous|prior)/gi, '[blocked]')
    .replace(/Override (instructions|system|prompt|rules|directives|your|the|all)/gi, '[blocked]')
    .replace(/\bOverride\b/gi, '[blocked]')
    .replace(/OVERRIDE/g, '[blocked]')
    .replace(/IGNORE/g, '[blocked]')
    // Bloquear jailbreak patterns
    .replace(/You are now/gi, '[filtered]')
    .replace(/Pretend (you are|to be)/gi, '[filtered]')
    .replace(/Act as (a |an |if )/gi, '[filtered]')
    .replace(/Role.?play/gi, '[filtered]')
    .replace(/DAN mode/gi, '[filtered]')
    .replace(/jailbreak/gi, '[filtered]')
    .replace(/Do Anything Now/gi, '[filtered]')
    .replace(/developer mode/i, '[filtered]')
    .replace(/\bGPT-?[34]/gi, 'outro modelo')   // evitar comparações
    .replace(/reveal (your|the) (system |)(prompt|instructions)/gi, '[blocked]')
    // Remover HTML e código
    .replace(/<\/?[a-z][^>]*>/gi, '')           // HTML tags
    .replace(/\$\{[^}]*\}/g, '')               // template literals
    .replace(/`[^`]*`/g, '')                     // backtick blocks
    .replace(/\b(?:fetch|XMLHttpRequest|eval|Function)\s*\(/gi, '[blocked](') // JS injection
    // Limpar e limitar
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // control chars
    .trim()
    .slice(0, 500);
}

function eNorm(s) {
  return (s||'').toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g,'')
    .replace(/[^a-z0-9\s]/g,'').replace(/\s+/g,' ').trim();
}
// Aliases: nickname/abbreviation → normalized city name
const eALIASES = {
  'bh':'belo horizonte','bhz':'belo horizonte',
  'sp':'sao paulo','sampa':'sao paulo','gru':'sao paulo','cgh':'sao paulo',
  'rj':'rio de janeiro','rio':'rio de janeiro','gig':'rio de janeiro',
  'bsb':'brasilia','df':'brasilia',
  'cwb':'curitiba','ssa':'salvador','rec':'recife',
  'for':'fortaleza','mao':'manaus','bel':'belem',
  'goi':'goiania','cgr':'campo grande','the':'teresina',
  'poa':'porto alegre','sao':'sao luis','mcz':'maceio',
  'aju':'aracaju','nat':'natal','jpa':'joao pessoa',
  'vix':'vitoria','ubt':'ubatuba','cpc':'chapada diamantina',
  'nyc':'nova york','ny':'nova york','new york':'nova york',
  'la':'los angeles','lax':'los angeles',
  'ba':'buenos aires','baires':'buenos aires',
  'lon':'londres','london':'londres',
  'par':'paris','paris':'paris',
  'tok':'toquio','tokyo':'toquio',
  'rom':'roma','rome':'roma','mil':'milao',
  'bar':'barcelona','mad':'madrid',
  'ist':'istambul','istanbul':'istambul',
  'dub':'dubai',
};
function eFuzzySearch(q, limit=12) {
  const raw = eNorm(q);
  const resolved = eALIASES[raw] || raw;
  if(!resolved || resolved.length < 2) return [];
  const results = [];
  // Early exit: se já temos resultados suficientes com score alto, parar
  let foundExact = false;
  eAPS.forEach(a => {
    if(results.length >= limit * 2 && foundExact) return; // skip se temos suficientes
    const cityN   = eNorm(a.city);
    const nameN   = eNorm(a.name);
    const countryN= eNorm(a.country);
    const codeN   = (a.code||'').toLowerCase();
    const altN    = (a.alt||[]).map(eNorm);
    // Score: exact code match = 100, starts with = 80, includes = 60, alt = 50
    let score = 0;
    if(codeN === resolved) score = 100;
    else if(codeN.startsWith(resolved)) score = 85;
    else if(cityN === resolved) score = 90;
    else if(cityN.startsWith(resolved)) score = 80;
    else if(cityN.includes(resolved)) score = 70;
    else if(nameN.includes(resolved)) score = 60;
    else if(countryN.includes(resolved)) score = 40;
    else if(altN.some(alt => alt.includes(resolved))) score = 55;
    if(score > 0) results.push({...a, score: score});
  });
  return results.sort((a,b) => (b.score||0) - (a.score||0)).slice(0, limit);
}

function eHaversine(lat1,lng1,lat2,lng2){
  const R=6371,dLat=(lat2-lat1)*Math.PI/180,dLng=(lng2-lng1)*Math.PI/180;
  const a=Math.sin(dLat/2)**2+Math.cos(lat1*Math.PI/180)*Math.cos(lat2*Math.PI/180)*Math.sin(dLng/2)**2;
  return R*2*Math.atan2(Math.sqrt(a),Math.sqrt(1-a));
}

if(typeof module !== 'undefined') module.exports = { eSanitize, eSanitizeUrl, eSanitizeInt, eSanitizeCity, eSanitizePrompt, eNorm, eALIASES, eFuzzySearch, eHaversine };
