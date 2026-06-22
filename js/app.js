

// ══════════════════════════════════════════════════════════════
// IA GUARDRAILS — Anti-alucinação e filtros de segurança
// ══════════════════════════════════════════════════════════════

const eAIGuardrails = {
  // Frases que indicam alucinação ou resposta inválida
  hallucinationPatterns: [
    /voo direto de .+ para .+ (não existe|inexistente)/i,
    /como (IA|assistente), (não tenho|não posso)/i,
  ],

  // Frases proibidas na resposta (prompt injection tentado)
  forbiddenPatterns: [
    /ignore (previous|all|above)/i,
    /\[SYSTEM\]/i,
    /\[INST\]/i,
    /you are now/i,
    /pretend (you are|to be)/i,
    /jailbreak/i,
    /DAN mode/i,
  ],

  // Avisos que devem ser adicionados quando resposta parece inventada
  disclaimers: {
    prices: '⚠️ *Valores são estimativas — confirme sempre antes de comprar.*',
    flights: '⚠️ *Disponibilidade de voos sujeita a alteração.*',
    visa: '⚠️ *Requisitos de visto podem mudar — consulte o consulado.*',
  },

  validate(reply) {
    if(!reply) return { ok: false, reason: 'Resposta vazia' };

    // Verificar prompt injection na resposta
    for(const pattern of this.forbiddenPatterns) {
      if(pattern.test(reply)) {
        return { ok: false, reason: 'Resposta contém conteúdo bloqueado' };
      }
    }

    // Verificar comprimento mínimo (evitar respostas truncadas/inúteis)
    if(reply.trim().length < 50) {
      return { ok: false, reason: 'Resposta muito curta' };
    }

    // Verificar se a resposta está em português (básico)
    const ptWords = ['de', 'para', 'com', 'uma', 'dias', 'em', 'que'];
    const hasPT = ptWords.filter(w => reply.toLowerCase().includes(w)).length >= 3;
    if(!hasPT && reply.length > 200) {
      return { ok: true, warning: 'Resposta pode não estar em português' };
    }

    return { ok: true };
  },

  addDisclaimers(reply) {
    let result = reply;
    if(/€\d|R\$\d|\$\d|preço|custo|valor/i.test(reply)) {
      result += '\n\n' + this.disclaimers.prices;
    }
    if(/voo|passagem|aéreo/i.test(reply)) {
      result += '\n' + this.disclaimers.flights;
    }
    if(/visto|passaporte|vistos/i.test(reply)) {
      result += '\n' + this.disclaimers.visa;
    }
    return result;
  },

  sanitizeInput(userInput) {
    return eSanitizePrompt(userInput);
  }
};

// ══════════════════════════════════════════════════════════════
// SEGURANÇA — Sanitização de HTML contra XSS
// ══════════════════════════════════════════════════════════════

const _eSanitizeEl = document.createElement('div');

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

// Rate limiter simples para a IA
const _eRateLimiter = {
  calls: [],
  maxPerMinute: 5,
  check() {
    const now = Date.now();
    this.calls = this.calls.filter(t => now - t < 60000);
    if(this.calls.length >= this.maxPerMinute) return false;
    this.calls.push(now);
    return true;
  }
};

// CSP via meta tag (defence in depth)
(function() {
  if(!document.querySelector('meta[http-equiv="Content-Security-Policy"]')) {
    const csp = document.createElement('meta');
    csp.httpEquiv = 'Content-Security-Policy';
    csp.content = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdnjs.cloudflare.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com",
      "font-src https://fonts.gstatic.com",
      "img-src 'self' data: https://images.unsplash.com https://*.tile.openstreetmap.org https://*.basemaps.cartocdn.com",
      "connect-src 'self' https://nominatim.openstreetmap.org",
      "frame-src 'none'",
      "object-src 'none'",
    ].join('; ');
    document.head.appendChild(csp);
  }
})();


// ═══════════════════════════════════════════════════
// HERO PARTICLES (canvas)
// ═══════════════════════════════════════════════════
(function(){
  // Canvas desativado — substituído por CSS
  return;
  const canvas = document.getElementById('heroCanvas');
  if(!canvas) return;
  // Verificar se canvas é suportado
  let ctx; try { ctx = canvas.getContext('2d'); } catch(e){ return; }
  let W=1, H=1, particles=[], _rafId=null, _lastT=0, _stopped=false;
  function resize(){ W=canvas.width=window.innerWidth; H=canvas.height=window.innerHeight; }
  resize();
  window.addEventListener('resize', resize, {passive:true});
  // 18 partículas (era 55 — 67% menos trabalho)
  for(let i=0;i<18;i++) particles.push({x:Math.random()*1000,y:Math.random()*800,r:Math.random()*1.2+0.4,sx:(Math.random()-.5)*.22,sy:(Math.random()-.5)*.16,o:Math.random()*.28+.06});
  function draw(t){
    if(_stopped){ return; }
    _rafId = requestAnimationFrame(draw);
    // Throttle 20fps (era 60fps — 67% menos frames)
    if(t - _lastT < 50) return;
    _lastT = t;
    // Parar se aba oculta ou app aberto
    if(document.hidden) return;
    if(document.getElementById('appEmbed')?.classList.contains('on')) return;
    ctx.clearRect(0,0,W,H);
    for(let i=0;i<particles.length;i++){
      const p=particles[i];
      p.x+=p.sx; p.y+=p.sy;
      if(p.x<0||p.x>1000)p.sx*=-1;
      if(p.y<0||p.y>800)p.sy*=-1;
      ctx.beginPath();
      ctx.arc(p.x*W/1000,p.y*H/800,p.r,0,Math.PI*2);
      ctx.fillStyle=`rgba(255,255,255,${p.o})`;
      ctx.fill();
    }
    // Conexões: máx 40 pares (era ilimitado — O(n²))
    let n=0;
    outer: for(let i=0;i<particles.length-1;i++){
      for(let j=i+1;j<particles.length;j++){
        if(++n>40) break outer;
        const dx=(particles[i].x-particles[j].x)*W/1000,dy=(particles[i].y-particles[j].y)*H/800;
        const d2=dx*dx+dy*dy;
        if(d2<6400){
          ctx.beginPath();
          ctx.moveTo(particles[i].x*W/1000,particles[i].y*H/800);
          ctx.lineTo(particles[j].x*W/1000,particles[j].y*H/800);
          ctx.strokeStyle=`rgba(255,255,255,${.055*(1-Math.sqrt(d2)/80)})`;
          ctx.lineWidth=.5; ctx.stroke();
        }
      }
    }
  }
  // Iniciar com delay de 2s para não competir com o carregamento da página
  setTimeout(()=>{ _rafId=requestAnimationFrame(draw); }, 2000);
  // Parar quando app abre, retomar quando fecha
  // Parar quando hero não está visível
  if(typeof IntersectionObserver !== 'undefined'){
    const obs = new IntersectionObserver(([e])=>{ _stopped=!e.isIntersecting; if(!_stopped) _rafId=requestAnimationFrame(draw); }, {threshold:0.1});
    obs.observe(canvas);
  }
  document.addEventListener('appOpen', ()=>{ _stopped=true; cancelAnimationFrame(_rafId); });
  document.addEventListener('appClose', ()=>{ _stopped=false; _rafId=requestAnimationFrame(draw); });
})()

// ═══════════════════════════════════════════════════
// HERO SLIDESHOW
// ═══════════════════════════════════════════════════
const SLIDES_META = [
  {name:'Patagônia', country:'Argentina · América do Sul'},
  {name:'Colômbia', country:'América do Sul'},
  {name:'Islândia', country:'Europa · Aurora Boreal'},
  {name:'Nepal', country:'Ásia · Himalaia'},
  {name:'Marrocos', country:'África · Deserto'},
];
let curSlide = 0;
const slides = document.querySelectorAll('.hero-slide');
const dotsEl = document.getElementById('slideDots');
const progressBar = document.getElementById('progressBar');
let slideTimer, progressAnim;

slides.forEach((_,i) => {
  const d = document.createElement('div');
  d.className = 'sdot' + (i===0?' on':'');
  d.onclick = () => goSlide(i);
  dotsEl.appendChild(d);
});

function goSlide(n) {
  slides[curSlide].classList.remove('on');
  dotsEl.children[curSlide].classList.remove('on');
  curSlide = (n + slides.length) % slides.length;
  slides[curSlide].classList.add('on');
  dotsEl.children[curSlide].classList.add('on');
  const m = SLIDES_META[curSlide];
  document.getElementById('slideName').textContent = m.name;
  document.getElementById('slideCountry').textContent = m.country;
  startProgress();
}
function startProgress() {
  progressBar.style.transition = 'none';
  progressBar.style.width = '0%';
  void progressBar.offsetWidth;
  progressBar.style.transition = 'width 5s linear';
  progressBar.style.width = '100%';
}
function autoSlide() {
  clearInterval(slideTimer); // Evitar acúmulo
  slideTimer = setInterval(() => {
    // Não avançar se app estiver aberto
    if(!document.getElementById('appEmbed')?.classList.contains('on')){
      goSlide(curSlide + 1);
    }
  }, 5000);
}
startProgress(); autoSlide();

// Nav scroll
window.addEventListener('scroll', () => {
  document.getElementById('mainNav').classList.toggle('scrolled', window.scrollY > 50);
});

// Counter animation
// animateCounter definida abaixo (segunda versão mais rica)

const observer = new IntersectionObserver(entries => {
  entries.forEach(e => {
    if(e.isIntersecting) {
      animateCounter(document.getElementById('counterAI'), 18340);
      observer.disconnect();
    }
  });
});
const counterEl = document.getElementById('counterAI');
if(counterEl) observer.observe(counterEl.closest('.hbadge'));

// Scroll reveal micro-animations
const revealEls = document.querySelectorAll('.feat, .dest-card, .testi-card, .hiw-step, .perk');
const revealObserver = new IntersectionObserver((entries) => {
  entries.forEach((entry, i) => {
    if(entry.isIntersecting) {
      entry.target.style.animation = `fadeUp .55s ${i*0.06}s ease both`;
      entry.target.style.opacity = '0';
      setTimeout(() => { entry.target.style.opacity = ''; }, 50);
      revealObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.1 });
revealEls.forEach(el => revealObserver.observe(el));

// App open/close
function openApp(){ document.getElementById('appEmbed').classList.add('on'); document.dispatchEvent(new Event('appOpen'));
  setTimeout(function(){ if(window.L) eInitLeafletMap(); }, 500);
  setTimeout(eShowOnboarding, 500); document.body.style.overflow='hidden'; }
function closeApp(){ document.getElementById('appEmbed').classList.remove('on'); document.body.style.overflow=''; }
function openAppWith(city){
  openApp();
  setTimeout(()=>{
    let destObj = {input:city, ap:null, days:3, dist:0};
    // Primeiro tenta match direto
    const direct = eFuzzySearch(city,1);
    if(direct.length && direct[0].score>60) {
      destObj.ap = direct[0];
    } else {
      // Resolve via DB local ou Nominatim
      const resolved = eResolveCityToAirport(city);
      if(resolved) {
        destObj.ap = resolved.ap;
        destObj.dist = resolved.dist||0;
        destObj.city = resolved.city||null;
        if(!resolved.direct && resolved.dist>0) {
          etoast('\u{1F4CD} '+city+' \u2192 aeroporto mais pr\xF3ximo: '+resolved.ap.code+' ('+resolved.dist+' km)','ai');
        }
      }
    }
    if(eDests.length===1 && !eDests[0].input) {
      Object.assign(eDests[0], destObj);
    } else {
      eDests.push(destObj);
    }
    eRenderDests();
    etoast('\u{1F30D} '+city+' adicionado!','suc');
  },300);
}

// ═══════════════════════════════════════════════════
// CURRENCY — global + nav dropdown
// ═══════════════════════════════════════════════════
function eToggleCurrencyMenu(e) {
  e.stopPropagation();
  const el = document.getElementById('navCurrency');
  el.classList.toggle('open');
}
document.addEventListener('click', () => {
  const el = document.getElementById('navCurrency');
  if(el) el.classList.remove('open');
});

function eSetCurrencyGlobal(code, symbol, flag, e) {
  if(e) e.stopPropagation();
  eCurrency = code;
  eCurrencySymbol = symbol;
  eStorage.autoSave();
  // Update nav display
  const flagEl = document.getElementById('navCurrencyFlag');
  const codeEl = document.getElementById('navCurrencyCode');
  if(flagEl) flagEl.textContent = flag;
  if(codeEl) codeEl.textContent = code;
  // Highlight active item
  document.querySelectorAll('.ncm-item').forEach(el => el.classList.remove('active'));
  if(e && e.target) e.target.closest('.ncm-item')?.classList.add('active');
  // Close menu
  document.getElementById('navCurrency')?.classList.remove('open');
  // Also update nav currency display
  // Re-render everything with new currency
  if(typeof eRouteDone !== 'undefined' && eRouteDone) {
    eRenderResults();
    // Re-run TSP display if results exist
    const tspEl = document.getElementById('etspVersions');
    if(tspEl && tspEl.querySelector('.algo-card, [onclick*="eApplyNN"]')) {
      erunTSPFull();
    }
  }
  // Update budget tab
  eUpdateBudgetDisplay();
  // Update homepage SB
  if(typeof eUpdateHomeSB === 'function') eUpdateHomeSB();
  etoast(`${flag} ${code} — ${(eCurrencyRates[code]||{}).name||code}`, 'suc');
}

function eUpdateBudgetDisplay() {
  // Re-render budget tab values with new currency
  const slider = document.querySelector('#etab-budget input[type=range]');
  if(slider) {
    const eurVal = parseFloat(slider.value) / (eCurrencyRates['EUR']?.rate || 1) * (eCurrencyRates[eCurrency]?.rate || 1);
    // update display
    const display = slider.nextElementSibling;
    if(display) display.textContent = eFmtPrice(parseFloat(slider.value) / (eCurrencyRates[eCurrency]?.rate || 1));
  }
}

// ═══════════════════════════════════════════════════
// SEARCH HUB — homepage editável (Rome2Rio style)
// ═══════════════════════════════════════════════════
let _shubAdults = 1;
let _shubChildren = 0;
let _shubChildAges = [];
let _shubOriginAp = null;
let _shubDestAp = null;
let _shubDays = 7;
let _shubStartDate = null;



function eShubAC(field, q) {
  const acEl = document.getElementById(`shub${field==='origin'?'Origin':'Dest'}AC`);
  if(!acEl) return;
  if(!q || q.length < 2) { acEl.classList.remove('open'); return; }

  const results = eFuzzySearch(q, 8);

  // Cidades sem aeroporto
  const qN = eNormCity(q);
  const cityResults = [];
  if(typeof eCityDB !== 'undefined') {
    for(const [key, city] of Object.entries(eCityDB)) {
      const kN = eNormCity(key);
      const nameN = eNormCity(city.name||'');
      if(kN.startsWith(qN.slice(0,2)) || nameN.startsWith(qN.slice(0,2)) || kN.includes(qN) || nameN.includes(qN)) {
        cityResults.push({...city, _key: key});
        if(cityResults.length >= 3) break;
      }
    }
  }

  if(!results.length && !cityResults.length) {
    acEl.innerHTML = `<div class="shub-ac-group">📍 Qualquer destino</div>
      <div class="shub-ac-row" onclick="eShubSelectCity(this,'${field}','${q.replace(/'/g,"\\'")}',null,null)">
        <div class="shub-ac-code" style="background:var(--coral-pale);color:var(--coral)">📍</div>
        <div><span class="shub-ac-name">${q}</span><span class="shub-ac-city"> — buscar aeroporto mais próximo</span></div>
      </div>`;
    acEl.classList.add('open');
    return;
  }

  let html_out = '';

  // Cidades sem aeroporto
  if(cityResults.length) {
    html_out += `<div class="shub-ac-group">📍 Cidades — aeroporto mais próximo</div>`;
    cityResults.forEach(c => {
      html_out += `<div class="shub-ac-row" onclick="eShubSelectCity(this,'${field}','${(c.name||'').replace(/'/g,"\\'")}',${c.lat||'null'},${c.lng||'null'})">
        <div class="shub-ac-code" style="background:var(--coral-pale);color:var(--coral);border-color:rgba(240,90,40,.2)">📍</div>
        <div>
          <span class="shub-ac-name">${c.name||''}</span>
          <span class="shub-ac-city">${c.state||''} · ${c.country||''}</span>
        </div>
      </div>`;
    });
  }

  // Aeroportos
  if(results.length) {
    const groups = {};
    results.forEach(a => {
      if(!groups[a.country]) groups[a.country] = [];
      groups[a.country].push(a);
    });
    Object.entries(groups).forEach(([country, aps]) => {
      html_out += `<div class="shub-ac-group">${aps[0].flag||''} ${country}</div>`;
      aps.forEach(a => {
        html_out += `<div class="shub-ac-row" onclick="eShubSelect('${field}','${a.code}')">
          <div class="shub-ac-code">${a.code}</div>
          <div>
            <span class="shub-ac-name">${a.city}</span>
            <span class="shub-ac-city">${a.name}</span>
          </div>
        </div>`;
      });
    });
  }

  acEl.innerHTML = html_out;
  acEl.classList.add('open');
}

function eShubSelect(field, code) {
  const ap = eAPS.find(a => a.code === code);
  if(!ap) return;
  if(field === 'origin') {
    _shubOriginAp = ap;
    document.getElementById('shubOriginInput').value = ap.city;
    document.getElementById('shubOriginTag').innerHTML = `<span style="background:rgba(74,124,53,.12);color:var(--fern);padding:1px 6px;border-radius:4px;font-weight:700">${ap.code}</span> ${ap.flag} ${ap.country}`;
    document.getElementById('shubOriginAC').classList.remove('open');
  } else {
    _shubDestAp = ap;
    document.getElementById('shubDestInput').value = ap.city;
    document.getElementById('shubDestTag').innerHTML = `<span style="background:rgba(74,124,53,.12);color:var(--fern);padding:1px 6px;border-radius:4px;font-weight:700">${ap.code}</span> ${ap.flag} ${ap.country}`;
    document.getElementById('shubDestAC').classList.remove('open');
  }
  eShubUpdatePlanBtn();
}

function eShubFocus(field) {}
function eShubBlur(field) {
  setTimeout(() => {
    document.getElementById(`shub${field==='origin'?'Origin':'Dest'}AC`).classList.remove('open');
  }, 200);
}

function eShubSwap() {
  const tmpAp = _shubOriginAp;
  _shubOriginAp = _shubDestAp;
  _shubDestAp = tmpAp;
  const originInput = document.getElementById('shubOriginInput');
  const destInput = document.getElementById('shubDestInput');
  const tmpVal = originInput.value;
  originInput.value = destInput.value;
  destInput.value = tmpVal;
  const originTag = document.getElementById('shubOriginTag').innerHTML;
  document.getElementById('shubOriginTag').innerHTML = document.getElementById('shubDestTag').innerHTML;
  document.getElementById('shubDestTag').innerHTML = originTag;
}

function eShubOpenDate() {
  eShubCloseAll();
  const picker = document.getElementById('shubDatePicker');
  picker.classList.toggle('open');
  // pre-fill today if empty
  const s = document.getElementById('shubDateStart');
  if(!s.value) {
    const now = new Date();
    s.value = now.toISOString().split('T')[0];
    const end = new Date(now.getTime() + _shubDays * 86400000);
    document.getElementById('shubDateEnd').value = end.toISOString().split('T')[0];
    eShubDateChange();
  }
}
function eShubDateChange() {
  const s = document.getElementById('shubDateStart');
  const e = document.getElementById('shubDateEnd');
  if(s.value && e.value) {
    _shubStartDate = new Date(s.value);
    const endDate = new Date(e.value);
    _shubDays = Math.max(1, Math.round((endDate - _shubStartDate) / 86400000));
    const fmt = d => d.toLocaleDateString('pt-BR', {day:'2-digit', month:'short'});
    document.getElementById('shubDateVal').textContent = `${fmt(_shubStartDate)} → ${fmt(endDate)} · ${_shubDays}d`;
    document.getElementById('shubDateVal').classList.remove('ph');
  }
}
function eShubQuick(days, e) {
  _shubDays = days;
  const now = new Date();
  const end = new Date(now.getTime() + days * 86400000);
  document.getElementById('shubDateStart').value = now.toISOString().split('T')[0];
  document.getElementById('shubDateEnd').value = end.toISOString().split('T')[0];
  _shubStartDate = now;
  const fmt = d => d.toLocaleDateString('pt-BR', {day:'2-digit', month:'short'});
  document.getElementById('shubDateVal').textContent = `${fmt(now)} → ${fmt(end)} · ${days}d`;
  document.getElementById('shubDateVal').classList.remove('ph');
  document.querySelectorAll('.shub-quick').forEach(b => b.classList.remove('on'));
  if(e && e.target) e.target.classList.add('on');
}

function eShubOpenTravelers() {
  eShubCloseAll();
  document.getElementById('shubTravPicker').classList.toggle('open');
}
function eShubAdj(type, delta) {
  if(type === 'adult') {
    _shubAdults = Math.max(1, _shubAdults + delta);
    document.getElementById('shubAdultCount').textContent = _shubAdults;
  } else {
    _shubChildren = Math.max(0, _shubChildren + delta);
    document.getElementById('shubChildCount').textContent = _shubChildren;
    eShubRenderChildAges();
  }
  eShubUpdateTravelerVal();
}
function eShubRenderChildAges() {
  const container = document.getElementById('shubChildAges');
  if(_shubChildren === 0) { container.style.display = 'none'; return; }
  container.style.display = 'block';
  // Resize array
  while(_shubChildAges.length < _shubChildren) _shubChildAges.push(0);
  _shubChildAges = _shubChildAges.slice(0, _shubChildren);
  container.innerHTML = `<div style="font-size:.65rem;font-weight:700;color:var(--mist);letter-spacing:.07em;text-transform:uppercase;margin-bottom:8px">Idades das crianças</div>` +
    _shubChildAges.map((age, i) =>
      `<div class="shub-age-row">Criança ${i+1}: 
       <input class="shub-age-input" type="number" min="0" max="17" value="${age}"
         oninput="_shubChildAges[${i}]=Math.min(17,Math.max(0,parseInt(this.value)||0));eShubUpdateTravelerVal()">
       anos</div>`
    ).join('');
}
function eShubUpdateTravelerVal() {
  let txt = _shubAdults === 1 ? '1 adulto' : `${_shubAdults} adultos`;
  if(_shubChildren > 0) txt += `, ${_shubChildren} criança${_shubChildren>1?'s':''}`;
  const el = document.getElementById('shubTravVal');
  if(el) { el.textContent = txt; el.classList.remove('ph'); }
  eShubUpdatePlanBtn();
}

function eShubOpenProfile() {
  eShubCloseAll();
  document.getElementById('shubProfilePicker').classList.toggle('open');
}
function eShubSetProfile(btn, profile) {
  document.querySelectorAll('.shub-prof-btn').forEach(b => b.classList.remove('on'));
  btn.classList.add('on');
  const labels = {mochileiro:'🎒 Mochileiro',economico:'💸 Econômico',comfort:'🏨 Conforto',luxury:'✨ Luxo',familia:'👨‍👩‍👧 Família',aventura:'🏔️ Aventura',gastro:'🍽️ Gastronômico',cultural:'🏛️ Cultural'};
  const el = document.getElementById('shubProfileVal');
  if(el) { el.textContent = labels[profile] || profile; el.classList.remove('ph'); }
  eProfileType = profile;
  // Also sync app profile badges
  document.querySelectorAll('.epbadge-item').forEach(b => {
    b.classList.toggle('on', b.onclick?.toString().includes(`'${profile}'`));
  });
  document.getElementById('shubProfilePicker')?.classList.remove('open');
}

function eShubCloseAll() {
  ['shubDatePicker','shubTravPicker','shubProfilePicker','shubOriginAC','shubDestAC'].forEach(id => {
    document.getElementById(id)?.classList.remove('open');
  });
}
document.addEventListener('click', e => {
  if(!e.target.closest('#searchHub')) eShubCloseAll();
});

function eShubUpdatePlanBtn() {
  const btn = document.getElementById('shubPlanBtn');
  if(!btn) return;
  const hasOrigin = _shubOriginAp || document.getElementById('shubOriginInput')?.value?.length > 1;
  const hasDest   = _shubDestAp   || document.getElementById('shubDestInput')?.value?.length > 1;
  const ready = hasOrigin && hasDest;
  btn.style.opacity = ready ? '1' : '0.65';
}

// ═══════════════════════════════════════════════════
// SEARCH HUB — simplified homepage (only origin + dests)
// ═══════════════════════════════════════════════════
let _shubExtraDests = []; // [{input, ap}]

function eShubAddDest() {
  const idx = _shubExtraDests.length;
  _shubExtraDests.push({input:'', ap:null});
  eShubRenderExtraDests();
  // Focus the new input
  setTimeout(() => {
    const inputs = document.querySelectorAll('.shub-extra-input');
    if(inputs[idx]) inputs[idx].focus();
  }, 50);
  // Show the extra row
  document.getElementById('shubExtraRow').style.display = 'flex';
  // Show remove on dest if we now have extras
  eShubUpdatePlanBtn();
}

function eShubRenderExtraDests() {
  const row = document.getElementById('shubExtraRow');
  if(!row) return;
  if(_shubExtraDests.length === 0) { row.style.display = 'none'; row.innerHTML = ''; return; }
  row.style.display = 'flex';
  row.innerHTML = _shubExtraDests.map((d, i) => `
    <div class="shub-extra-dest" id="shubExtra_${i}">
      <div class="shub-label" style="white-space:nowrap;margin-right:4px">📍 Parada ${i+2}</div>
      <input class="shub-input shub-extra-input" placeholder="Adicionar destino…"
        value="${d.input}" autocomplete="off"
        oninput="eShubExtraInput(${i},this.value)"
        onblur="setTimeout(()=>document.getElementById('shubExtraAC_${i}')?.classList.remove('open'),200)">
      <div class="shub-ac" id="shubExtraAC_${i}"></div>
      ${d.ap ? `<div style="font-size:.67rem;color:var(--fern);font-weight:600;white-space:nowrap">
        <span style="background:rgba(74,124,53,.12);padding:1px 5px;border-radius:4px">${d.ap.code}</span> ${d.ap.flag}
      </div>` : ''}
      <button class="shub-extra-remove" onclick="eShubRemoveDest(${i})">×</button>
    </div>
  `).join('');
}

function eShubExtraInput(idx, q) {
  _shubExtraDests[idx].input = q;
  _shubExtraDests[idx].ap = null;
  const acEl = document.getElementById(`shubExtraAC_${idx}`);
  if(!acEl) return;
  if(!q || q.length < 2) { acEl.classList.remove('open'); return; }
  const results = eFuzzySearch(q, 8);
  if(!results.length) { acEl.innerHTML = `<div class="shub-ac-empty">Nenhum resultado</div>`; acEl.classList.add('open'); return; }
  const grouped = {};
  results.forEach(a => { if(!grouped[a.country]) grouped[a.country]=[]; grouped[a.country].push(a); });
  let html = '';
  Object.keys(grouped).forEach(country => {
    html += `<div class="shub-ac-group">${grouped[country][0].flag} ${country}</div>`;
    grouped[country].forEach(a => {
      html += `<div class="shub-ac-row" onclick="eShubSelectExtra(${idx},'${a.code}')">
        <span class="shub-ac-code">${a.code}</span>
        <div><div class="shub-ac-name">${a.name}</div><div class="shub-ac-city">${a.flag} ${a.city}</div></div>
      </div>`;
    });
  });
  acEl.innerHTML = html;
  acEl.classList.add('open');
}

function eShubSelectExtra(idx, code) {
  const ap = eAPS.find(a => a.code === code);
  if(!ap) return;
  _shubExtraDests[idx] = {input: ap.city, ap};
  eShubRenderExtraDests();
  eShubUpdatePlanBtn();
}

function eShubRemoveDest(idx) {
  _shubExtraDests.splice(idx, 1);
  eShubRenderExtraDests();
  eShubUpdatePlanBtn();
}

function eShubPlan() {
  // Build eDests: origin + all extras + last dest as return (optional)
  const newDests = [];
  
  // Origin
  newDests.push({
    input: _shubOriginAp ? _shubOriginAp.city : (document.getElementById('shubOriginInput')?.value || ''),
    ap: _shubOriginAp,
    days: 0
  });
  
  // Extra intermediate destinations
  _shubExtraDests.forEach(d => {
    if(d.ap || d.input) newDests.push({input: d.input, ap: d.ap, days: 3});
  });
  
  // Main destination
  if(_shubDestAp || document.getElementById('shubDestInput')?.value) {
    newDests.push({
      input: _shubDestAp ? _shubDestAp.city : document.getElementById('shubDestInput').value,
      ap: _shubDestAp,
      days: 3
    });
  }
  
  // Final return (same as origin)
  if(newDests.length >= 2) {
    newDests.push({input: newDests[0].input, ap: newDests[0].ap, days: 0});
  }
  
  // Transfer to app state
  if(newDests.length >= 2) {
    eDests = newDests;
  }
  
  // Open the app (page 2) — dates/travelers/profile set there
  openApp();
  
  // Render destinations in app
  setTimeout(() => {
    eRenderDests();
    eUpdateTravelerBar();
  }, 300);
}




function eUpdateHomeSB() {
  // Origin
  const origin = eDests[0];
  const sbO = document.getElementById('sbOriginVal');
  if(sbO) {
    if(origin?.ap) {
      sbO.textContent = `${origin.ap.flag} ${origin.ap.city}`;
      sbO.classList.remove('ph');
    } else {
      sbO.textContent = 'De onde você vai?';
      sbO.classList.add('ph');
    }
  }
  // Destinations
  const sbD = document.getElementById('sbDestVal');
  if(sbD) {
    const dests = eDests.slice(1,-1).filter(d=>d.ap);
    if(dests.length > 0) {
      sbD.textContent = dests.slice(0,3).map(d=>d.ap.city).join(' → ') + (dests.length>3?` +${dests.length-3}`:'');
      sbD.classList.remove('ph');
    } else {
      sbD.textContent = 'Para onde?';
      sbD.classList.add('ph');
    }
  }
  // Date
  const sbDt = document.getElementById('sbDateVal');
  if(sbDt) {
    const days = eTotDays();
    if(days && days > 0) {
      const start = eStartDate;
      const end = new Date(start.getTime() + days*86400000);
      const fmt = d => d.toLocaleDateString('pt-BR',{day:'2-digit',month:'short'});
      sbDt.textContent = `${fmt(start)} → ${fmt(end)} (${days}d)`;
      sbDt.classList.remove('ph');
    } else {
      sbDt.textContent = 'Quando você vai?';
      sbDt.classList.add('ph');
    }
  }
  // Travelers
  const sbT = document.getElementById('sbTravVal');
  if(sbT && typeof eTravelers !== 'undefined') {
    const n = eTravelers.length;
    const kids = eTravelers.filter(t=>t.tipo==='crianca').length;
    let txt = n === 1 ? '1 viajante' : `${n} viajantes`;
    if(kids > 0) txt += ` · ${kids} criança${kids>1?'s':''}`;
    sbT.textContent = txt;
    sbT.classList.remove('ph');
  }
}

function openAppFrom(focus) {
  openApp();
  // After app opens, focus the relevant section
  setTimeout(() => {
    if(focus === 'origin' || focus === 'dest') {
      const inputs = document.querySelectorAll('.edinput');
      const target = focus === 'origin' ? inputs[0] : inputs[1];
      if(target) { target.focus(); target.select(); }
    } else if(focus === 'date') {
      eSwitchDateMode('manual', document.querySelectorAll('.edmode')[1]);
    } else if(focus === 'travelers') {
      openTravelerModal();
    }
  }, 400);
}


// ═══════════════════════════════════════════════════
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

// ═══════════════════════════════════════════════════
// AIRPORT DATA — 200+ airports
// ═══════════════════════════════════════════════════

// Airport data loaded from js/airports.js
// City data loaded from js/cities.js



// ═══════════════════════════════════════════════════
// APP STATE
// ═══════════════════════════════════════════════════
let eDests = [
  {input:'', ap:null, days:0},
  {input:'', ap:null, days:3},
  {input:'', ap:null, days:0},
];
let eSelTr = {};
let eRouteDone = false;
let eSelAlgo = 'nn';
let eStartDate = new Date();
const eQuickDur = {'1w':7,'2w':14,'1m':30,'weekend':3};
let eCurDur = 7;

// Traveler & profile state — declared early to avoid TDZ errors
let eTravelers = [{name:'Você',role:'🎒 Mochileiro',emoji:'🎒',tipo:'adulto'}];
let eSelectedRole = '🎒 Mochileiro';
let eProfileType = 'mochileiro';
let eTravelerProfile = 'mochileiro';

// ═══════════════════════════════════════════════════
// PERSISTENCE — localStorage auto-save/restore
// ═══════════════════════════════════════════════════
const eStorage = {
  _key: 'nomadroute_state',
  _version: 1,

  save() {
    try {
      const state = {
        v: this._version,
        ts: Date.now(),
        dests: eDests.map(d => ({
          input: d.input || '',
          days: d.days || 0,
          apCode: d.ap ? d.ap.code : null,
          dist: d.dist || 0,
          cityKey: d.city ? (d.city._key || d.city.name || '') : ''
        })),
        travelers: eTravelers,
        profileType: eProfileType,
        travelerProfile: eTravelerProfile,
        currency: typeof eCurrency !== 'undefined' ? eCurrency : 'BRL',
        curDur: eCurDur,
        selAlgo: eSelAlgo,
      };
      localStorage.setItem(this._key, JSON.stringify(state));
    } catch(e) { /* quota exceeded or private mode */ }
  },

  load() {
    try {
      const raw = localStorage.getItem(this._key);
      if (!raw) return false;
      const state = JSON.parse(raw);
      if (!state || state.v !== this._version) return false;
      // Stale after 30 days
      if (Date.now() - state.ts > 30 * 86400000) {
        this.clear();
        return false;
      }

      if (state.travelers && state.travelers.length > 0) {
        eTravelers = state.travelers;
      }
      if (state.profileType) eProfileType = state.profileType;
      if (state.travelerProfile) eTravelerProfile = state.travelerProfile;
      if (state.curDur) eCurDur = state.curDur;
      if (state.selAlgo) eSelAlgo = state.selAlgo;

      if (state.dests && state.dests.length > 0) {
        eDests = state.dests.map(d => {
          const ap = d.apCode ? eAPS.find(a => a.code === d.apCode) : null;
          let city = null;
          if (d.cityKey && typeof eCityDB !== 'undefined') {
            city = eCityDB[d.cityKey.toLowerCase()] || null;
          }
          return {
            input: d.input || '',
            ap: ap || null,
            days: d.days || 0,
            dist: d.dist || 0,
            city: city
          };
        });
      }
      return true;
    } catch(e) { return false; }
  },

  clear() {
    try { localStorage.removeItem(this._key); } catch(e) {}
  },

  _debounceTimer: null,
  autoSave() {
    clearTimeout(this._debounceTimer);
    this._debounceTimer = setTimeout(() => this.save(), 500);
  }
};

function setEQuick(el,key) {
  document.querySelectorAll('.eqd').forEach(q=>q.classList.remove('on'));
  el.classList.add('on');
  eCurDur = eQuickDur[key]||7;
  eUpdateSum();
  if(typeof eUpdateHomeSB === 'function') eUpdateHomeSB();
}

// ═══════════════════════════════════════════════════
// DATE MODE SWITCHING
// ═══════════════════════════════════════════════════
let eDateMode = 'quick';

function eSwitchDateMode(mode, el) {
  eDateMode = mode;
  // Update tab styles
  el.parentNode.querySelectorAll('.edmode').forEach(d => d.classList.remove('on'));
  el.classList.add('on');
  // Show/hide panels
  document.getElementById('edm-quick').style.display  = mode==='quick'  ? 'flex' : 'none';
  document.getElementById('edm-manual').style.display = mode==='manual' ? 'block' : 'none';
  document.getElementById('edm-flex').style.display   = mode==='flex'   ? 'block' : 'none';
  // Pre-fill manual inputs with current date range
  if(mode === 'manual') {
    const s = document.getElementById('eDateStart');
    const e = document.getElementById('eDateEnd');
    if(!s.value) {
      const now = new Date();
      const end = new Date(now.getTime() + eCurDur * 86400000);
      s.value = now.toISOString().split('T')[0];
      e.value = end.toISOString().split('T')[0];
      eManualDateChange();
    }
  }
}

function eManualDateChange() {
  const s = document.getElementById('eDateStart');
  const e = document.getElementById('eDateEnd');
  const info = document.getElementById('eManualDateInfo');
  if(!s || !e) return;
  if(s.value && e.value) {
    const start = new Date(s.value);
    const end   = new Date(e.value);
    if(end <= start) {
      info.style.color = 'var(--eember)';
      info.textContent = '⚠️ Data de fim deve ser após o início';
      return;
    }
    const days = Math.round((end - start) / 86400000);
    eStartDate = start;
    eCurDur = days;
    info.style.color = 'var(--egreen2)';
    info.textContent = `✅ ${days} dias · ${start.toLocaleDateString('pt-BR',{day:'2-digit',month:'short'})} → ${end.toLocaleDateString('pt-BR',{day:'2-digit',month:'short'})}`;
    eUpdateSum();
    if(typeof eUpdateHomeSB === 'function') eUpdateHomeSB();
  }
}

let eFlexMonthsSel = new Set();
function eToggleFlexMonth(btn, month) {
  btn.classList.toggle('on');
  if(eFlexMonthsSel.has(month)) eFlexMonthsSel.delete(month);
  else eFlexMonthsSel.add(month);
}

function eTotDays() {

  return eDests.reduce((a,d)=>a+d.days,0)||eCurDur;
}
function eUpdateSum() {
  const n = eDests.filter(d=>d.ap).length;
  const days = eTotDays();
  const end = new Date(eStartDate.getTime() + days*86400000);
  const fmt = d => d.toLocaleDateString('pt-BR',{day:'2-digit',month:'short'});
  document.getElementById('etsmC').textContent = n||'—';
  document.getElementById('etsmD').textContent = days||'—';
  document.getElementById('etsmS').textContent = n?fmt(eStartDate):'—';
  document.getElementById('etsmE').textContent = n?fmt(end):'—';
}

// ═══════════════════════════════════════════════════
// RENDER DESTINATIONS LIST
// ═══════════════════════════════════════════════════
function eRenderDests() {
  eStorage.autoSave();
  const list = document.getElementById('edlist');
  list.innerHTML = '';
  eDests.forEach((d, i) => {
    const isFirst = i===0, isLast = i===eDests.length-1;
    const dotCls = isFirst?'org':isLast?'fin':'';
    const dotLbl = isFirst?'🟢':isLast?'🔴':'○';
    const div = document.createElement('div');
    div.className = 'editem';
    div.draggable = true;
    div.dataset.idx = i;
    div.innerHTML = `
      <div class="edrag-handle" title="Arrastar">⠿</div>
      <div class="edconn">
        <div class="eddot ${dotCls}">${dotLbl}</div>
        ${!isLast?'<div class="edline"></div>':''}
      </div>
      <div class="edinput-col">
        <div class="edinput-row">
          <input class="edinput" placeholder="${isFirst?'De onde você parte?':isLast?'Onde você chega?':'Parada '+i+' — qual cidade?'}"
            value='${eSanitize(d.input).replace(/'/g, "&#39;")}' oninput="eOnInput(this,${i})" onfocus="eShowAC(${i})" onblur="var _i=${i};setTimeout(function(){var d=document.getElementById('eac'+_i);if(d)d.classList.remove('open');},200)" autocomplete="off">
          ${!isFirst&&!isLast?`<div class="edays-wrap">
            <button class="edays-btn" onclick="eDaysAdj(${i},-1)">-</button>
            <div class="edays-val">${d.days}</div>
            <button class="edays-btn" onclick="eDaysAdj(${i},+1)">+</button>
            <div class="edays-lbl">n</div>
          </div>`:''}
          ${!isFirst&&!isLast?`<button class="edremove" onclick="eRemDest(${i})">×</button>`:''}
        </div>
        <div class="eacdrop" id="eac${i}"></div>
        ${d.ap ? (d.dist>0 ? `<div class="eaptag eaptag-near"><span class="eapcode eapcode-near">${d.ap.code}</span>\uD83D\uDCCD ${d.city?d.city.name:d.ap.city} \u2192 \u2708\uFE0F ${d.ap.code} \u00B7 ${d.dist} km</div>` : `<div class="eaptag"><span class="eapcode">${d.ap.code}</span>${d.ap.flag} ${d.ap.city} \u00B7 ${d.ap.country}</div>`) : `<div class="eaptag eaptag-pending">\u23F3 Digite para buscar...</div>`}
      </div>`;
    // Drag events
    div.addEventListener('dragstart', e => {
      e.dataTransfer.setData('text/plain', i);
      setTimeout(()=>div.classList.add('dragging'),0);
    });
    div.addEventListener('dragend', () => div.classList.remove('dragging'));
    div.addEventListener('dragover', e => { e.preventDefault(); div.classList.add('drag-over'); });
    div.addEventListener('dragleave', () => div.classList.remove('drag-over'));
    div.addEventListener('drop', e => {
      e.preventDefault(); div.classList.remove('drag-over');
      const from = parseInt(e.dataTransfer.getData('text/plain'));
      const to = parseInt(div.dataset.idx);
      if(from!==to){ const tmp=eDests[from]; eDests[from]=eDests[to]; eDests[to]=tmp; eRenderDests(); }
    });
    list.appendChild(div);
  });
  eUpdateSum();
  if(typeof eUpdateHomeSB === 'function') eUpdateHomeSB();
}

function eDaysAdj(i,delta){
  eDests[i].days = Math.max(0, eDests[i].days+delta);
  eRenderDests();
}
function eRemDest(i){ eDests.splice(i,1); eRenderDests(); }
function eaddDest(){
  eDests.splice(eDests.length-1,0,{input:'',ap:null,days:3});
  eRenderDests();
  setTimeout(()=>{
    const inputs=document.querySelectorAll('.edinput');
    if(inputs[eDests.length-2]) inputs[eDests.length-2].focus();
  },50);
}

// ═══════════════════════════════════════════════════
// AUTOCOMPLETE
// ═══════════════════════════════════════════════════
let eAcOpen = -1;
function eOnInput(inp, i) {
  var raw = inp.value;
  var safe = eSanitizeCity(raw);
  if(raw !== safe) inp.value = safe;
  eDests[i].input = safe;
  eDests[i].ap = null;
  eDests[i].dist = 0;
  eShowAC(i);
}
function eShowAC(i) {
  clearTimeout(window._acTimer);
  window._acTimer = setTimeout(function(){ _eShowACNow(i); }, 80);
}
function _eShowACNow(i) {
  const inp = document.querySelectorAll('.edinput')[i];
  if(!inp) return;
  const q = inp.value.trim();
  const drop = document.getElementById('eac'+i);
  if(!drop) return;
  if(!q || q.length < 2) { drop.classList.remove('open'); return; }
  // Cache: não re-renderizar se a query não mudou

  // Resultados de aeroportos
  const apResults = eFuzzySearch(q, 8);

  // Resultados de cidades sem aeroporto (eCityDB)
  const qN = eNormCity(q);
  const cityResults = [];
  if(typeof eCityDB !== 'undefined') {
    for(const [key, city] of Object.entries(eCityDB)) {
      const kN = eNormCity(key);
      const nameN = eNormCity(city.name||'');
      if(kN.startsWith(qN.slice(0,2)) || nameN.startsWith(qN.slice(0,2)) ||
         kN.includes(qN) || nameN.includes(qN)) {
        cityResults.push(city);
        if(cityResults.length >= 4) break;
      }
    }
  }

  if(!apResults.length && !cityResults.length) {
    drop.innerHTML = `<div style="color:var(--slate);padding:10px 14px;font-size:.78rem">
      Nenhum aeroporto encontrado para "<b>${eSanitize(q)}</b>"<br>
      <span style="font-size:.7rem;color:var(--sky)">Digite para buscar qualquer cidade — encontramos o aeroporto mais próximo automaticamente</span>
    </div>
    <div style="padding:8px 14px">
      <div class="eacrow" onmousedown="event.preventDefault();eAcSelectCity(${i},this.dataset.city,this.dataset.lat,this.dataset.lng)" data-city="${q.replace(/'/g,"\\'")}" style="background:var(--sky-ghost);border-radius:var(--radius-sm)">
        <div class="eaccode" style="background:var(--coral-pale);color:var(--coral);border-color:rgba(240,90,40,.2)">📍</div>
        <div><div class="eacname">${eSanitize(q)}</div><div class="eaccity">Buscar aeroporto mais próximo</div></div>
      </div>
    </div>`;
    drop.classList.add('open');
    return;
  }

  let html_out = '';

  // Cidades sem aeroporto primeiro (mais relevante para busca geral)
  if(cityResults.length) {
    html_out += `<div class="eacgroup">📍 Cidades — aeroporto mais próximo</div>`;
    cityResults.forEach(city => {
      html_out += `<div class="eacrow" onmousedown="event.preventDefault();eAcSelectCity(${i},this.dataset.city,this.dataset.lat,this.dataset.lng)" data-city="${(city.name||'').replace(/'/g,"\\'")}">
        <div class="eaccode" style="background:var(--coral-pale);color:var(--coral);border-color:rgba(240,90,40,.2)">📍</div>
        <div>
          <div class="eacname">${city.name||''}</div>
          <div class="eaccity">${city.state||''} · ${city.country||''} · aeroporto mais próximo automático</div>
        </div>
      </div>`;
    });
  }

  // Aeroportos
  if(apResults.length) {
    const grouped = {};
    apResults.forEach(a => {
      if(!grouped[a.country]) grouped[a.country] = [];
      grouped[a.country].push(a);
    });
    Object.entries(grouped).forEach(([country, aps]) => {
      html_out += `<div class="eacgroup">${aps[0].flag||''} ${country}</div>`;
      aps.forEach(a => {
        html_out += `<div class="eacrow" onmousedown="event.preventDefault();eAcSelect(${i},'${a.code}')">
          <div class="eaccode">${a.code}</div>
          <div>
            <div class="eacname">${eSanitize(a.city)}</div>
            <div class="eaccity">${eSanitize(a.name)}</div>
          </div>
        </div>`;
      });
    });
  }

  drop.innerHTML = html_out;
  drop.classList.add('open');
}
function eSelAC(i, code) {
  const ap = eAPS.find(a=>a.code===code);
  if(!ap) return;
  eDests[i].input = ap.city;
  eDests[i].ap = ap;
  const drop = document.getElementById('eac'+i);
  if(drop) drop.classList.remove('open');
  eRenderDests();
  eUpdateSum();
}
document.addEventListener('click', e => {
  if(!e.target.closest('.edinput-col')) {
    document.querySelectorAll('.eacdrop').forEach(d=>d.classList.remove('open'));
  }
});

// ═══════════════════════════════════════════════════
// TRANSPORT DATA
// ═══════════════════════════════════════════════════
// Países/regiões que têm rede ferroviária relevante
const eRAIL_COUNTRIES = ['Portugal','Espanha','França','Alemanha','Itália','UK','Holanda',
  'Bélgica','Suíça','Áustria','Hungria','República Tcheca','Polônia','Suécia','Dinamarca',
  'Noruega','Finlândia','Japão','Coreia do Sul','China'];
// Rotas com ferry
const eFERRY_PAIRS = [
  ['LIS','CDG'],['MAD','BCN'],['BCN','FCO'],['AMS','BER'],['LHR','CDG'],['CDG','AMS'],
  ['AMS','CPH'],['CPH','OSL'],['CPH','ARN'],['NAP','PMO'],['VCE','SPU'],['VCE','DBV'],
  ['ATH','HER'],['ATH','JTR'],['ATH','JMK'],
];
// Países onde ônibus interestaduais são viáveis (América do Sul, América Central, Ásia)
const eBUS_REGIONS = ['Brasil','Argentina','Chile','Peru','Colômbia','Uruguai','Bolívia',
  'Paraguai','Equador','México','Guatemala','Costa Rica','Panamá','El Salvador',
  'Tailândia','Vietnã','Camboja','Malásia','Indonésia','Índia','Nepal'];

function eGetT(from, to) {
  const fromAp = eAPS.find(a => a.code === from);
  const toAp   = eAPS.find(a => a.code === to);
  const options = [];

  // ── Distância aproximada ──
  let dist = 9999;
  if(fromAp && toAp && fromAp.lat != null && toAp.lat != null) {
    dist = eHaversine(fromAp.lat, fromAp.lng, toAp.lat, toAp.lng);
  } else if(fromAp && toAp) {
    // fallback sem coordenadas: estimar por continente
    dist = fromAp.country === toAp.country ? 500 : 3000;
  }

  const sameCountry = fromAp && toAp && fromAp.country === toAp.country;
  const fromBus = fromAp && eBUS_REGIONS.includes(fromAp.country);
  const toBus   = toAp   && eBUS_REGIONS.includes(toAp.country);
  const fromRail = fromAp && eRAIL_COUNTRIES.includes(fromAp.country);
  const toRail   = toAp   && eRAIL_COUNTRIES.includes(toAp.country);

  // ── Avião: sempre disponível ──
  const flightH = Math.max(1, Math.round(dist / 800 * 10) / 10);
  options.push({
    type: 'plane',
    price: Math.floor(40 + dist * 0.12 + Math.random() * 60),
    time: flightH < 1.5 ? `${Math.floor(flightH*60)}min` : `${flightH.toFixed(1).replace('.0','')}h`
  });

  // ── Trem: só se ambos países têm ferrovia E distância < 1200km ──
  if(fromRail && toRail && dist < 1200) {
    const trainH = Math.max(1, Math.round(dist / 120));
    options.push({
      type: 'train',
      price: Math.floor(20 + dist * 0.06 + Math.random() * 40),
      time: `${trainH}h`
    });
  }

  // ── Ônibus: só em regiões com cultura de ônibus E distância < 1500km ──
  if((fromBus || toBus || sameCountry) && dist < 1500) {
    const busH = Math.max(2, Math.round(dist / 60));
    options.push({
      type: 'bus',
      price: Math.floor(8 + dist * 0.025 + Math.random() * 25),
      time: `${busH}h`
    });
  }

  // ── Ferry: só em rotas costeiras específicas ──
  const key = `${from}-${to}`;
  const hasF = eFERRY_PAIRS.some(([a,b]) => 
    (a===from && b===to) || (a===to && b===from) ||
    (fromAp && toAp && fromAp.country===toAp.country && 
     ['Grécia','Croácia','Itália','Noruega','Filipinas','Indonésia'].includes(fromAp.country) && dist < 500)
  );
  if(hasF) {
    const ferryH = Math.max(4, Math.round(dist / 30));
    options.push({
      type: 'ferry',
      price: Math.floor(30 + dist * 0.05 + Math.random() * 40),
      time: `${ferryH}h`
    });
  }

  return options;
}

// ═══════════════════════════════════════════════════
// PLAN
// ═══════════════════════════════════════════════════
function eplan(){
  const btnTxt = document.getElementById('ePlanBtnTxt');
  if(btnTxt) btnTxt.textContent = '⏳ Verificando destinos...';
  eShowLoad('Planejando rota…','Calculando rotas');

  // Resolver cidades sem aeroporto — SÍNCRONO, instantâneo
  eDests.forEach(dest => {
    if(dest.input && dest.input.trim() && !dest.ap){
      const r = eResolveCityToAirport(dest.input);
      if(r){ dest.ap=r.ap; dest.dist=r.dist||0; dest.city=r.city||null; }
    }
  });

  const filled = eDests.filter(d=>d.ap);
  if(filled.length<2){
    eHideLoad();
    if(btnTxt) btnTxt.textContent = '🗺️ Encontrar rotas';
    etoast('⚠️ Adicione ao menos 2 destinos válidos','warn');
    return;
  }

  // Usar setTimeout para dar tempo ao browser de renderizar o loading
  setTimeout(()=>{
    eHideLoad();
    eRouteDone=true;
    eRenderResults();
    eRenderMap();
    eRenderTimeline();
    document.getElementById('etspBtn').style.display='flex';
    document.getElementById('eanalBtn').style.display='flex';
    if(btnTxt) btnTxt.textContent = '🗺️ Encontrar rotas';
    etoast('✅ Rota planejada!','suc');
  }, 100);
}

// ═══════════════════════════════════════════════════
// RESULTS
// ═══════════════════════════════════════════════════
function eRenderResults(){
  const f=eDests.filter(d=>d.ap);
  const el=document.getElementById('eresults');
  el.classList.add('on');

  // Título dinâmico
  const origin = f[0]?.input || '';
  const dest   = f[f.length-1]?.input || '';
  const titleEl = document.getElementById('erouteTitle');
  if(titleEl && origin && dest) {
    titleEl.textContent = f.length <= 2
      ? `${origin} → ${dest}`
      : `${origin} → ${f.length-2} parada${f.length-2>1?'s':''} → ${dest}`;
  }

  document.getElementById('ebdgC').textContent = f.length + (f.length===1?' cidade':' cidades');
  document.getElementById('ebdgD').textContent = eTotDays() + ' dias';

  // Segmentos — visual melhorado
  let segHtml='', totalTrans=0;
  for(let i=0;i<f.length-1;i++){
    const fr=f[i], to=f[i+1];
    const key=`${fr.ap.code}-${to.ap.code}`;
    const opts=eGetT(fr.ap.code,to.ap.code);
    if(!eSelTr[key]) eSelTr[key]=opts[0];
    totalTrans+=eSelTr[key].price;

    const icons={plane:'✈️',train:'🚄',bus:'🚌',ferry:'🚢'};
    const labels={plane:'Avião',train:'Trem',bus:'Ônibus',ferry:'Ferry'};
    const cls={plane:'etp',train:'ett',bus:'etb',ferry:'etf'};

    const tagHtml=opts.map(o=>{
      const sel=eSelTr[key]&&eSelTr[key].type===o.type;
      return `<button class="ettag ${cls[o.type]}${sel?' s':''}" onclick="eSelT('${key}','${o.type}',this)">
        <span>${icons[o.type]}</span>
        <span>${labels[o.type]}</span>
        <span class="etag-sep">·</span>
        <span>${o.time}</span>
        <span class="etag-sep">·</span>
        <span style="font-weight:700">${eFmtPrice(o.price)}</span>
      </button>`;
    }).join('');

    // Distância aproximada
    let distStr = '';
    if(fr.ap && to.ap) {
      const dx=(fr.ap.x-to.ap.x)*1.1, dy=fr.ap.y-to.ap.y;
      const dist = Math.round(Math.sqrt(dx*dx+dy*dy)*111);
      distStr = `<span class="eseg-dist">~${dist.toLocaleString()} km</span>`;
    }

    segHtml+=`<div class="esegcard">
      <div class="esegcities">
        <span class="eseg-flag">${fr.ap?.flag||''}</span>
        <span class="eseg-city">${eSanitize(fr.city?fr.city.name||fr.input:fr.input)}</span>
        <span class="esetarrow">→</span>
        <span class="eseg-flag">${to.ap?.flag||''}</span>
        <span class="eseg-city">${eSanitize(to.city?to.city.name||to.input:to.input)}</span>
        ${distStr}
      </div>
      ${fr.dist>0?'<div class="etransfer-leg"><span class="etl-icon">🚗</span><span class="etl-txt">'+eSanitize(fr.city?.name||'')+' → Aeroporto <b>'+fr.ap.code+'</b> · '+fr.dist+' km de transfer</span></div>':''}
      <div class="esegcodes">${fr.ap.code} · ${fr.ap.country} → ${to.ap.code} · ${to.ap.country}</div>
      ${to.dist>0?'<div class="etransfer-leg"><span class="etl-icon">🚗</span><span class="etl-txt">Aeroporto <b>'+to.ap.code+'</b> → '+eSanitize(to.city?.name||to.input)+' · '+to.dist+' km de transfer</span></div>':''}
      <div class="esegopts">${tagHtml}</div>
      <button class="eseg-toggle" onclick="var x=this.nextElementSibling;x.classList.toggle('open');this.textContent=x.classList.contains('open')?'\u25B2 Fechar':'\u{1F517} Ver onde comprar'">&#128279; Ver onde comprar</button>
      <div class="esegcard-expand">
        <span class="epartner-label">Onde comprar — ${eTransportLabel(eSelTr[key]?.type||"plane")}</span>
        <div class="epartner-links">${eBuildPartnerLinks(eSelTr[key]?.type||"plane",fr.input,to.input,fr.ap.code,to.ap.code)}</div>
        <div class="eaccom-box">
          <span class="epartner-label" style="color:var(--gold)">&#127968; Hospedagem em ${eSanitize(to.input)}</span>
          ${eBuildAccomLinks(to.input,eTravelerProfile||'conforto')}
        </div>
        <div class="ecar-box">
          <div class="ecar-title">&#128661; Aluguel de carro</div>
          <div class="epartner-links">${eBuildPartnerLinks('drive',fr.input,to.input,fr.ap.code,to.ap.code)}</div>
        </div>
      </div>
    </div>`;
  }
  document.getElementById('esegList').innerHTML=segHtml;

  const days=eTotDays();
  const travN = (typeof eTravelers!=='undefined') ? eTravelers.length : 1;
  const kids  = (typeof eTravelers!=='undefined') ? eTravelers.filter(t=>t.tipo==='crianca').length : 0;
  const profDef = (typeof eProfileDefs!=='undefined' && eProfileDefs[eProfileType])
    ? eProfileDefs[eProfileType]
    : {mult:1,hotel:25,food:20,tag:'(hostel)',tips:[]};
  const costMult = typeof eTravelerCostMult === 'function' ? eTravelerCostMult() : travN;
  const hotelBase  = f.slice(1,-1).reduce((a,d) => a + d.days * profDef.hotel, 0);
  const foodTotal  = days * profDef.food * travN;
  // Adicionar custo de transfer cidade→aeroporto (R$2/km estimado)
  let transferCost = 0;
  f.forEach(d => {
    if(d.dist > 0) transferCost += d.dist * 0.15; // ~€0.15/km de transfer
  });
  const transTotal = totalTrans * (costMult / profDef.mult) + transferCost;
  const totalEUR   = Math.round(transTotal + hotelBase + foodTotal);
  const fmt = typeof eFmtPrice === 'function' ? eFmtPrice : (v=>'€'+Math.round(v));

  document.getElementById('ecTrans').textContent = fmt(transTotal);
  document.getElementById('ecHotel').textContent = `${fmt(hotelBase)} ${profDef.tag}`;
  document.getElementById('ecFood').textContent  = fmt(foodTotal);
  document.getElementById('ecTotal').textContent = fmt(totalEUR);
  document.getElementById('emsP').textContent    = fmt(totalEUR);

  // Subtítulo do total
  const subEl = document.getElementById('ectotalSub');
  if(subEl) {
    const paxStr = travN === 1 ? '1 pessoa' : `${travN} pessoas`;
    const kidsStr = kids > 0 ? ` · ${kids} criança${kids>1?'s':''}` : '';
    subEl.textContent = `${paxStr}${kidsStr} · ${days} dias`;
  }

  // Tips
  const tips = profDef.tips || [];
  const criancas = (typeof eTravelers!=='undefined') ? eTravelers.filter(t=>t.tipo==='crianca') : [];
  const extraTips = criancas.length > 0
    ? [{i:'🧒', t:`Crianças (${criancas.map(c=>c.idade+'a').join(', ')}): verifique descontos e seguro-saúde`}]
    : travN > 1 ? [{i:'👥', t:`${travN} viajantes: dividam hospedagem para economizar até 40% por pessoa`}] : [];
  const finalTips = [...extraTips, ...tips].slice(0,4);
  document.getElementById('etipsList').innerHTML = finalTips.map(t =>
    `<div class="etip"><span class="etipdot">${t.i}</span>${t.t}</div>`
  ).join('');

  // ── Gráfico de distribuição de custos ──
  const chartEl = document.getElementById('eCostChart');
  if(chartEl) {
    const items = [
      { label: 'Transporte', val: transTotal, color: 'var(--sky)', icon: '✈️' },
      { label: 'Hospedagem', val: hotelBase,  color: 'var(--teal)', icon: '🏨' },
      { label: 'Alimentação',val: foodTotal,  color: 'var(--gold)', icon: '🍽️' },
    ];
    const tot = transTotal + hotelBase + foodTotal || 1;
    chartEl.innerHTML = items.map(item => {
      const pct = Math.round(item.val / tot * 100);
      return `<div class="echart-row">
        <span class="echart-icon">${item.icon}</span>
        <div class="echart-bar-wrap">
          <div class="echart-lbl">${item.label}</div>
          <div class="echart-track">
            <div class="echart-bar" style="width:${pct}%;background:${item.color}"></div>
          </div>
        </div>
        <span class="echart-pct">${pct}%</span>
      </div>`;
    }).join('');
    chartEl.style.display = 'block';
  }
}



// ── CTA flutuante mobile ──
(function() {
  const cta = document.getElementById('floatingCta');
  if(!cta) return;
  const appSection = document.querySelector('.app-section') || document.querySelector('.app-embed');
  const obs = new IntersectionObserver(([e]) => {
    if(cta) cta.style.display = e.isIntersecting ? 'none' : '';
  }, { threshold: 0.1 });
  if(appSection) obs.observe(appSection);
})();




// ── Progress bar de carregamento ──
(function() {
  const bar = document.getElementById('pageProgress');
  if (!bar) return;
  bar.style.transform = 'scaleX(0.1)';
  window.addEventListener('load', () => {
    bar.style.transform = 'scaleX(1)';
    setTimeout(() => { bar.style.opacity = '0'; bar.style.transition = 'opacity .5s ease'; }, 400);
    setTimeout(() => { bar.remove(); }, 900);
  });
})();

// ── Onboarding tour (primeira visita) ──
function eShowOnboarding() {
  return; // desativado — causava freeze com backdrop-filter
  if (localStorage.getItem('nrOnboarded')) return;
  const tips = [
    { target: '.etraveler-bar', title: '👋 Bem-vindo!', body: 'Clique aqui para configurar quantos viajantes e o seu perfil de viagem.', pos: 'right' },
    { target: '.eadd-dest', title: '📍 Adicione destinos', body: 'Digite as cidades que você quer visitar. Pode adicionar quantas quiser!', pos: 'top' },
    { target: '.epbtn-plan', title: '🗺️ Encontre rotas', body: 'Quando terminar, clique aqui para calcular a melhor rota e os custos.', pos: 'top' },
  ];
  let current = 0;
  const overlay = document.createElement('div');
  overlay.className = 'onboard-overlay';
  overlay.onclick = nextTip;
  document.body.appendChild(overlay);
  function nextTip() {
    document.querySelector('.onboard-tip')?.remove();
    if (current >= tips.length) {
      overlay.remove();
      localStorage.setItem('nrOnboarded', '1');
      return;
    }
    const tip = tips[current++];
    const el = document.querySelector(tip.target);
    if (!el) { nextTip(); return; }
    const rect = el.getBoundingClientRect();
    const div = document.createElement('div');
    div.className = 'onboard-tip top';
    div.innerHTML = '<div class="onboard-tip-title"><span class="onboard-tip-dot"></span>' + tip.title + '</div><div class="onboard-tip-body">' + tip.body + '</div><div style="margin-top:8px;font-size:.7rem;opacity:.6">Clique para continuar →</div>';
    div.style.cssText = 'left:' + (rect.left + rect.width/2 - 120) + 'px;top:' + (rect.bottom + 12) + 'px;position:fixed';
    div.onclick = (e) => { e.stopPropagation(); nextTip(); };
    document.body.appendChild(div);
  }
  setTimeout(nextTip, 800);
}

// ── Filtro de destinos por continente ──
function eFilterDest(filter, btn) {
  document.querySelectorAll('.dest-filter').forEach(b => b.classList.remove('on'));
  btn.classList.add('on');
  document.querySelectorAll('#destGrid .dest-card').forEach(card => {
    const cont = card.dataset.continent || 'all';
    const show = filter === 'all' || cont === filter;
    if (show) {
      card.classList.remove('hidden');
    } else {
      card.classList.add('hidden');
    }
  });
  // Ajustar grid quando filtrado
  const visible = document.querySelectorAll('#destGrid .dest-card:not(.hidden)');
  const grid = document.getElementById('destGrid');
  if (grid) {
    grid.style.gridTemplateColumns = visible.length <= 2 ? '1fr 1fr' : '';
    grid.style.gridTemplateRows = '';
  }
}

// ── Counter animado nos badges ──
(function() {
  function animateCounter(el, target, duration) {
    const start = performance.now();
    const update = (now) => {
      const elapsed = Math.min((now - start) / duration, 1);
      const ease = 1 - Math.pow(1 - elapsed, 3);
      el.textContent = Math.round(ease * target).toLocaleString('pt-BR');
      if (elapsed < 1) requestAnimationFrame(update);
    };
    requestAnimationFrame(update);
  }
  const obs = new IntersectionObserver(([e]) => {
    if (!e.isIntersecting) return;
    obs.disconnect();
    const targets = { 'hbNum1': 199, 'hbNum2': 47, 'hbNum3': 187, 'hbNum4': 4.8 };
    Object.entries(targets).forEach(([id, val]) => {
      const el = document.getElementById(id);
      if (el) animateCounter(el, val, 1400);
    });
  }, { threshold: 0.3 });
  const badges = document.querySelector('.hero-badges');
  if (badges) obs.observe(badges);
})();

// ── Scroll reveal ──
(function() {
  const obs = new IntersectionObserver(
    (entries) => entries.forEach(e => { if(e.isIntersecting) { e.target.classList.add('visible'); obs.unobserve(e.target); } }),
    { threshold: 0.1, rootMargin: '0px 0px -40px 0px' }
  );
  document.querySelectorAll('.feat, .dest-card, .testi-card, .hiw-step, .pop-card, .style-card').forEach((el, i) => {
    el.classList.add('reveal');
    el.style.transitionDelay = (i % 4 * 0.1) + 's';
    obs.observe(el);
  });
})();

// Compartilhar rota
function eShareRoute() {
  const f = eDests.filter(d=>d.ap);
  if(!f.length){ etoast('⚠️ Planeje a rota primeiro','warn'); return; }
  const codes = f.map(d=>d.ap.code).join('-');
  const days  = f.map(d=>d.days).join(',');
  const shareText = `🌿 Meu roteiro NomadRoute: ${f.map(d=>d.input).join(' → ')} | ${eTotDays()} dias`;
  if(navigator.share) {
    navigator.share({title:'NomadRoute', text:shareText}).catch(()=>{});
  } else if(navigator.clipboard) {
    navigator.clipboard.writeText(shareText);
    etoast('🔗 Roteiro copiado para a área de transferência!','suc');
  } else {
    etoast('🔗 '+shareText,'suc');
  }
}
function eSelT(key,type,el){
  el.closest('.esegopts').querySelectorAll('.ettag').forEach(t=>t.classList.remove('s'));
  el.classList.add('s');
  const opts=eGetT(key.split('-')[0],key.split('-')[1]);
  eSelTr[key]=opts.find(o=>o.type===type);
  if(eRouteDone){ eRenderResults(); eRenderMap(); }
}

// Map
function eHvrs(a,b){const dx=(a.x-b.x)*1.1,dy=a.y-b.y;return Math.sqrt(dx*dx+dy*dy)*111;}
function eRenderMap(){
  if(window.L){ eRenderLeafletMap(); return; }
  // fallback: sem Leaflet
}


// Timeline
function eRenderTimeline(){
  const f=eDests.filter(d=>d.ap);
  const tl=document.getElementById('etlList');tl.innerHTML='';
  const ticon={plane:'✈️',train:'🚄',bus:'🚌',ferry:'🚢'};
  const tcls={plane:'plane',train:'train',bus:'bus',ferry:'def'};
  let day=1;
  for(let i=0;i<f.length-1;i++){
    const fr=f[i],to=f[i+1],key=`${fr.ap.code}-${to.ap.code}`;
    const sel=eSelTr[key]||{type:'plane',price:80,time:'2h'};
    tl.innerHTML+=`<div class="etl-item"><div class="etl-l"><div class="etl-day">D${day}</div><div class="etl-dot ${i===0?'g':''}"></div><div class="etl-line"></div></div>
      <div class="etl-c"><div class="etl-cities">${fr.input}<span class="etl-arr"> › </span>${to.input}</div>
        <div class="etl-aps">${fr.ap.code}→${to.ap.code}</div>
        <div class="etl-meta"><span class="etlchip ${tcls[sel.type]}">${ticon[sel.type]} ${sel.time}</span><span class="etlchip def">${eFmtPrice(sel.price)}</span></div>
        <button class="etl-buy" onclick="etoast('🎟️ Buscando passagens…','suc')">Ver passagens</button>
      </div></div>`;
    day++;
    if(to.days>0){
      tl.innerHTML+=`<div class="etl-city-stay"><div class="etl-cs-name">${to.ap.flag} ${to.input}</div><div class="etl-cs-days">🛏️ ${to.days} noite${to.days>1?'s':''}</div></div>`;
      day+=to.days;
    }
  }
  if(f.length>1){const fin=f[f.length-1];tl.innerHTML+=`<div class="etl-item"><div class="etl-l"><div class="etl-day">D${day}</div><div class="etl-dot r"></div></div><div class="etl-c"><div class="etl-cities">🏁 ${fin.input}</div></div></div>`;}
}

// TSP
function eHvrs2(a,b){const dx=(a.x-b.x)*1.1,dy=a.y-b.y;return Math.sqrt(dx*dx+dy*dy)*111;}
function eCalcScore(r){
  let d=0,p=0;
  for(let i=0;i<r.length-1;i++){const fr=r[i].ap,to=r[i+1].ap;if(!fr||!to)continue;const opts=eGetT(fr.code,to.code);const b=opts.reduce((a,c)=>a.price<c.price?a:c);d+=eHvrs2(fr,to);p+=b.price;}
  return{dist:Math.round(d),price:Math.round(p)};
}
function eNN(cs){
  const n=cs.length;if(n<=2) return[...cs];
  const mid=cs.slice(1,n-1),vis=new Array(mid.length).fill(false),r=[cs[0]];let cur=cs[0];
  for(let s=0;s<mid.length;s++){let bi=-1,bd=Infinity;mid.forEach((c,i)=>{if(!vis[i]&&c.ap&&cur.ap){const d=eHvrs2(c.ap,cur.ap);if(d<bd){bd=d;bi=i;}}});if(bi>=0){vis[bi]=true;r.push(mid[bi]);cur=mid[bi];}}
  r.push(cs[n-1]);return r;
}
function erunTSP(){document.querySelectorAll('.eptab')[1].click();setTimeout(erunTSPFull,100);}
function erunTSPFull(){
  const f=eDests.filter(d=>d.ap);
  if(f.length<3){etoast('⚠️ Adicione pelo menos 3 destinos','warn');return;}
  eShowLoad('Rodando TSP…','Testando combinações de rota · Dijkstra em cada aresta');
  setTimeout(()=>{
    eHideLoad();
    const nn=eNN(f);const oS=eCalcScore(f),nS=eCalcScore(nn);
    const dist_save=Math.max(0,oS.dist-nS.dist),price_save=Math.max(0,oS.price-nS.price);
    const rt=nn.map(r=>r.ap?r.ap.code:r.input).join(' › ');
    document.getElementById('etspVersions').innerHTML=`
      <div class="etsp-result" style="border-color:rgba(45,216,138,.3);cursor:pointer" onclick="eApplyNN(this)">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
          <span style="font-size:.82rem;font-weight:700;color:var(--efg)">⚖️ Rota Otimizada
            <span style="font-size:.6rem;background:rgba(45,216,138,.12);color:var(--emint);padding:1px 6px;border-radius:20px;border:1px solid rgba(45,216,138,.25);margin-left:4px">MELHOR</span>
          </span>
          <span style="font-size:.78rem;color:var(--emint);font-weight:700">-${eFmtPrice(price_save)}</span>
        </div>
        <div class="etsp-route-label">Sequência otimizada</div>
        <div class="etsp-route-cities" style="margin-bottom:8px">${rt.split(' › ').join(' <span style="color:var(--egreen2)">›</span> ')}</div>
        <div class="etsp-dist">
          <span>📍 <span class="etsp-dist-val">${nS.dist.toLocaleString()} km</span></span>
          <span style="color:var(--erim2)">·</span>
          <span>💰 <span class="etsp-dist-val">${eFmtPrice(nS.price)}</span></span>
          <span style="color:var(--erim2)">·</span>
          <span>🧠 Nearest Neighbor</span>
        </div>
      </div>`;
    etoast(`🧠 TSP economiza ${dist_save.toLocaleString()} km e ${eFmtPrice(price_save)}`,'ai');
  },1600);
}
function eApplyNN(el){
  const f=eDests.filter(d=>d.ap);
  const nn=eNN(f);
  nn.forEach((r,i)=>{const orig=eDests.find(d=>d.ap&&d.ap.code===r.ap?.code);if(orig) nn[i]={...r,days:orig.days};});
  eDests=nn;eSelTr={};eRenderDests();eRenderResults();eRenderMap();eRenderTimeline();
  etoast('✅ Rota otimizada aplicada!','ai');
  document.querySelectorAll('.eptab')[0].click();
}

// Analysis (static fallback)
function erunAnalysis(){
  if(!eRouteDone){etoast('\u26A0\uFE0F Planeje a rota primeiro','warn');return;}
  eShowLoad('Analisando roteiro\u2026','Verificando clima, eventos e log\xEDstica');
  setTimeout(()=>{
    eHideLoad();
    const f=eDests.filter(d=>d.ap);
    const destCount=f.length, days=eTotDays();
    const profile=eTravelerProfile||eProfileType||'conforto';
    const insights=[
      {type:'warn',icon:'\u{1F328}\uFE0F',title:'Clima & Sazonalidade',body:'Verifique a melhor \xE9poca para cada destino. Use a aba <b>IA Claude</b> para uma an\xE1lise clim\xE1tica personalizada com dicas de roupa e acess\xF3rios.'},
      {type:'ok',icon:'\u{1F9F3}',title:'Dica de Malas — Perfil '+(profile.charAt(0).toUpperCase()+profile.slice(1)),body:'Para o perfil <b>'+profile+'</b>: mala de m\xE9dio porte, adaptador universal de tomadas, seguro viagem e c\xF3pias digitais dos documentos.'},
      {type:'info',icon:'\u2705',title:'Log\xEDstica Favor\xE1vel',body:'Rota bem conectada com '+(destCount)+' paradas. Use a aba <b>TSP</b> para otimizar a ordem dos destinos e economizar.'},
      {type:'sky',icon:'\u{1F4B1}',title:'C\xE2mbio e Pagamentos',body:'Pesquise taxas via <a href="https://www.google.com/search?q=cambio+hoje" target="_blank" rel="noopener noreferrer" style="color:var(--sky)">Google C\xE2mbio</a> ou apps como Wise e Remessa Online. Cartões internacionais com zero IOF economizam bastante.'},
    ];
    if(destCount>=4) insights.push({type:'gold',icon:'\u26A1',title:'Agenda Intensa',body:destCount+' destinos em '+days+' dias \xE9 uma agenda intensa. Considere 1-2 dias extras de folga para imprevistos e descanso.' });
    if(days>=14) insights.push({type:'teal',icon:'\u{1F6E1}\uFE0F',title:'Seguro Viagem',body:'Para viagens acima de 14 dias recomendamos seguro com cobert>ura m\xE9dica. Compare em <a href="https://www.comparaonline.com.br/seguro-viagem" target="_blank" rel="noopener noreferrer" style="color:var(--teal)">Compara Online</a> ou <a href="https://www.zurich.com.br/pt-br/seguro-viagem" target="_blank" rel="noopener noreferrer" style="color:var(--teal)">Zurich</a>.' });
    // Adicionar links de parceiros por destino
    const partnerSection = f.length>1 ? '<div style="margin-top:12px"><span class="epartner-label">Links r\xE1pidos</span><div class="epartner-links">'
      +'<a href="https://www.google.com/travel" target="_blank" rel="noopener noreferrer" class="epartner-link" style="--pc:#1a73e8"><span class="epl-icon">\u2708\uFE0F</span><span class="epl-name">Google Travel</span><span class="epl-arrow">\u2197</span></a>'
      +'<a href="https://www.kayak.com.br" target="_blank" rel="noopener noreferrer" class="epartner-link" style="--pc:#ff690f"><span class="epl-icon">\u{1F50D}</span><span class="epl-name">Kayak</span><span class="epl-arrow">\u2197</span></a>'
      +'<a href="https://www.booking.com/searchresults.html?ss='+encodeURIComponent(f[f.length-1].input)+'" target="_blank" rel="noopener noreferrer" class="epartner-link" style="--pc:#003580"><span class="epl-icon">\u{1F3E8}</span><span class="epl-name">Booking.com</span><span class="epl-arrow">\u2197</span></a>'
      +'</div></div>' : '';
    document.getElementById('eanalResults').innerHTML=insights.map((ins,i)=>{
      const delay=(i*0.12).toFixed(2);
      return '<div class="eanalysis-card '+ins.type+'" style="opacity:0;transform:translateY(10px);transition:opacity .35s '+delay+'s ease,transform .35s '+delay+'s ease"><div class="eanalysis-card-title">'+ins.icon+' '+ins.title+'</div>'+ins.body+'</div>';
    }).join('')+partnerSection;
    requestAnimationFrame(()=>{
      requestAnimationFrame(()=>{
        document.querySelectorAll('#eanalResults .eanalysis-card').forEach(el=>{
          el.style.opacity='1'; el.style.transform='none';
        });
      });
    });
  },1200);
}

// ═══════════════════════════════════════════════════
// AI CLAUDE — REAL API
// ═══════════════════════════════════════════════════
let eAiHistory = [];

async function eAiChip(el, text) {
  document.getElementById('eaiPrompt').value = text;
  document.querySelectorAll('.eai-chip').forEach(c => c.classList.remove('on'));
  el.classList.add('on');
  el.style.borderColor = 'var(--egreen)';
  el.style.color = 'var(--egreen2)';
  el.style.background = 'rgba(90,170,66,.12)';
}
async function egenAI(){
  const rawPrompt = document.getElementById('eaiPrompt').value.trim();
  if(!rawPrompt){ etoast('⚠️ Descreva sua viagem','warn'); return; }

  // Rate limiting — máx 5 chamadas/minuto
  if(!_eRateLimiter.check()){
    etoast('⏳ Aguarde um momento antes de enviar outra mensagem','warn');
    return;
  }

  // Sanitizar input do usuário (anti-prompt-injection)
  const prompt = eAIGuardrails.sanitizeInput(rawPrompt);
  if(prompt.length < 3){ etoast('⚠️ Descreva sua viagem em mais detalhes','warn'); return; }

  // Add user message to chat
  const chat = document.getElementById('eaiChat');
  const userMsg = document.createElement('div');
  userMsg.className = 'eai-msg user';
  userMsg.textContent = prompt;
  chat.appendChild(userMsg);
  document.getElementById('eaiPrompt').value = '';

  // Add loading message
  const loadMsg = document.createElement('div');
  loadMsg.className = 'eai-msg assistant loading';
  loadMsg.textContent = '🌿 Pensando no seu roteiro…';
  chat.appendChild(loadMsg);
  chat.scrollTop = chat.scrollHeight;

  const btn = document.getElementById('eaiBtnSend');
  btn.disabled = true; btn.textContent = '⏳ Aguarde…';

  eAiHistory.push({ role: 'user', content: prompt });

  try {
    const systemPrompt = `Você é o NomadRoute AI, especialista global em viagens. Responda SEMPRE em português brasileiro. Use markdown com emojis. Seja entusiasmado, detalhado e específico com valores reais e dicas concretas.\n\nCONTEXTO COMPLETO DA VIAGEM:\n- Viajantes: ${eTravelers.length} pessoa(s) — ${eTravelers.map(t=>t.tipo==='crianca'?eSanitizePrompt(t.name)+' (criança '+t.idade+' anos)':t.name+' (adulto)').join(', ')}\n- Perfil: ${eTravelerProfile||eProfileType||'conforto'}\n- Destinos planejados: ${eDests.filter(d=>d.ap).map(d=>(eSanitizePrompt(d.city?d.city.name||d.input:d.input))+' ('+d.days+' dias, aeroporto '+d.ap.code+')').join(' → ')||'Nenhum ainda'}\n- Distância total da rota: ${eDests.filter(d=>d.ap).length>1?Math.round(eDests.filter(d=>d.ap).reduce((s,d,i,arr)=>i===0?0:s+eHaversine(arr[i-1].ap.lat||0,arr[i-1].ap.lng||0,d.ap.lat||0,d.ap.lng||0),0))+' km':'desconhecida'}\n- Moeda preferida: ${eCurrency}\n- Crianças: ${eTravelers.filter(t=>t.tipo==='crianca').length>0?'SIM: '+eTravelers.filter(t=>t.tipo==='crianca').map(c=>c.name+' '+c.idade+' anos').join(', '):'Não'}\n\nQUANDO O USUÁRIO DESCREVER OU PERGUNTAR SOBRE UMA VIAGEM, RESPONDA COM:\n\n## ✈️ Rota Sugerida\nCidades em ordem ideal com dias recomendados em cada uma.\n\n## 🌤️ Clima & Melhor Época\n- Clima esperado por destino (temperatura média, chuva, eventos sazonais)\n- Meses ideais para visitar cada cidade\n- **Roupa recomendada:** seja específico (ex: 'casaco leve à noite, sandálias', 'protetor solar 50+, camisetas leves')\n- ⚠️ Alertas: temporadas de chuva, calor extremo, alta temporada (preços sobem)\n\n## 💰 Estimativa de Custos Detalhada\n- Passagens aéreas: valor médio por trecho principal\n- Hospedagem: diária estimada × noites × perfil ${eTravelerProfile||'conforto'}\n- Alimentação: estimativa diária por pessoa\n- Passeios: lista dos principais com preço de entrada\n- **TOTAL ESTIMADO** para ${eTravelers.length} pessoa(s)\n\n## 🗺️ Top Passeios por Cidade\nPara CADA cidade: 3-5 atrações com valor de entrada estimado em BRL.\n\n## 💱 Dicas Práticas\n- **Câmbio:** cotação atual aproximada, apps recomendados (Wise, Remessa Online)\n- **Chip/eSIM:** operadora local recomendada, preço médio\n- **Transporte local:** apps de táxi locais (Grab, Gojek, etc.), passes de metrô\n- **Segurança:** bairros a evitar, dicas específicas para o destino\n- **Gastronomia:** 3-5 pratos típicos obrigatórios, onde comer bem e barato\n\n## 📱 Apps para baixar\nLista de apps essenciais para ESTES destinos específicos.\n\n## 🎒 Lista de Malas\nItens específicos para o clima e atividades destes destinos.${eTravelers.filter(t=>t.tipo==='crianca').length>0?'\n\n## 👨‍👩‍👧 Dicas para Crianças\n- Atrações e restaurantes family-friendly\n- Segurança e saúde com crianças na viagem\n- O que levar para crianças':''}\n\n---\nAo final, SEMPRE pergunte: 'Quer que eu importe esses destinos para o seu Planner?'`;

    const response = await fetch('/api/ai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        system: systemPrompt,
        messages: eAiHistory
      })
    });

    const data = await response.json();
    if (!data.ok) {
      loadMsg.classList.remove('loading');
      loadMsg.innerHTML = '⚠️ ' + (data.error || 'Erro ao conectar com a IA.');
      return;
    }
    const rawReply = data.reply || '';
    // Validar resposta com guardrails
    const validation = eAIGuardrails.validate(rawReply);
    if(!validation.ok) {
      loadMsg.classList.remove('loading');
      loadMsg.innerHTML = '⚠️ Não foi possível gerar uma resposta válida. Tente reformular sua pergunta.';
      return;
    }
    // Adicionar disclaimers automáticos
    const reply = eAIGuardrails.addDisclaimers(rawReply);

    eAiHistory.push({ role: 'assistant', content: reply });

    loadMsg.classList.remove('loading');
    loadMsg.innerHTML = reply.replace(/\n/g, '<br>').replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>').replace(/\*(.*?)\*/g, '<em>$1</em>');

    // Check if response has importable route
    const hasRoute = reply.toLowerCase().includes('→') || reply.toLowerCase().includes('rota') || reply.toLowerCase().includes('cidades');
    if(hasRoute) {
      // Tentar extrair cidades da resposta
      const cityMatches = reply.match(/[A-ZÁÉÍÓÚÀÂÊÔÃÕÜÇ][a-záéíóúàâêôãõüç\s]+(?:\s+[A-ZÁÉÍÓÚÀÂÊÔÃÕÜÇ][a-záéíóúàâêôãõüç]+)*/g) || [];
      const potentialCities = cityMatches
        .map(c => c.trim())
        .filter(c => c.length > 3 && c.length < 30 && !['Para', 'Dias', 'Total', 'Voos', 'Hotel', 'Custo', 'Rota', 'Perfil', 'Liste', 'Nota', 'Dica', 'Itens', 'Apps', 'Malas'].includes(c))
        .slice(0, 8);

      window._eLastAICities = potentialCities;
      document.getElementById('eaiResult').style.display = 'block';
      document.getElementById('eaiResult').innerHTML = `
        <div style="background:var(--sky-ghost);border:1.5px solid var(--sky-pale);border-radius:var(--radius-md);padding:12px;margin-top:8px">
          <div style="font-family:var(--font-body);font-size:.72rem;font-weight:700;color:var(--sky);margin-bottom:8px;text-transform:uppercase;letter-spacing:.08em">↗ Importar rota para o Planner</div>
          <button class="epbtn epbtn-plan" style="margin-bottom:0" onclick="eImportAIRoute(window._eLastAICities)">
            🗺️ Importar destinos automaticamente
          </button>
        </div>`;
    }
    etoast('✦ Roteiro gerado pela IA!','ai');
  } catch(err) {
    loadMsg.classList.remove('loading');
    loadMsg.textContent = '⚠️ Erro ao conectar com a IA. Verifique sua conexão e tente novamente.';
    etoast('Erro na IA','warn');
    console.error(err);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '🌿 Gerar roteiro com IA';
    chat.scrollTop = chat.scrollHeight;
  }
}


// ═══════════════════════════════════════════════════
// TAB SWITCHING
// ═══════════════════════════════════════════════════
const ETABS=['planner','tsp','analysis','ai','budget'];
function etab(name,el,idx){
  ETABS.forEach(t=>{const d=document.getElementById('etab-'+t);if(d) d.style.display='none';});
  const target=document.getElementById('etab-'+name);if(target) target.style.display='block';
  document.querySelectorAll('.eptab').forEach((t,i)=>t.classList.toggle('on',i===(idx!==undefined?idx:ETABS.indexOf(name))));
}

// ═══════════════════════════════════════════════════
// UI HELPERS
// ═══════════════════════════════════════════════════
function eShowLoad(t,s=''){document.getElementById('eltxt').textContent=t;document.getElementById('elsub').textContent=s;document.getElementById('elov').classList.add('on');}
function eHideLoad(){document.getElementById('elov').classList.remove('on');}
function eShowBudgetPlan() {
  const slider = document.getElementById('eBudgetSlider');
  const total = parseInt(slider?.value || 1500);
  const days = eTotDays() || 7;
  const travN = (typeof eTravelers!=='undefined') ? eTravelers.length : 1;
  const dist = { trans: .35, hotel: .35, food: .20, misc: .10 };
  const items = [
    { icon:'✈️', label:'Transporte', pct: dist.trans, color:'var(--egreen2)' },
    { icon:'🏨', label:'Hospedagem', pct: dist.hotel, color:'var(--esky)' },
    { icon:'🍽️', label:'Alimentação', pct: dist.food, color:'var(--egold)' },
    { icon:'🎭', label:'Lazer/Extras', pct: dist.misc, color:'var(--elilac)' },
  ];
  const rowsHtml = items.map(item => {
    const val = Math.round(total * item.pct);
    const pct = Math.round(item.pct * 100);
    return `<div class="ebudget-bar-row">
      <div class="ebudget-bar-top">
        <span class="ebudget-lbl">${item.icon} ${item.label}</span>
        <span class="ebudget-val">${eFmtPrice(val / ((eCurrencyRates[eCurrency]||{rate:1}).rate))}</span>
      </div>
      <div class="ebudget-bar-track">
        <div class="ebudget-bar-fill" style="width:${pct}%;background:${item.color}"></div>
      </div>
    </div>`;
  }).join('');
  const ppVal = eFmtPrice((total/travN) / ((eCurrencyRates[eCurrency]||{rate:1}).rate));
  const totVal = eFmtPrice(total / ((eCurrencyRates[eCurrency]||{rate:1}).rate));
  document.getElementById('eBudgetRows').innerHTML = rowsHtml;
  document.getElementById('eBudgetBreakdown').style.display = 'block';
  document.getElementById('eBudgetTotal').style.display = 'flex';
  document.getElementById('eBudgetTotalVal').textContent = totVal;
  document.getElementById('eBudgetPP').textContent = `${ppVal}/pessoa · ${days} dias`;
  etoast('✦ Distribuição calculada!','suc');
}
function etoast(msg,type){
  const t=document.getElementById('etoast');t.textContent=msg;t.className='etoast '+(type||'');
  setTimeout(()=>t.classList.add('on'),10);setTimeout(()=>t.classList.remove('on'),3200);
}

// ═══════════════════════════════════════════════════
// MOBILE MENU
// ═══════════════════════════════════════════════════
function openMobileMenu(){ document.getElementById('mobileMenu').classList.add('on'); document.body.style.overflow='hidden'; }
function closeMobileMenu(){ document.getElementById('mobileMenu').classList.remove('on'); document.body.style.overflow=''; }

// ═══════════════════════════════════════════════════
// TRAVELER PROFILES
// ═══════════════════════════════════════════════════
const TRAVELER_EMOJIS = ['🎒','📸','🧗','🍜','😎','🎭','🌿','🏄','🚵','🧘'];
let _eTravType = 'adulto'; // current type being added

function eSetTravType(tipo){
  _eTravType = tipo;
  const btnA = document.getElementById('etravTypeAdult');
  const btnC = document.getElementById('etravTypeChild');
  const ageEl = document.getElementById('etravAgeInput');
  const rolesEl = document.getElementById('etravRoleSelect');
  if(tipo === 'adulto'){
    btnA.style.cssText = 'flex:1;padding:6px;border-radius:7px;font-size:.75rem;font-family:inherit;cursor:pointer;font-weight:600;background:rgba(90,170,66,.15);border:1px solid rgba(90,170,66,.5);color:var(--egreen2);transition:all .2s';
    btnC.style.cssText = 'flex:1;padding:6px;border-radius:7px;font-size:.75rem;font-family:inherit;cursor:pointer;font-weight:600;background:none;border:1px solid var(--erim2);color:var(--efg3);transition:all .2s';
    ageEl.style.display = 'none';
    rolesEl.style.display = 'flex';
    document.getElementById('etravNameInput').placeholder = 'Nome…';
  } else {
    btnA.style.cssText = 'flex:1;padding:6px;border-radius:7px;font-size:.75rem;font-family:inherit;cursor:pointer;font-weight:600;background:none;border:1px solid var(--erim2);color:var(--efg3);transition:all .2s';
    btnC.style.cssText = 'flex:1;padding:6px;border-radius:7px;font-size:.75rem;font-family:inherit;cursor:pointer;font-weight:600;background:rgba(212,160,32,.15);border:1px solid rgba(212,160,32,.5);color:var(--egold);transition:all .2s';
    ageEl.style.display = 'flex';
    rolesEl.style.display = 'none';
    document.getElementById('etravNameInput').placeholder = 'Nome da criança…';
  }
}

function eTravelerCostMult(){
  const b = {budget:1,comfort:1.6,luxury:2.8};
  // Children discounts: <2 free, 2-11 = 0.6x, 12+ = 0.85x
  const total = eTravelers.reduce((acc, t) => {
    if(t.tipo === 'crianca'){
      const age = t.idade || 0;
      if(age < 2) return acc + 0;
      if(age < 12) return acc + 0.6;
      return acc + 0.85;
    }
    return acc + 1;
  }, 0);
  return (b[eProfileType]||1) * (total || 1);
}

function eUpdateTravelerBar(){
  eStorage.autoSave();
  const adults = eTravelers.filter(t => t.tipo !== 'crianca').length;
  const children = eTravelers.filter(t => t.tipo === 'crianca').length;
  const n = eTravelers.length;
  const profDef = (typeof eProfileDefs !== 'undefined' && eProfileDefs[eProfileType]) ? eProfileDefs[eProfileType] : {label: eProfileType};
  const profLabel = profDef.label || eProfileType;
  let countTxt = n === 1 ? '1 Viajante' : `${n} Viajantes`;
  if(children > 0) countTxt += ` · ${children} criança${children>1?'s':''}`;
  document.getElementById('etravCount').textContent = countTxt;
  document.getElementById('etravSub').textContent = `${profLabel} · Clique para editar`;
  const mainEmoji = eTravelers[0]?.tipo==='crianca' ? '🧒' : (eTravelers[0]?.emoji||'🎒');
  document.getElementById('etavMain').textContent = mainEmoji;
  // Sync inline profile dropdown if visible
  const def = (typeof eProfileDefs !== 'undefined' && eProfileDefs[eProfileType]) ? eProfileDefs[eProfileType] : null;
  if(def) {
    const parts = def.label.split(' ');
    const iconEl = document.getElementById('etravProfileIcon');
    const txtEl  = document.getElementById('etravProfileTxt');
    if(iconEl) iconEl.textContent = parts[0];
    if(txtEl)  txtEl.textContent  = parts.slice(1).join(' ');
    document.querySelectorAll('.etpd-item').forEach(i => {
      i.classList.toggle('on', i.textContent.trim().toLowerCase().includes(eProfileType));
    });
  }
  if(typeof eUpdateHomeSB === 'function') eUpdateHomeSB();
}

function eRenderTravelerList(){
  const list = document.getElementById('etravList');
  list.innerHTML = '';
  eTravelers.forEach((t, i) => {
    const isCrianca = t.tipo === 'crianca';
    const emoji = isCrianca ? '🧒' : (t.emoji || '🎒');
    const roleOrAge = isCrianca
      ? `Criança · ${t.idade!=null ? t.idade + ' anos' : 'idade não informada'}`
      : (t.role || 'Adulto');
    const costNote = isCrianca && t.idade!=null
      ? (t.idade < 2 ? '(gratuito)' : t.idade < 12 ? '(60% tarifa)' : '(85% tarifa)')
      : '';
    const div = document.createElement('div');
    div.className = 'etrav-item';
    div.innerHTML = `
      <div class="etrav-emoji">${emoji}</div>
      <div class="etrav-info">
        <div class="etrav-name">${t.name} ${costNote?`<span style="font-size:.6rem;color:var(--efg3)">${costNote}</span>`:''}</div>
        <div class="etrav-role">${roleOrAge}</div>
      </div>
      ${i>0
        ? `<button class="etrav-del" onclick="eRemTraveler(${i})">×</button>`
        : `<div class="etrav-profile-drop" id="etravProfileDrop">
            <button class="etrav-profile-btn" onclick="eToggleTravProfileDrop(event)" title="Alterar perfil de viagem">
              <span id="etravProfileIcon">${(eProfileDefs[eProfileType]||eProfileDefs.mochileiro).label.split(' ')[0]}</span>
              <span id="etravProfileTxt" style="font-size:.65rem;font-weight:700;color:var(--egreen2)">${(eProfileDefs[eProfileType]||eProfileDefs.mochileiro).label.replace(/^.\s/,'')}</span>
              <span style="font-size:.5rem;color:var(--efg3)">▾</span>
            </button>
            <div class="etrav-profile-menu" id="etravProfileMenu">
              <div class="etpd-item on" onclick="eSetTravProfile('mochileiro',this)">🎒 Mochileiro</div>
              <div class="etpd-item" onclick="eSetTravProfile('economico',this)">💸 Econômico</div>
              <div class="etpd-item" onclick="eSetTravProfile('comfort',this)">🏨 Conforto</div>
              <div class="etpd-item" onclick="eSetTravProfile('luxury',this)">✨ Luxo</div>
              <div class="etpd-item" onclick="eSetTravProfile('familia',this)">👨‍👩‍👧 Família</div>
              <div class="etpd-item" onclick="eSetTravProfile('aventura',this)">🏔️ Aventura</div>
              <div class="etpd-item" onclick="eSetTravProfile('gastro',this)">🍽️ Gastronômico</div>
              <div class="etpd-item" onclick="eSetTravProfile('cultural',this)">🏛️ Cultural</div>
            </div>
          </div>`
      }`;
    list.appendChild(div);
  });
}

function eAddTraveler(){
  const nameEl = document.getElementById('etravNameInput');
  const ageEl  = document.getElementById('etravAgeInput');
  const tipo   = _eTravType;
  const name   = nameEl.value.trim() || (tipo==='crianca' ? `Criança ${eTravelers.filter(t=>t.tipo==='crianca').length+1}` : `Viajante ${eTravelers.length+1}`);

  if(tipo === 'crianca'){
    const ageVal = ageEl.value !== '' ? parseInt(ageEl.value) : null;
    if(ageVal === null || isNaN(ageVal)){
      etoast('⚠️ Informe a idade da criança','warn');
      ageEl.focus();
      return;
    }
    eTravelers.push({name, tipo:'crianca', idade:ageVal, emoji:'🧒', role:''});
    ageEl.value = '';
  } else {
    const emoji = TRAVELER_EMOJIS[eTravelers.filter(t=>t.tipo!=='crianca').length % TRAVELER_EMOJIS.length];
    eTravelers.push({name, tipo:'adulto', role:eSelectedRole, emoji});
  }

  nameEl.value = '';
  eRenderTravelerList();
  eUpdateTravelerBar();
  if(eRouteDone) eRenderResults();

  // Warn if child + extreme destination
  const criancas = eTravelers.filter(t => t.tipo === 'crianca');
  if(criancas.length > 0 && eDests.some(d => d.ap)){
    const coldDests = ['KEF','OSL','ARN','HEL','CTS','USH','FTE'];
    const hotDests  = ['BKK','DPS','SGN','DAD','CMN','CAI','NBO'];
    const codes = eDests.filter(d=>d.ap).map(d=>d.ap.code);
    if(codes.some(c => coldDests.includes(c))){
      etoast('❄️ Destino com frio intenso — verifique clima para crianças na aba Análise','warn');
    } else if(codes.some(c => hotDests.includes(c))){
      etoast('🌡️ Destino tropical — verifique recomendações para crianças na aba Análise','warn');
    } else {
      etoast(`🧒 ${name} adicionado${tipo==='crianca'?' (criança)':''}!`,'suc');
    }
  } else {
    etoast(`✅ ${name} adicionado!`,'suc');
  }
}

function eRemTraveler(i){
  eTravelers.splice(i,1);
  eRenderTravelerList();
  eUpdateTravelerBar();
  if(eRouteDone) eRenderResults();
}

function openTravelerModal(){
  eRenderTravelerList();
  document.getElementById('etravModal').classList.add('on');
}
function closeTravelerModal(){
  document.getElementById('etravModal').classList.remove('on');
  eUpdateTravelerBar();
}

// ═══════════════════════════════════════════════════
// CURRENCY SYSTEM
// ═══════════════════════════════════════════════════
let eCurrency = 'BRL';
let eCurrencySymbol = 'R$';
// Restore saved currency preference
(function() {
  try {
    const saved = JSON.parse(localStorage.getItem('nomadroute_state') || '{}');
    if (saved.currency && saved.currency !== 'BRL') {
      eCurrency = saved.currency;
    }
  } catch(e) {}
})();
// Approximate rates relative to EUR
const eCurrencyRates = {
  EUR: {rate:1,      symbol:'€',  name:'Euro'},
  BRL: {rate:5.8,    symbol:'R$', name:'Real'},
  USD: {rate:1.08,   symbol:'$',  name:'Dólar'},
  GBP: {rate:0.86,   symbol:'£',  name:'Libra'},
  ARS: {rate:980,    symbol:'$',  name:'Peso Arg.'},
  CLP: {rate:1020,   symbol:'$',  name:'Peso Chi.'},
  JPY: {rate:162,    symbol:'¥',  name:'Iene'},
};

function eFmtPrice(eurVal) {
  const r = eCurrencyRates[eCurrency] || eCurrencyRates.EUR;
  const converted = Math.round(eurVal * r.rate);
  if(eCurrency === 'BRL') return `R$${converted.toLocaleString('pt-BR')}`;
  if(eCurrency === 'ARS') return `$${converted.toLocaleString('pt-BR')}`;
  return `${r.symbol}${converted.toLocaleString('en-US')}`;
}

function eSetCurrency(el, code, symbol) {
  eCurrency = code;
  eCurrencySymbol = symbol;
  document.querySelectorAll('#eCurrencyBtns .eqd').forEach(b => b.classList.remove('on'));
  el.classList.add('on');
  if(eRouteDone) eRenderResults();
  const r = eCurrencyRates[code];
  etoast(`${r.symbol} ${r.name} selecionado`, 'suc');
}

// ═══════════════════════════════════════════════════
// PROFILE SYSTEM — 8 perfis
// ═══════════════════════════════════════════════════
const eProfileDefs = {
  mochileiro: { label:'🎒 Mochileiro', mult:1.0,    hotel:20, food:18, tag:'(hostel/dorm)',    tips:[
    {i:'🌿',t:'Reserve dormitórios compartilhados — economize 60% vs quarto privado'},
    {i:'🎒',t:'Madrugadas e dias de semana têm passagens até 40% mais baratas'},
    {i:'🚌',t:'Ônibus noturnos economizam hospedagem e tempo de viagem'},
    {i:'💳',t:'Evite taxas de câmbio — use cartão sem IOF no exterior'},
  ]},
  economico:  { label:'💸 Econômico',  mult:1.25,   hotel:35, food:22, tag:'(guesthouse)',    tips:[
    {i:'🏠',t:'Guesthouses familiares — mais barato que hotel e mais confortável que hostel'},
    {i:'🛒',t:'Supermercados locais para refeições rápidas economizam até 70%'},
    {i:'🗓️',t:'Reserve com 3-4 semanas de antecedência para melhores tarifas aéreas'},
    {i:'📍',t:'Bairros fora do centro turístico costumam ter preços 30-40% menores'},
  ]},
  comfort:    { label:'🏨 Conforto',   mult:1.7,    hotel:70, food:35, tag:'(hotel 2-3★)',    tips:[
    {i:'🏨',t:'Hotel com café da manhã incluso pode sair mais barato que hostel + refeição'},
    {i:'🚆',t:'Passe de trem regional compensa em trajetos curtos na Europa'},
    {i:'📱',t:'Apps como Booking com cashback frequentemente superam o site oficial'},
    {i:'💳',t:'Cartão de viagem com seguro internacional gratuito e sem anuidade'},
  ]},
  luxury:     { label:'✨ Luxo',        mult:3.2,    hotel:200,food:80, tag:'(hotel 4-5★)',   tips:[
    {i:'✨',t:'Acumule milhas — voos longos valem muito em programas de fidelidade'},
    {i:'🏨',t:'Hotéis boutique locais costumam superar as grandes redes em experiência'},
    {i:'🍽️',t:'Chef\u2019s table e experiências gastronômicas únicas valem o investimento'},
    {i:'🚁',t:'Transfers privados economizam tempo e chegam com conforto total'},
  ]},
  familia:    { label:'👨‍👩‍👧 Família',    mult:2.2,    hotel:90, food:50, tag:'(apart-hotel)',  tips:[
    {i:'👨‍👩‍👧',t:'Apart-hotéis com cozinha economizam 40% em alimentação com crianças'},
    {i:'🎠',t:'Reserve parques e atrações com antecedência — ingressos até 25% mais baratos online'},
    {i:'🌡️',t:'Verifique vacinas e seguro-saúde que cubra crianças no destino'},
    {i:'✈️',t:'Crianças até 2 anos voam grátis (colo) na maioria das companhias'},
  ]},
  aventura:   { label:'🏔️ Aventura',   mult:1.5,    hotel:40, food:25, tag:'(lodge/camping)', tips:[
    {i:'🏔️',t:'Trilhas e parques nacionais são gratuitos ou muito baratos — foque nisso'},
    {i:'🎒',t:'Alugue equipamentos in-loco — mais barato do que trazer de casa'},
    {i:'🌤️',t:'Pesquise a janela climática do destino — mude datas se necessário'},
    {i:'🚐',t:'Vans compartilhadas entre destinos aventura custam 80% menos que transfer privado'},
  ]},
  gastro:     { label:'🍽️ Gastronômico',mult:2.0,   hotel:80, food:100,tag:'(hotel boutique)', tips:[
    {i:'🍷',t:'Mercados municipais têm os melhores produtos locais — vá cedo pela manhã'},
    {i:'🍽️',t:'Almoços em restaurantes com estrela Michelin custam 3x menos que o jantar'},
    {i:'📍',t:'Bairros sem turismo têm os restaurantes mais autênticos e baratos'},
    {i:'🎓',t:'Tours gastronômicos locais incluem degustações e valem muito o preço'},
  ]},
  cultural:   { label:'🏛️ Cultural',   mult:1.6,    hotel:60, food:30, tag:'(hotel central)',  tips:[
    {i:'🏛️',t:'Muitos museus têm entrada gratuita na primeira terça ou domingo do mês'},
    {i:'🎭',t:'Pesquise a programação cultural local com semanas de antecedência'},
    {i:'📚',t:'Free walking tours são excelentes — pague apenas a gorjeta ao final'},
    {i:'🗺️',t:'Fique no centro histórico — economia em transporte compensa o preço do hotel'},
  ]},
};


// ── Profile dropdown compacto ──
function eToggleTravProfileDrop(e) {
  e.stopPropagation();
  document.getElementById('etravProfileMenu')?.classList.toggle('open');
}

function eSetTravProfile(type, el) {
  eProfileType = type;
  eTravelerProfile = type; // sync para partner links
  const def = eProfileDefs[type] || eProfileDefs.mochileiro;
  const parts = def.label.split(' ');
  const icon = parts[0];
  const label = parts.slice(1).join(' ');
  // Update dropdown display
  const iconEl = document.getElementById('etravProfileIcon');
  const txtEl  = document.getElementById('etravProfileTxt');
  if(iconEl) iconEl.textContent = icon;
  if(txtEl)  txtEl.textContent  = label;
  // Mark active
  document.querySelectorAll('.etpd-item').forEach(i => i.classList.remove('on'));
  el.classList.add('on');
  document.getElementById('etravProfileMenu')?.classList.remove('open');
  // Sync the other profile dropdown in planner panel
  document.querySelectorAll('.epd-item').forEach(i => {
    i.classList.toggle('on', i.dataset.profile === type);
  });
  const dropIcon = document.getElementById('eProfileDropIcon');
  const dropLabel = document.getElementById('eProfileDropLabel');
  if(dropIcon) dropIcon.textContent = icon;
  if(dropLabel) dropLabel.textContent = label;
  // Update bar and re-render
  eUpdateTravelerBar();
  if(eRouteDone) eRenderResults();
  etoast(def.label + ' ativo', 'ai');
}

document.addEventListener('click', e => {
  if(!e.target.closest('#etravProfileDrop')) {
    document.getElementById('etravProfileMenu')?.classList.remove('open');
  }
});


function eToggleProfileDrop(e) {
  e.stopPropagation();
  document.getElementById('eProfileDropMenu').classList.toggle('open');
}
function eSetProfileDrop(type, icon, label, el) {
  // Update dropdown display
  document.getElementById('eProfileDropIcon').textContent = icon;
  document.getElementById('eProfileDropLabel').textContent = label;
  document.querySelectorAll('.epd-item').forEach(i => i.classList.remove('on'));
  el.classList.add('on');
  document.getElementById('eProfileDropMenu').classList.remove('open');
  // Set profile
  eProfileType = type;
  eUpdateTravelerBar();
  if(eRouteDone) eRenderResults();
  const def = eProfileDefs[type] || eProfileDefs.mochileiro;
  etoast(def.label + ' ativo', 'ai');
}
document.addEventListener('click', e => {
  if(!e.target.closest('#eProfileDropWrap')) {
    document.getElementById('eProfileDropMenu')?.classList.remove('open');
  }
});

function eSetProfile(el, type) {
  document.querySelectorAll('.epbadge-item').forEach(b => b.classList.remove('on'));

  eTravelerProfile = type; // sync  el.classList.add('on');
  eProfileType = type;
  eUpdateTravelerBar();
  if(eRouteDone) eRenderResults();
  const def = eProfileDefs[type] || eProfileDefs.mochileiro;
  etoast(def.label + ' ativo', 'ai');
}

// ═══════════════════════════════════════════════════
// SIMULATION
// ═══════════════════════════════════════════════════
const SIM_CITY_DATA = {
  // tips per city/airport code
  'GRU':{ weather:'🌤 Verão quente', cost:'R$120/dia', stay:'Hostel Vila Madalena', tip:'Metrô rápido ao centro' },
  'EZE':{ weather:'🌥 Primavera suave', cost:'€28/dia', stay:'Hostel El Camino', tip:'Tango no La Catedral!' },
  'LIM':{ weather:'🌫 Nublado típico', cost:'€22/dia', stay:'Hostel Kokopelli', tip:'Ceviche no Mercado Surquillo' },
  'BOG':{ weather:'☁️ Fresco e chuvoso', cost:'€20/dia', stay:'Hostel Masaya', tip:'Tour Ciudad Perdida' },
  'SCL':{ weather:'☀️ Ensolarado', cost:'€30/dia', stay:'Hostel Lastarria', tip:'Valle Nevado nos fins de semana' },
  'LIS':{ weather:'🌞 Mediterrâneo', cost:'€40/dia', stay:'Yes! Hostel', tip:'Tram 28 e pastéis de Belém' },
  'MAD':{ weather:'☀️ Seco e quente', cost:'€45/dia', stay:'Cats Hostel', tip:'Museu do Prado + tapas à noite' },
  'BCN':{ weather:'🌤 Agradável', cost:'€50/dia', stay:'Equity Point', tip:'Sagrada Família ao amanhecer' },
  'CDG':{ weather:'🌧 Nublado', cost:'€60/dia', stay:'Generator Hostel', tip:'Baguete e museu Orsay' },
  'AMS':{ weather:'🌦 Variável', cost:'€55/dia', stay:'Stayokay Hostel', tip:'Bicicleta pela Jordaan' },
  'BKK':{ weather:'🌡 Quente e úmido', cost:'€18/dia', stay:'Lub*d Hostel', tip:'Khao San Road à noite' },
  'KUL':{ weather:'⛈ Tropical', cost:'€15/dia', stay:'Reggae Mansion', tip:'Batu Caves de manhã cedo' },
  'NRT':{ weather:'🍂 Ameno', cost:'€65/dia', stay:'Grids Hostel', tip:'Shinjuku Gyoen at sunrise' },
  'DPS':{ weather:'☀️ Tropical', cost:'€25/dia', stay:'Puri Garden', tip:'Ubud Rice Terraces ao nascer do sol' },
  'DEF':{ weather:'🌍 Variável', cost:'€35/dia', stay:'Hostel local', tip:'Explore o bairro histórico' },
};

let eSimStep_idx = 0;
let eSimCities = [];

function eOpenSim(){
  const dests = eDests.filter(d=>d.ap);
  if(dests.length<2){ etoast('⚠️ Adicione destinos e planeje a rota','warn'); return; }
  eSimCities = dests;
  eSimStep_idx = 0;
  // Build dots
  const dotsEl = document.getElementById('esimDots');
  dotsEl.innerHTML = '';
  eSimCities.forEach((_,i)=>{
    const d=document.createElement('div');
    d.className='esim-pdot'+(i===0?' on':'');
    dotsEl.appendChild(d);
  });
  eRenderSimCity();
  document.getElementById('esimOverlay').classList.add('on');
}
function eCloseSim(){ document.getElementById('esimOverlay').classList.remove('on'); }

function eSimStep(dir){
  eSimStep_idx = Math.max(0, Math.min(eSimCities.length-1, eSimStep_idx+dir));
  eRenderSimCity();
  // Update dots
  document.querySelectorAll('.esim-pdot').forEach((d,i)=>d.classList.toggle('on',i===eSimStep_idx));
}

function eRenderSimCity(){
  const city = eSimCities[eSimStep_idx];
  const code = city.ap?.code||'DEF';
  const data = SIM_CITY_DATA[code]||SIM_CITY_DATA['DEF'];
  const label = city.ap ? `${city.ap.flag} ${city.ap.city}, ${city.ap.country}` : city.input;
  const totalDays = eDests.reduce((a,d,i)=>i<=eSimStep_idx?a+d.days:a,0)||eSimStep_idx+1;

  document.getElementById('esimCityName').textContent = label;
  document.getElementById('esimCityMeta').textContent = city.days>0?`${city.days} noites aqui`:'Passagem rápida';
  document.getElementById('esimDayBadge').textContent = `Dia ${totalDays}`;

  // Route text
  const from = eSimCities[Math.max(0,eSimStep_idx-1)];
  const to = city;
  const routeTxt = eSimStep_idx>0 ? `${from.ap?.city||from.input} → ${to.ap?.city||to.input}` : `${to.ap?.city||to.input} (Início)`;
  document.getElementById('esimRouteText').textContent = routeTxt;

  // Fill bar
  const pct = Math.round((eSimStep_idx/(eSimCities.length-1))*100);
  document.getElementById('esimRouteFill').style.width = pct+'%';
  document.getElementById('esimPlane').style.marginLeft = `calc(${pct}% - 16px)`;

  // Facts — use eFmtPrice for cost conversion
  const profDef = (typeof eProfileDefs !== 'undefined' && eProfileDefs[eProfileType]) ? eProfileDefs[eProfileType] : {mult:1};
  const baseEur = parseFloat((data.cost||'35').replace(/[^0-9.]/g,'')) || 35;
  const adjustedEur = baseEur * profDef.mult;
  const dailyCostFmt = eFmtPrice(adjustedEur);
  const travN = eTravelers.length;
  document.getElementById('esimCityFacts').innerHTML = `
    <div class="esim-fact">${data.weather}</div>
    <div class="esim-fact">💰 <strong>${dailyCostFmt}</strong>/pessoa</div>
    ${travN>1?`<div class="esim-fact">👥 ${travN} viajantes</div>`:''}
    <div class="esim-fact">🏨 <strong>${data.stay}</strong></div>
    <div class="esim-fact">💡 ${data.tip}</div>`;
}

window.addEventListener('resize',()=>{ if(eRouteDone) eRenderMap(); });

// ── Map zoom & pan ──────────────────────────
(function(){
  let scale = 1, ox = 0, oy = 0;
  let dragging = false, lastX, lastY;
  let pinchDist = null;

  function applyTransform() {
    const canvas = document.getElementById('emcanvas');
    if(!canvas) return;
    const inner = canvas.querySelector('#emsvg')?.parentElement || canvas;
    // Apply to all children
    [canvas.querySelector('#emsvg'), canvas.querySelector('#ecityMks')].forEach(el => {
      if(el) el.style.transform = `translate(${ox}px,${oy}px) scale(${scale})`;
    });
  }

  function setupMapInteraction() {
    const canvas = document.getElementById('emcanvas');
    if(!canvas || canvas._zoomSetup) return;
    canvas._zoomSetup = true;

    // Wheel zoom
    canvas.addEventListener('wheel', e => {
      e.preventDefault();
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      const delta = e.deltaY > 0 ? 0.85 : 1.18;
      const newScale = Math.min(5, Math.max(0.5, scale * delta));
      ox = mx - (mx - ox) * (newScale / scale);
      oy = my - (my - oy) * (newScale / scale);
      scale = newScale;
      applyTransform();
    }, {passive: false});

    // Mouse drag
    canvas.addEventListener('mousedown', e => {
      dragging = true; lastX = e.clientX; lastY = e.clientY;
      canvas.classList.add('panning');
    });
    document.addEventListener('mousemove', e => {
      if(!dragging) return;
      ox += e.clientX - lastX; oy += e.clientY - lastY;
      lastX = e.clientX; lastY = e.clientY;
      applyTransform();
    });
    document.addEventListener('mouseup', () => {
      dragging = false;
      document.getElementById('emcanvas')?.classList.remove('panning');
    });

    // Touch pinch & pan
    canvas.addEventListener('touchstart', e => {
      if(e.touches.length === 2) {
        const dx = e.touches[0].clientX - e.touches[1].clientX;
        const dy = e.touches[0].clientY - e.touches[1].clientY;
        pinchDist = Math.sqrt(dx*dx + dy*dy);
      } else if(e.touches.length === 1) {
        dragging = true;
        lastX = e.touches[0].clientX;
        lastY = e.touches[0].clientY;
      }
    }, {passive: true});
    canvas.addEventListener('touchmove', e => {
      e.preventDefault();
      if(e.touches.length === 2 && pinchDist) {
        const dx = e.touches[0].clientX - e.touches[1].clientX;
        const dy = e.touches[0].clientY - e.touches[1].clientY;
        const newDist = Math.sqrt(dx*dx + dy*dy);
        const delta = newDist / pinchDist;
        scale = Math.min(5, Math.max(0.5, scale * delta));
        pinchDist = newDist;
        applyTransform();
      } else if(e.touches.length === 1 && dragging) {
        ox += e.touches[0].clientX - lastX;
        oy += e.touches[0].clientY - lastY;
        lastX = e.touches[0].clientX;
        lastY = e.touches[0].clientY;
        applyTransform();
      }
    }, {passive: false});
    canvas.addEventListener('touchend', () => {
      dragging = false; pinchDist = null;
    });

    // Double-click reset
    canvas.addEventListener('dblclick', () => {
      scale = 1; ox = 0; oy = 0;
      applyTransform();
    });
  }

  // Add reset zoom button HTML when map renders
  const origRenderMap = window.eRenderMap;
  // Hook into DOMContentLoaded to setup after map is ready
  document.addEventListener('DOMContentLoaded', () => {
    // Add reset button to map
    const statsEl = document.getElementById('emstats');
    if(statsEl) {
      const resetBtn = document.createElement('button');
      resetBtn.className = 'emap-reset-btn';
      resetBtn.textContent = '⟲';
      resetBtn.title = 'Resetar zoom';
      resetBtn.onclick = () => { scale=1; ox=0; oy=0; applyTransform(); };
      statsEl.parentNode.appendChild(resetBtn);
    }
    setupMapInteraction();
  });

  // Also setup when route is planned
  const origEplan = window.eplan;
  window.eRenderMapHook = function() {
    setTimeout(setupMapInteraction, 200);
  };
})();


// ── Init (after DOM ready) ──────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const restored = eStorage.load();
  if (restored && typeof eCurrency === 'undefined') {
    // Currency is defined later — will be picked up on next save
  }
  eRenderDests();
  eUpdateTravelerBar();
  if (restored) {
    const f = eDests.filter(d => d.ap);
    if (f.length >= 2) etoast('📋 Roteiro anterior restaurado!', 'suc');
  }

  // Role select buttons in traveler modal
  document.querySelectorAll('.etrav-role-btn').forEach(btn => {
    btn.addEventListener('click', function(){
      document.querySelectorAll('.etrav-role-btn').forEach(b=>b.classList.remove('on'));
      this.classList.add('on');
      eSelectedRole = this.dataset.role;
    });
  });

  // Enter key in AI textarea
  const ta = document.getElementById('eaiPrompt');
  if(ta){
    ta.addEventListener('keydown', e => {
      if(e.key==='Enter' && !e.shiftKey){ e.preventDefault(); egenAI(); }
    });
  }

  // Enter key em qualquer campo de destino dispara Planejar Rota
  document.addEventListener('keydown', e => {
    if(e.key === 'Enter' && e.target.classList.contains('edinput')) {
      // Close autocomplete first
      document.querySelectorAll('.eacdrop').forEach(d => d.classList.remove('open'));
      // If we have at least 2 destinations, plan the route
      const filled = eDests.filter(d => d.ap);
      if(filled.length >= 2) {
        e.preventDefault();
        eplan();
      }
    }
  });
});

// Scroll reveal com IntersectionObserver
(function() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
  
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.feat, .dest-card, .testi-card, .hiw-step, .section-title, .section-tag, .perk, .hbadge').forEach((el, i) => {
      el.classList.add('reveal');
      if (i % 4 === 1) el.classList.add('reveal-delay-1');
      if (i % 4 === 2) el.classList.add('reveal-delay-2');
      if (i % 4 === 3) el.classList.add('reveal-delay-3');
      observer.observe(el);
    });
  });
})();

// Step tracker update
function eUpdateSteps() {
  const f = eDests.filter(d => d.ap || d.input);
  const hasStart = f.length > 0 && f[0].input;
  const hasDest = f.length > 1;
  const hasDates = eTotDays() > 0;
  const hasTrav = (typeof eTravelers !== 'undefined') && eTravelers.length > 0;
  const hasRoute = eRouteDone;

  const steps = [
    { id: 'estep1', done: hasDest, active: !hasDest && hasStart },
    { id: 'estep2', done: hasDates, active: hasDest && !hasDates },
    { id: 'estep3', done: hasTrav, active: hasDates && !hasTrav },
    { id: 'estep4', done: hasRoute, active: hasTrav && !hasRoute },
  ];
  steps.forEach(s => {
    const el = document.getElementById(s.id);
    if (!el) return;
    el.classList.toggle('done', s.done);
    el.classList.toggle('active', s.active && !s.done);
    el.querySelector('.estep-dot').textContent = s.done ? '✓' : steps.indexOf(s)+1+'';
  });
}



// ══════════════════════════════════════════════════════════════
// LEAFLET MAP — mapa real com OpenStreetMap
// ══════════════════════════════════════════════════════════════
let eLeafMap=null,eLeafMarkers=[],eLeafLines=[];

function eInitLeafletMap(){
  if(eLeafMap||!window.L)return;
  const el=document.getElementById('eLeafletMap');
  if(!el||el.offsetHeight<10)return;
  eLeafMap=L.map('eLeafletMap',{center:[-15,-50],zoom:3,zoomControl:true});
  L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png',{
    attribution:'\\u00a9 OpenStreetMap \\u00a9 CARTO',subdomains:'abcd',maxZoom:19
  }).addTo(eLeafMap);
}

function eHaversine(lat1,lng1,lat2,lng2){
  const R=6371,dLat=(lat2-lat1)*Math.PI/180,dLng=(lng2-lng1)*Math.PI/180;
  const a=Math.sin(dLat/2)**2+Math.cos(lat1*Math.PI/180)*Math.cos(lat2*Math.PI/180)*Math.sin(dLng/2)**2;
  return R*2*Math.atan2(Math.sqrt(a),Math.sqrt(1-a));
}

function eNearestAirport(lat,lng){
  let best=null,bestD=Infinity;
  for(const ap of eAirports){
    if(ap.lat==null||ap.lng==null)continue;
    const d=eHaversine(lat,lng,ap.lat,ap.lng);
    if(d<bestD){bestD=d;best=ap;}
  }
  return best?{ap:best,dist:Math.round(bestD)}:null;
}


function eNormCity(s){
  return (s||'').toLowerCase().normalize('NFD').replace(/[\\u0300-\\u036f]/g,'').trim();
}

function eResolveCityToAirport(input){
  // SÍNCRONO — sem Nominatim para não travar o browser
  if(!input||input.trim().length<2) return null;
  const q = eNormCity(input);

  // 1. Match fuzzy direto nos aeroportos
  const direct = eFuzzySearch(input, 1);
  if(direct.length && direct[0].score > 60) return {ap:direct[0], dist:0, direct:true};

  // 2. Match exato cidade/código
  if(q.length >= 3){
    const apExact = eAirports.find(a => eNormCity(a.city||'') === q);
    if(apExact) return {ap:apExact, dist:0, direct:true};
    const apCode = eAirports.find(a => (a.code||'').toLowerCase() === q);
    if(apCode) return {ap:apCode, dist:0, direct:true};
  }

  // 3. Match na eCityDB local (187 cidades, instantâneo)
  for(const [key, city] of Object.entries(eCityDB)){
    const k = eNormCity(key);
    if(q===k || (q.length>=4 && k.startsWith(q.slice(0,4))) || (k.length>=4 && q.startsWith(k.slice(0,4)))){
      const n = eNearestAirport(city.lat, city.lng);
      if(n) return {ap:n.ap, dist:n.dist, city, direct:false};
    }
  }

  // 4. Match parcial mais amplo
  if(q.length >= 3){
    for(const [key, city] of Object.entries(eCityDB)){
      const k = eNormCity(key);
      if(k.includes(q) || q.includes(k)){
        const n = eNearestAirport(city.lat, city.lng);
        if(n) return {ap:n.ap, dist:n.dist, city, direct:false};
      }
    }
    // Match parcial nos aeroportos
    const apPart = eAirports.find(a => {
      const cn = eNormCity(a.city||'');
      return cn.startsWith(q.slice(0,3)) || cn.includes(q.slice(0,4));
    });
    if(apPart) return {ap:apPart, dist:0, direct:true};
  }

  return null; // não encontrado — sem await, sem freeze
}

function eRenderLeafletMap(){
  if(!eLeafMap) eInitLeafletMap();
  if(!eLeafMap) return;
  eLeafMarkers.forEach(m=>m.remove()); eLeafLines.forEach(l=>l.remove());
  eLeafMarkers=[]; eLeafLines=[];
  const dests=eDests.filter(d=>d.ap&&d.ap.lat!=null&&d.ap.lng!=null);
  if(!dests.length) return;
  const tColors={plane:'#1a6fb5',train:'#f05a28',bus:'#00a896',ferry:'#f0a500',drive:'#7c5cbf'};
  // Linhas com arco suave
  for(let i=0;i<dests.length-1;i++){
    const a=dests[i].ap,b=dests[i+1].ap,t=(eGetT(a.code,b.code)[0]?.type||"plane"),color=tColors[t]||'#8fa3b8';
    const pts=[],steps=20;
    for(let j=0;j<=steps;j++){
      const r=j/steps,lt=a.lat+(b.lat-a.lat)*r,ln=a.lng+(b.lng-a.lng)*r;
      const dist=eHaversine(a.lat,a.lng,b.lat,b.lng);
      pts.push([lt+(dist>500?Math.sin(r*Math.PI)*Math.min(dist*0.025,5):0),ln]);
    }
    const line=L.polyline(pts,{color,weight:2.5,opacity:.8,dashArray:t==='plane'?'8,5':null}).addTo(eLeafMap);
    line.bindTooltip('<b>'+dests[i].input+'→'+dests[i+1].input+'</b><br>'+Math.round(eHaversine(a.lat,a.lng,b.lat,b.lng))+' km',{sticky:true});
    eLeafLines.push(line);
  }
  // Marcadores
  dests.forEach((d,i)=>{
    const ap=d.ap,isF=i===0,isL=i===dests.length-1;
    const color=isF?'#00a896':isL?'#f05a28':'#1a6fb5',sz=isF||isL?16:12;
    const icon=L.divIcon({className:'',html:'<div style="width:'+sz+'px;height:'+sz+'px;border-radius:50%;background:'+color+';border:2.5px solid white;box-shadow:0 2px 8px rgba(0,0,0,.3)"></div>',iconSize:[sz,sz],iconAnchor:[sz/2,sz/2]});
    const m=L.marker([ap.lat,ap.lng],{icon}).addTo(eLeafMap);
    m.bindPopup('<b style="color:#1a2d3d;font-size:.9rem">'+(d.city?d.city.name||ap.city:ap.city)+'</b><br><span style="color:#8fa3b8;font-size:.75rem">\\u2708 '+ap.code+' \\u2014 '+ap.name+'</span>'+(d.dist>0?'<br><span style="color:#00a896;font-size:.75rem">\\u{1F4CD} '+d.dist+' km do centro</span>':'')+(d.days?'<br><span style="color:#1a6fb5;font-size:.75rem">\\u{1F319} '+d.days+' dias</span>':''),{maxWidth:200});
    eLeafMarkers.push(m);
  });
  if(dests.length>=2){
    eLeafMap.fitBounds(L.latLngBounds(dests.map(d=>[d.ap.lat,d.ap.lng])),{padding:[50,50]});
  } else if(dests.length===1){
    eLeafMap.setView([dests[0].ap.lat,dests[0].ap.lng],7);
  }
  const sb=document.getElementById('emStatsBar');
  if(sb){
    sb.style.display='flex';
    const td=dests.reduce((s,d,i)=>i===0?0:s+eHaversine(dests[i-1].ap.lat,dests[i-1].ap.lng,d.ap.lat,d.ap.lng),0);
    document.getElementById('emStatCities').textContent=dests.length;
    document.getElementById('emStatDist').textContent=Math.round(td).toLocaleString('pt-BR');
    document.getElementById('emStatDays').textContent=eTotDays();
  }
}

// ══════════════════════════════════════════════════════════════
// PARCEIROS — Links estilo Rome2Rio
// ══════════════════════════════════════════════════════════════
const ePartners={
  plane:[
    {name:'Google Flights',icon:'\\u2708\\uFE0F',color:'#1a73e8',url:function(f,t){return 'https://www.google.com/travel/flights?q=Flights+to+'+encodeURIComponent(t)+'+from+'+encodeURIComponent(f);}},
    {name:'Decolar',icon:'\\u{1F6EB}',color:'#e63946',url:function(f,t){return 'https://www.decolar.com/shop/flights';}},
    {name:'Kayak',icon:'\\u{1F50D}',color:'#ff690f',url:function(f,t){return 'https://www.kayak.com.br/flights/'+encodeURIComponent(f)+'-'+encodeURIComponent(t);}},
    {name:'LATAM',icon:'\\u{1F534}',color:'#e40000',url:function(f,t){return 'https://www.latamairlines.com/br/pt/oferta-voos?origin='+f+'&destination='+t;}},
    {name:'GOL',icon:'\\u{1F7E0}',color:'#f47a20',url:function(f,t){return 'https://www.voegol.com.br';}},
    {name:'Azul',icon:'\\u{1F535}',color:'#003399',url:function(f,t){return 'https://www.voeazul.com.br';}},
  ],
  train:[
    {name:'Raileurope',icon:'\\u{1F684}',color:'#e4002b',url:function(f,t){return 'https://www.raileurope.com';}},
    {name:'Eurail',icon:'\\u{1F30D}',color:'#004a97',url:function(f,t){return 'https://www.eurail.com';}},
    {name:'Interrail',icon:'\\u{1F682}',color:'#00843d',url:function(f,t){return 'https://www.interrail.eu';}},
    {name:'DB Bahn',icon:'\\u{1F1E9}\\u{1F1EA}',color:'#d60b0b',url:function(f,t){return 'https://www.bahn.com';}},
  ],
  bus:[
    {name:'Clickbus',icon:'\\u{1F3AB}',color:'#ff4a4a',url:function(f,t){return 'https://www.clickbus.com.br/passagens-de-onibus/?from='+encodeURIComponent(f)+'&to='+encodeURIComponent(t);}},
    {name:'Busbud',icon:'\\u{1F68C}',color:'#295ba7',url:function(f,t){return 'https://www.busbud.com/pt';}},
    {name:'FlixBus',icon:'\\u{1F7E2}',color:'#73d700',url:function(f,t){return 'https://www.flixbus.com.br';}},
    {name:'GuichêNet',icon:'\\u{1F3DF}\\uFE0F',color:'#005baa',url:function(f,t){return 'https://www.guichenet.com.br';}},
  ],
  ferry:[
    {name:'Directferries',icon:'\\u26F4\\uFE0F',color:'#0077be',url:function(f,t){return 'https://www.directferries.com';}},
    {name:'Ferrysavers',icon:'\\u{1F6A2}',color:'#1e90ff',url:function(f,t){return 'https://www.ferrysavers.co.uk';}},
  ],
  drive:[
    {name:'Localiza',icon:'\\u{1F697}',color:'#00a84f',url:function(f,t){return 'https://www.localiza.com';}},
    {name:'Movida',icon:'\\u{1F511}',color:'#e30613',url:function(f,t){return 'https://www.movida.com.br';}},
    {name:'Hertz',icon:'\\u{1F30D}',color:'#ffb400',url:function(f,t){return 'https://www.hertz.com.br';}},
    {name:'Google Maps',icon:'\\u{1F5FA}\\uFE0F',color:'#4285f4',url:function(f,t){return 'https://www.google.com/maps/dir/'+encodeURIComponent(f)+'/'+encodeURIComponent(t);}},
  ],
};

const eAccomPartners={
  mochileiro:[
    {name:'Hostelworld',icon:'\\u{1F3D5}\\uFE0F',color:'#e07b39',url:function(c){return 'https://www.hostelworld.com/st/hostels/'+encodeURIComponent(c);}},
    {name:'Booking Hostels',icon:'\\u{1F3E0}',color:'#003580',url:function(c){return 'https://www.booking.com/hostels/';}},
    {name:'Airbnb',icon:'\\u{1F3E1}',color:'#ff5a5f',url:function(c){return 'https://www.airbnb.com.br/s/'+encodeURIComponent(c);}},
  ],
  economico:[
    {name:'Booking.com',icon:'\\u{1F3E8}',color:'#003580',url:function(c){return 'https://www.booking.com/searchresults.html?ss='+encodeURIComponent(c);}},
    {name:'HotelUrbano',icon:'\\u{1F3A9}',color:'#e40023',url:function(c){return 'https://www.hotelurbano.com';}},
    {name:'Airbnb',icon:'\\u{1F3E1}',color:'#ff5a5f',url:function(c){return 'https://www.airbnb.com.br/s/'+encodeURIComponent(c);}},
  ],
  conforto:[
    {name:'Booking.com',icon:'\\u{1F3E8}',color:'#003580',url:function(c){return 'https://www.booking.com/searchresults.html?ss='+encodeURIComponent(c)+'&nflt=class%3D4';}},
    {name:'Hotels.com',icon:'\\u2B50',color:'#d32f2f',url:function(c){return 'https://www.hotels.com';}},
    {name:'Decolar Hotéis',icon:'\\u{1F3A8}',color:'#e63946',url:function(c){return 'https://www.decolar.com/shop/hotels';}},
  ],
  luxo:[
    {name:'The Leading Hotels',icon:'\\u2728',color:'#c9a227',url:function(c){return 'https://www.lhw.com';}},
    {name:'Mr & Mrs Smith',icon:'\\u{1F48E}',color:'#2c2c2c',url:function(c){return 'https://www.mrandmrssmith.com/search/?destination='+encodeURIComponent(c);}},
    {name:'Booking Luxo',icon:'\\u{1F451}',color:'#003580',url:function(c){return 'https://www.booking.com/searchresults.html?ss='+encodeURIComponent(c)+'&nflt=class%3D5';}},
  ],
  familia:[
    {name:'Booking Família',icon:'\\u{1F46A}',color:'#003580',url:function(c){return 'https://www.booking.com/searchresults.html?ss='+encodeURIComponent(c)+'&nflt=hotelfacility%3D28';}},
    {name:'Club Med',icon:'\\u26F1\\uFE0F',color:'#009b77',url:function(c){return 'https://www.clubmed.com.br';}},
    {name:'Airbnb Casas',icon:'\\u{1F3E0}',color:'#ff5a5f',url:function(c){return 'https://www.airbnb.com.br/s/'+encodeURIComponent(c);}},
  ],
  aventura:[
    {name:'Booking.com',icon:'\\u{1F3E8}',color:'#003580',url:function(c){return 'https://www.booking.com/searchresults.html?ss='+encodeURIComponent(c);}},
    {name:'Hostelworld',icon:'\\u{1F3D5}\\uFE0F',color:'#e07b39',url:function(c){return 'https://www.hostelworld.com';}},
    {name:'Airbnb',icon:'\\u{1F3E1}',color:'#ff5a5f',url:function(c){return 'https://www.airbnb.com.br/s/'+encodeURIComponent(c);}},
  ],
};

function eTransportLabel(t){return {plane:'Avião',train:'Trem',bus:'Ônibus',ferry:'Ferry',drive:'Carro'}[t]||t;}

function eBuildPartnerLinks(transport,fromCity,toCity,fromCode,toCode){
  const ps=ePartners[transport]||ePartners.plane;
  return ps.slice(0,4).map(function(p){
    const href=p.url(fromCode||fromCity,toCode||toCity);
    return '<a href="'+href+'" target="_blank" rel="noopener" class="epartner-link" style="--pc:'+p.color+'"><span class="epl-icon">'+p.icon+'</span><span class="epl-name">'+p.name+'</span><span class="epl-arrow">\\u2197</span></a>';
  }).join('');
}

function eBuildAccomLinks(city,profile){
  const ps=(eAccomPartners[profile]||eAccomPartners.conforto);
  const prices={mochileiro:'~R$60/noite',economico:'~R$150/noite',conforto:'~R$300/noite',luxo:'~R$800/noite',familia:'~R$350/noite',aventura:'~R$90/noite'};
  const price=prices[profile]||'~R$200/noite';
  return '<div class="eaccom-header"><span class="eaccom-price">'+price+'</span><span class="eaccom-label"> em '+city+'</span></div>'
    +ps.map(function(p){return '<a href="'+p.url(city)+'" target="_blank" rel="noopener" class="epartner-link" style="--pc:'+p.color+'"><span class="epl-icon">'+p.icon+'</span><span class="epl-name">'+p.name+'</span><span class="epl-arrow">\\u2197</span></a>';}).join('');
}

// ══════════════════════════════════════════════════════════════
// RESOLVE CIDADES ao digitar no campo
// ══════════════════════════════════════════════════════════════
function eSmartResolve(destObj){
  if(destObj.ap) return; // já tem aeroporto
  const result=eResolveCityToAirport(destObj.input);
  if(result){
    destObj.ap=result.ap;
    destObj.dist=result.dist||0;
    destObj.city=result.city||null;
    if(!result.direct && result.dist>0){
      etoast('\\u{1F4CD} '+destObj.input+' \\u2192 aeroporto mais próximo: '+result.ap.code+' ('+result.dist+' km)','ai');
    }
  }
}



function eGenBudgetPlan(){
  const slider = document.getElementById('eBudgetSlider');
  const totalBRL = slider ? parseInt(slider.value) : 3000;
  const f = eDests.filter(d=>d.ap);
  if(!f.length){ etoast('Planeje uma rota primeiro','warn'); return; }
  const profile = eTravelerProfile||'conforto';
  const days = eTotDays();
  const cats = [
    {icon:'✈️',name:'Transporte',pct:35,color:'var(--sky)'},
    {icon:'🏨',name:'Hospedagem',pct:30,color:'var(--gold)'},
    {icon:'🍽️',name:'Alimentação',pct:20,color:'var(--teal)'},
    {icon:'🗺️',name:'Passeios',pct:10,color:'var(--lilac)'},
    {icon:'🛍️',name:'Extras',pct:5,color:'var(--coral)'},
  ];
  const dest = f[f.length-1];
  const rate = (eCurrencyRates[eCurrency]||{rate:1}).rate;
  let out = '<div style="background:var(--surface);border:1.5px solid var(--mist);border-radius:var(--radius-md);padding:14px;box-shadow:var(--shadow-sm)">';
  out += '<div style="font-family:var(--font-body);font-size:.65rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--slate);margin-bottom:10px">📊 Distribuição — '+eFmtPrice(totalBRL/rate)+'</div>';
  out += cats.map(function(c){
    var val=Math.round(totalBRL*c.pct/100);
    return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">'
      +'<span style="font-size:.85rem">'+c.icon+'</span>'
      +'<div style="flex:1"><div style="font-family:var(--font-body);font-size:.7rem;font-weight:600;color:var(--ink);margin-bottom:3px">'+c.name+'</div>'
      +'<div style="background:var(--surface-2);border-radius:var(--radius-full);height:6px"><div style="width:'+c.pct+'%;height:100%;background:'+c.color+';border-radius:var(--radius-full)"></div></div></div>'
      +'<span style="font-family:var(--font-body);font-size:.75rem;font-weight:700;color:var(--ink);min-width:58px;text-align:right">'+eFmtPrice(val/rate)+'</span></div>';
  }).join('');
  out += '<div style="margin-top:12px"><span class="epartner-label">🏨 Hospedagem em '+dest.input+'</span>';
  out += '<div class="epartner-links">'+eBuildAccomLinks(dest.input,profile)+'</div></div>';
  out += '</div>';
  var el = document.getElementById('eBudgetPlanResult');
  if(el){ el.innerHTML=out; el.style.display='block'; }
  etoast('✦ Plano gerado!','ai');
}




function eAcSelect(i, code) {
  const ap = eAPS.find(a => a.code === code);
  if(!ap) return;
  // Fechar dropdown
  const drop = document.getElementById('eac'+i);
  if(drop) drop.classList.remove('open');
  // Setar aeroporto no destino
  eDests[i].ap = ap;
  eDests[i].input = eSanitize(ap.city);
  eDests[i].dist = 0;
  eDests[i].city = null;
  // Atualizar input field
  const inputs = document.querySelectorAll('.edinput');
  if(inputs[i]) inputs[i].value = ap.city;
  eRenderDests();
  etoast('✈️ ' + ap.city + ' (' + ap.code + ') selecionado', 'suc');
}

function eAcSelectCity(i, cityName, lat, lng, country) {
  const drop = document.getElementById('eac'+i);
  if(drop) drop.classList.remove('open');
  const inp = document.querySelectorAll('.edinput')[i];
  if(inp) inp.value = cityName;
  eDests[i].input = eSanitizeCity(cityName);
  eDests[i].ap = null;
  eDests[i].dist = 0;
  eDests[i].city = lat ? {name: cityName, lat, lng, country} : null;

  if(lat && lng) {
    const nearest = eNearestAirport(lat, lng);
    if(nearest) {
      eDests[i].ap = nearest.ap;
      eDests[i].dist = nearest.dist;
      eDests[i].city = {name: cityName, lat, lng, country};
      eRenderDests();
      if(nearest.dist > 0) {
        etoast('📍 ' + cityName + ' → ✈️ ' + nearest.ap.code + ' ' + nearest.ap.city + ' (' + nearest.dist + ' km)', 'ai');
      }
      return;
    }
  }

  // Sem coords: mostrar "resolvendo" e resolver em background
  eRenderDests();
  // Mostrar badge de resolvendo no campo
  const tag = document.querySelector('#eac'+i+' ~ .eaptag') || document.querySelectorAll('.eaptag')[i];
  etoast('⏳ Buscando aeroporto para "' + cityName + '"...', 'warn');

  eResolveCityToAirport(cityName).then(r => {
    if(r) {
      eDests[i].ap = r.ap;
      eDests[i].dist = r.dist||0;
      eDests[i].city = r.city || {name: cityName};
      eRenderDests();
      etoast('✅ ' + cityName + ' → ✈️ ' + r.ap.code + ' (' + (r.dist||0) + ' km)', 'suc');
    } else {
      etoast('⚠️ Aeroporto não encontrado para "' + cityName + '" — tente outro nome', 'warn');
    }
  }).catch(()=>{
    etoast('⚠️ Erro ao buscar aeroporto. Tente digitar o código IATA.', 'warn');
  });
}
function eShubSelectCity(el, field, cityName, lat, lng) {
  const acEl = el.closest('.shub-ac');
  if(acEl) acEl.classList.remove('open');

  const inputId = field === 'origin' ? 'shubOriginInput' : 'shubDestInput';
  const inp = document.getElementById(inputId);
  if(inp) inp.value = cityName;

  if(lat && lng) {
    const nearest = eNearestAirport(lat, lng);
    if(nearest) {
      const apObj = {...nearest.ap, _cityName: cityName, _dist: nearest.dist, _displayName: cityName};
      if(field === 'origin') {
        _shubOriginAp = apObj;
      } else {
        if(!_shubDests.find(d => d._cityName === cityName)) _shubDests.push(apObj);
      }
      eRenderShubTags();
      if(nearest.dist > 0) etoast('📍 ' + cityName + ' → ✈️ ' + nearest.ap.code + ' (' + nearest.dist + ' km)', 'ai');
      return;
    }
  }

  // Resolver síncronamente via eCityDB
  const rr = eResolveCityToAirport(cityName);
  if(rr){
    const apObj = {...rr.ap, _cityName: cityName, _dist: rr.dist||0, _displayName: cityName};
    if(field === 'origin'){
      _shubOriginAp = apObj;
    } else {
      if(!_shubDests.find(d => d._cityName === cityName)) _shubDests.push(apObj);
    }
    eRenderShubTags();
    if(rr.dist>0) etoast('📍 ' + cityName + ' → ✈️ ' + rr.ap.code + ' (' + rr.dist + ' km)', 'suc');
  } else {
    etoast('⚠️ "' + cityName + '" não encontrado — tente o nome do aeroporto', 'warn');
  }
}

function ePrintRoute() {
  // Abrir janela de impressão com conteúdo formatado
  const title = document.getElementById('eroute-title-text')?.textContent || 'Meu Roteiro';
  const segs = Array.from(document.querySelectorAll('.esegcard')).map(s => {
    const cities = s.querySelector('.esegcities')?.innerText || '';
    const codes = s.querySelector('.esegcodes')?.textContent || '';
    const opts = s.querySelector('.esegopts')?.textContent || '';
    const transfers = Array.from(s.querySelectorAll('.etransfer-leg')).map(t => t.textContent).join('\n');
    return cities + '\n' + codes + '\n' + opts + (transfers ? '\n' + transfers : '');
  }).join('\n\n');
  const cost = document.querySelector('.ecostbox')?.innerText || '';
  const days = document.getElementById('ectotalSub')?.textContent || '';
  
  const win = window.open('', '_blank');
  win.document.write(`<!DOCTYPE html><html><head><title>${title}</title>
<style>
  body { font-family: 'Plus Jakarta Sans', sans-serif; max-width: 800px; margin: 40px auto; color: #1a2d3d; font-size: 14px; }
  h1 { font-size: 2rem; margin-bottom: 8px; color: #0f4c81; }
  .subtitle { color: #8fa3b8; margin-bottom: 24px; font-size: .9rem; }
  .seg { border: 1px solid #e2eaf2; border-radius: 10px; padding: 14px; margin-bottom: 12px; }
  .seg-title { font-weight: 700; font-size: 1rem; margin-bottom: 4px; color: #1a2d3d; }
  .seg-meta { font-size: .8rem; color: #8fa3b8; }
  .transfer { background: #fff8e6; border-left: 3px solid #f0a500; padding: 6px 10px; margin: 6px 0; border-radius: 4px; font-size: .78rem; }
  .total { background: #e8f4fb; border-radius: 10px; padding: 16px; margin-top: 16px; }
  .total h3 { margin: 0 0 8px; color: #0f4c81; }
  @media print { body { margin: 20px; } }
</style>
</head><body>
<h1>✈️ ${title}</h1>
<div class="subtitle">${days} · Gerado pelo NomadRoute</div>
`);
  
  document.querySelectorAll('.esegcard').forEach(s => {
    const cities = s.querySelector('.esegcities')?.innerText?.replace(/\n/g, ' ') || '';
    const codes = s.querySelector('.esegcodes')?.textContent || '';
    const opts = s.querySelector('.esegopts')?.textContent || '';
    const legs = Array.from(s.querySelectorAll('.etransfer-leg'));
    win.document.write(`<div class="seg">
      <div class="seg-title">${cities}</div>
      <div class="seg-meta">${codes} · ${opts}</div>
      ${legs.map(l=>'<div class="transfer">'+l.textContent+'</div>').join('')}
    </div>`);
  });
  
  const costBox = document.querySelector('.ecostbox');
  if(costBox) win.document.write('<div class="total"><h3>💰 Estimativa de Custos</h3>' + costBox.innerText.replace(/\n/g,'<br>') + '</div>');
  
  win.document.write('<\/body><\/html>');
  win.document.close();
  setTimeout(() => win.print(), 500);
}


function eMoveDest(i, direction) {
  const newIdx = i + direction;
  if(newIdx < 1 || newIdx >= eDests.length - 1) return; // não mover origem/destino
  const temp = eDests[i];
  eDests[i] = eDests[newIdx];
  eDests[newIdx] = temp;
  eRenderDests();
}


function eInitHomeMap() {
  if(!window.L) return;
  const el = document.getElementById('homeMap');
  if(!el || el._leaflet_id) return;
  const map = L.map('homeMap', {center:[20,10],zoom:2,zoomControl:false,attributionControl:false,scrollWheelZoom:false});
  L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png',{subdomains:'abcd',maxZoom:10}).addTo(map);
  const dests = [
    {name:'Paris',lat:48.85,lng:2.35,emoji:'🗼'},
    {name:'Tokyo',lat:35.68,lng:139.69,emoji:'🗾'},
    {name:'New York',lat:40.71,lng:-74.00,emoji:'🗽'},
    {name:'Rio de Janeiro',lat:-22.90,lng:-43.17,emoji:'🌴'},
    {name:'Santorini',lat:36.39,lng:25.46,emoji:'🏛️'},
    {name:'Machu Picchu',lat:-13.16,lng:-72.54,emoji:'🏔️'},
    {name:'Bali',lat:-8.34,lng:115.09,emoji:'🌺'},
    {name:'São Paulo',lat:-23.55,lng:-46.63,emoji:'🌇'},
    {name:'Dubai',lat:25.20,lng:55.27,emoji:'🏙️'},
    {name:'Lisboa',lat:38.71,lng:-9.14,emoji:'🐚'},
    {name:'Buenos Aires',lat:-34.60,lng:-58.38,emoji:'💃'},
    {name:'Bangkok',lat:13.75,lng:100.52,emoji:'🛕'},
  ];
  dests.forEach(d => {
    const icon = L.divIcon({className:'',html:'<div style="background:white;border:2px solid #1a6fb5;border-radius:50%;width:30px;height:30px;display:flex;align-items:center;justify-content:center;font-size:14px;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.2)">' + d.emoji + '</div>',iconSize:[30,30],iconAnchor:[15,15]});
    const m = L.marker([d.lat, d.lng], {icon}).addTo(map);
    m.bindPopup('<b style="color:#0f4c81">' + d.name + '</b><br><a href="#" onclick="openAppWith(\'' + d.name + '\');return false;" style="color:#f05a28;font-weight:600;font-size:.78rem">Planejar →</a>');
  });
}
window.addEventListener('load', function(){ if(window.L) setTimeout(eInitHomeMap, 1000); });



function eQuickProfile(type, btn) {
  eProfileType = type;
  eTravelerProfile = type;
  eStorage.autoSave();
  var defs = {
    mochileiro:{icon:'🎒',label:'Mochileiro'},
    economico:{icon:'💰',label:'Econômico'},
    conforto:{icon:'⭐',label:'Conforto'},
    luxo:{icon:'✨',label:'Luxo'},
    familia:{icon:'👨‍👩‍👧',label:'Família'},
    aventura:{icon:'🏔️',label:'Aventura'},
    gastro:{icon:'🍜',label:'Gastronômico'},
    cultural:{icon:'🏛️',label:'Cultural'},
  };
  var def = defs[type] || defs.mochileiro;
  document.querySelectorAll('.epqchip').forEach(function(c){
    c.classList.toggle('on', c.dataset.p === type);
  });
  var av = document.getElementById('etavMain');
  if(av) av.textContent = def.icon;
  var sub = document.getElementById('etravSub');
  if(sub) sub.textContent = def.label + ' · Clique para editar';
  document.querySelectorAll('.etpd-item,.epd-item,.epbadge-item').forEach(function(el){
    el.classList.toggle('on', (el.dataset.type||el.dataset.profile) === type);
  });
  var di = document.getElementById('etravProfileIcon');
  var dl = document.getElementById('etravProfileTxt');
  if(di) di.textContent = def.icon;
  if(dl) dl.textContent = def.label;
  if(typeof eRouteDone !== 'undefined' && eRouteDone && typeof eRenderResults === 'function') eRenderResults();
  if(typeof etoast === 'function') etoast(def.icon + ' ' + def.label + ' ativo', 'ai');
}

