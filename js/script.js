// Populate CIDR
const cidrSel = document.getElementById('cidrInput');
for (let i = 1; i <= 32; i++) {
  const o = document.createElement('option');
  o.value = i;
  o.textContent = `/${i}`;
  if (i === 24) o.selected = true;
  cidrSel.appendChild(o);
}

function ipToLong(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (let p of parts) {
    const x = parseInt(p);
    if (isNaN(x) || x < 0 || x > 255) return null;
    n = (n << 8) | x;
  }
  return n >>> 0;
}

function longToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

function toBinary(n, bits=8) {
  return n.toString(2).padStart(bits, '0');
}

function calculate() {
  const ipRaw = document.getElementById('ipInput').value.trim();
  const cidr = parseInt(document.getElementById('cidrInput').value);
  const err = document.getElementById('errorMsg');
  const results = document.getElementById('results');

  const ipLong = ipToLong(ipRaw);
  if (ipLong === null) {
    err.style.display = 'block';
    results.classList.remove('visible');
    return;
  }
  err.style.display = 'none';

  // Calculations
  const maskLong = cidr === 0 ? 0 : (0xFFFFFFFF << (32 - cidr)) >>> 0;
  const networkLong = (ipLong & maskLong) >>> 0;
  const broadcastLong = (networkLong | (~maskLong >>> 0)) >>> 0;
  const wildcard = ~maskLong >>> 0;
  const totalHosts = Math.pow(2, 32 - cidr);
  const usableHosts = cidr >= 31 ? (cidr === 32 ? 1 : 2) : Math.max(0, totalHosts - 2);
  const firstHost = cidr >= 31 ? networkLong : networkLong + 1;
  const lastHost = cidr >= 31 ? broadcastLong : broadcastLong - 1;

  const networkIp = longToIp(networkLong);
  const broadcastIp = longToIp(broadcastLong);
  const maskIp = longToIp(maskLong);
  const wildcardIp = longToIp(wildcard);
  const firstHostIp = longToIp(firstHost);
  const lastHostIp = longToIp(lastHost);

  // Class
  const firstOctet = (networkLong >>> 24) & 255;
  let ipClass = firstOctet < 128 ? 'A' : firstOctet < 192 ? 'B' : firstOctet < 224 ? 'C' : firstOctet < 240 ? 'D' : 'E';

  // Private?
  let isPrivate = false;
  if (firstOctet === 10) isPrivate = true;
  if (firstOctet === 172 && ((networkLong >>> 16) & 255) >= 16 && ((networkLong >>> 16) & 255) <= 31) isPrivate = true;
  if (firstOctet === 192 && ((networkLong >>> 16) & 255) === 168) isPrivate = true;

  // Info table
  const rows = [
    ['ENDEREÇO', `${longToIp(ipLong)}`],
    ['REDE', `${networkIp} <span class="tag network">/NETWORK</span>`],
    ['BROADCAST', `${broadcastIp} <span class="tag broadcast">/BROADCAST</span>`],
    ['MÁSCARA', maskIp],
    ['WILDCARD', wildcardIp],
    ['1º HOST', `${firstHostIp} <span class="tag host">/USÁVEL</span>`],
    ['ÚLTIMO HOST', lastHostIp],
    ['CLASSE', `Classe ${ipClass}${isPrivate ? ' <span class="tag host">PRIVADO</span>' : ''}`],
    ['TOTAL IPs', totalHosts.toLocaleString('pt-BR')],
    ['HOSTS USÁVEIS', usableHosts.toLocaleString('pt-BR')],
  ];

  const tbl = document.getElementById('infoTable');
  tbl.innerHTML = rows.map(([k,v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join('');

  // PIE CHART
  drawPie(totalHosts, usableHosts, cidr);

  // GAUGE
  drawGauge(cidr);
  document.getElementById('gaugeVal').textContent = `/${cidr}`;

  // MASK OCTETS
  drawMaskOctets(maskLong);

  // BINARY GRID
  drawBinaryGrid(ipLong, networkLong, broadcastLong, maskLong, cidr);

  // HOSTS INFO
  const hostsInfo = document.getElementById('hostsInfo');
  const pct = totalHosts > 0 ? Math.min(100, (usableHosts / totalHosts) * 100) : 0;
  hostsInfo.innerHTML = `
    <span style="color:var(--green);font-size:22px;font-family:'Orbitron',monospace">${usableHosts.toLocaleString('pt-BR')}</span>
    <span style="color:var(--dim);font-size:12px;margin-left:8px;">hosts utilizáveis de ${totalHosts.toLocaleString('pt-BR')} endereços totais</span>
  `;
  setTimeout(() => {
    document.getElementById('hostsBar').style.width = pct.toFixed(1) + '%';
  }, 100);

  // SUBNETS LIST (show first 32 subnets if splitting)
  const subnetsContainer = document.getElementById('subnetsContainer');
  if (cidr < 28) {
    const showCidr = Math.min(cidr + 4, 30);
    const subnetCount = Math.pow(2, showCidr - cidr);
    const subSize = Math.pow(2, 32 - showCidr);
    let html = `<div style="margin-top:16px;font-size:11px;color:var(--dim);letter-spacing:2px;margin-bottom:8px;">SUBNETS /${showCidr} DENTRO DESTA REDE (${subnetCount} sub-redes):</div><div class="subnets-grid">`;
    for (let i = 0; i < Math.min(subnetCount, 64); i++) {
      const snNet = (networkLong + i * subSize) >>> 0;
      const snBc = (snNet + subSize - 1) >>> 0;
      html += `<div class="subnet-card"><div class="sn-addr">${longToIp(snNet)}/${showCidr}</div><span style="color:var(--dim);font-size:10px">${longToIp(snNet+1)} — ${longToIp(snBc-1)}</span></div>`;
    }
    if (subnetCount > 64) html += `<div class="subnet-card" style="color:var(--dim)">... +${(subnetCount-64).toLocaleString()} mais</div>`;
    html += '</div>';
    subnetsContainer.innerHTML = html;
  } else {
    subnetsContainer.innerHTML = '';
  }

  results.classList.add('visible');
}

// ---- PIE CHART ----
function drawPie(total, usable, cidr) {
  const canvas = document.getElementById('pieCanvas');
  const ctx = canvas.getContext('2d');
  const cx = 90, cy = 90, r = 75;
  ctx.clearRect(0, 0, 180, 180);

  const overhead = total - usable; // network + broadcast
  const slices = cidr >= 31 ? [
    { val: total, color: '#00ff88', label: 'Usáveis' }
  ] : [
    { val: usable, color: '#00ff88', label: 'Hosts Usáveis' },
    { val: 1, color: '#00e5ff', label: 'Rede' },
    { val: 1, color: '#ff6b35', label: 'Broadcast' },
  ];

  let startAngle = -Math.PI / 2;
  slices.forEach(s => {
    const angle = (s.val / total) * 2 * Math.PI;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, startAngle, startAngle + angle);
    ctx.closePath();
    ctx.fillStyle = s.color;
    ctx.fill();

    // inner glow
    const grad = ctx.createRadialGradient(cx, cy, r*0.5, cx, cy, r);
    grad.addColorStop(0, 'rgba(255,255,255,0.05)');
    grad.addColorStop(1, 'rgba(0,0,0,0.3)');
    ctx.fillStyle = grad;
    ctx.fill();

    startAngle += angle;
  });

  // Center hole
  ctx.beginPath();
  ctx.arc(cx, cy, 40, 0, 2 * Math.PI);
  ctx.fillStyle = '#0d1520';
  ctx.fill();

  // Center text
  ctx.fillStyle = '#00e5ff';
  ctx.font = 'bold 14px Orbitron, monospace';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(`/${cidr}`, cx, cy - 8);
  ctx.fillStyle = '#3a5a7a';
  ctx.font = '10px Share Tech Mono, monospace';
  ctx.fillText(`${total <= 1024 ? total : total.toLocaleString()}`, cx, cy + 10);

  // Border ring
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, 2 * Math.PI);
  ctx.strokeStyle = 'rgba(0,229,255,0.15)';
  ctx.lineWidth = 1;
  ctx.stroke();

  // Legend
  const legend = document.getElementById('pieLegend');
  legend.innerHTML = slices.map(s => `
    <div class="legend-item">
      <div class="legend-dot" style="background:${s.color};box-shadow:0 0 6px ${s.color}"></div>
      <span class="legend-label">${s.label}</span>
      <span class="legend-val">${s.val.toLocaleString('pt-BR')}</span>
    </div>
  `).join('');
}

// ---- GAUGE / CLOCK ----
function drawGauge(cidr) {
  const canvas = document.getElementById('gaugeCanvas');
  const ctx = canvas.getContext('2d');
  const cx = 100, cy = 110, r = 78;
  ctx.clearRect(0, 0, 200, 200);

  const startAngle = Math.PI * 0.75;
  const endAngle = Math.PI * 2.25;
  const fillAngle = startAngle + ((cidr / 32) * (endAngle - startAngle));

  // Background arc
  ctx.beginPath();
  ctx.arc(cx, cy, r, startAngle, endAngle);
  ctx.strokeStyle = 'rgba(26,48,80,0.8)';
  ctx.lineWidth = 16;
  ctx.lineCap = 'round';
  ctx.stroke();

  // Filled arc
  if (cidr > 0) {
    const gradient = ctx.createLinearGradient(cx - r, cy, cx + r, cy);
    gradient.addColorStop(0, '#ff6b35');
    gradient.addColorStop(0.5, '#ffd600');
    gradient.addColorStop(1, '#00ff88');
    ctx.beginPath();
    ctx.arc(cx, cy, r, startAngle, fillAngle);
    ctx.strokeStyle = gradient;
    ctx.lineWidth = 16;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Glow
    ctx.beginPath();
    ctx.arc(cx, cy, r, startAngle, fillAngle);
    ctx.strokeStyle = 'rgba(255,214,0,0.15)';
    ctx.lineWidth = 28;
    ctx.stroke();
  }

  // Tick marks
  ctx.lineWidth = 1;
  for (let i = 0; i <= 32; i += 4) {
    const a = startAngle + (i / 32) * (endAngle - startAngle);
    const inner = r - 12, outer = r - 4;
    ctx.beginPath();
    ctx.moveTo(cx + Math.cos(a) * inner, cy + Math.sin(a) * inner);
    ctx.lineTo(cx + Math.cos(a) * outer, cy + Math.sin(a) * outer);
    ctx.strokeStyle = '#3a5a7a';
    ctx.lineWidth = 1;
    ctx.stroke();

    // Labels
    if (i % 8 === 0) {
      const lr = r - 24;
      ctx.fillStyle = '#3a5a7a';
      ctx.font = '9px Share Tech Mono';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(i, cx + Math.cos(a) * lr, cy + Math.sin(a) * lr);
    }
  }

  // Needle endpoint dot
  const nx = cx + Math.cos(fillAngle) * r;
  const ny = cy + Math.sin(fillAngle) * r;
  ctx.beginPath();
  ctx.arc(nx, ny, 6, 0, 2 * Math.PI);
  ctx.fillStyle = '#ffd600';
  ctx.fill();
  ctx.shadowColor = '#ffd600';
  ctx.shadowBlur = 12;
  ctx.fill();
  ctx.shadowBlur = 0;
}

// ---- MASK OCTETS ----
function drawMaskOctets(maskLong) {
  const container = document.getElementById('maskOctets');
  const octets = [(maskLong >>> 24) & 255, (maskLong >>> 16) & 255, (maskLong >>> 8) & 255, maskLong & 255];
  container.innerHTML = octets.map((o, i) => {
    const bits = toBinary(o, 8);
    const bitsHtml = bits.split('').map(b => `
      <div class="octet-bit ${b === '1' ? 'mask-on' : 'mask-off'}">${b}</div>
    `).join('');
    return `
      <div class="octet-row">
        <div class="octet-label">OCTETO ${i+1}</div>
        <div class="octet-bits">${bitsHtml}</div>
        <div class="octet-val">${o}</div>
      </div>
    `;
  }).join('');
}

// ---- BINARY GRID ----
function drawBinaryGrid(ipLong, networkLong, broadcastLong, maskLong, cidr) {
  const container = document.getElementById('binaryGrid');

  function renderBits(val, cidr, colorMode) {
    let html = '';
    const binary = toBinary(val, 32);
    for (let group = 0; group < 4; group++) {
      html += '<div class="bit-group">';
      for (let b = 0; b < 8; b++) {
        const idx = group * 8 + b;
        const bit = binary[idx];
        let cls = bit === '1' ? 'on' : 'off';
        if (colorMode === 'address') {
          if (idx < cidr) cls += ' network-bit';
          else cls += ' host-bit';
        }
        html += `<div class="bit ${cls}">${bit}</div>`;
      }
      html += '</div>';
      if (group < 3) html += '<div class="octet-dot">.</div>';
    }
    return html;
  }

  const rows = [
    { label: 'IP ORIGEM', val: ipLong, mode: 'address' },
    { label: 'MÁSCARA', val: maskLong, mode: '' },
    { label: 'REDE', val: networkLong, mode: 'address' },
    { label: 'BROADCAST', val: broadcastLong, mode: '' },
  ];

  // Emit label + bits + value as flat grid children (no row wrapper)
  container.innerHTML = rows.map(r => `
    <div class="binary-row-label">${r.label}</div>
    <div class="binary-bits">${renderBits(r.val, cidr, r.mode)}</div>
    <div class="binary-value">${longToIp(r.val)}</div>
  `).join('');

  // Legend spans all 3 columns
  container.innerHTML += `
    <div style="grid-column:1/-1;margin-top:4px;display:flex;gap:20px;flex-wrap:wrap;">
      <span style="font-size:11px;color:#00e5ff;">■ bits de REDE</span>
      <span style="font-size:11px;color:#ff6b35;">■ bits de HOST</span>
      <span style="font-size:11px;color:#00ff88;">■ bit 1</span>
      <span style="font-size:11px;color:#3a5a7a;">■ bit 0</span>
    </div>
  `;
}

// Auto-calculate on load
calculate();

// Allow Enter key
document.getElementById('ipInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') calculate();
});
document.getElementById('cidrInput').addEventListener('change', calculate);
