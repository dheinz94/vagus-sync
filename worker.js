/* =====================================================================
   Vagus Sync – kleiner Speicherdienst für Cloudflare Workers
   1) Geräteabgleich: speichert EINEN verschlüsselten Datensatz (nur Datensalat,
      der Schlüssel bleibt auf deinen Geräten)
   2) MCP-Endpunkt, damit die Claude-Version als Konnektor „Vagus Sync“ abgleichen kann
   3) Vermittlung zu COROS (nur mcp/mcpeu/mcpus/mcpcn.coros.com), falls der Browser direkte Abfragen blockiert
   Zugriff nur mit dem geheimen Schlüssel im Pfad.
   Speicher: ein Durable Object (SQLite, im Gratis-Tarif enthalten). Alle Zugriffe laufen
   nacheinander durch dieses eine Objekt – so überschreibt kein Gerät versehentlich ein anderes.
   ===================================================================== */
import { DurableObject } from 'cloudflare:workers';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, Accept, MCP-Protocol-Version, Mcp-Session-Id',
  'Access-Control-Expose-Headers': 'Mcp-Session-Id',
  'Access-Control-Max-Age': '86400'
};
const RELAY_HOST = /^mcp(eu|us|cn)?\.coros\.com$/;
const MAX_BLOB = 900 * 1024;
const KEY_RX = /^[A-Za-z0-9_-]{20,128}$/;
const MCP_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...CORS } });

async function hashKey(key) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('vagus:' + key));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function validBlob(b) {
  return b && typeof b === 'object' && b.v === 1 && ['salt', 'iv', 'ct'].every(k => typeof b[k] === 'string' && b[k].length < MAX_BLOB) && JSON.stringify(b).length < MAX_BLOB;
}

/* ---------- Der Speicher: genau ein Objekt, strikt der Reihe nach ---------- */
export class VagusStore extends DurableObject {
  async claim(h) {
    const owner = await this.ctx.storage.get('owner');
    if (!owner) { await this.ctx.storage.put('owner', h); return { ok: true, claimed: true }; }
    return owner === h ? { ok: true } : { error: 'already_claimed' };
  }
  async isOwner(h) { const owner = await this.ctx.storage.get('owner'); return !!owner && owner === h; }
  async readBlob() { return (await this.ctx.storage.get('blob')) || { rev: 0, blob: null }; }
  async putBlob(rev, blob) {
    if (!validBlob(blob)) return { status: 400, out: { ok: false, error: 'invalid_blob' } };
    const cur = await this.readBlob();
    if ((cur.rev || 0) !== Number(rev || 0)) return { status: 409, out: { ok: false, conflict: true, rev: cur.rev || 0 } };
    const next = { rev: (cur.rev || 0) + 1, blob, at: Date.now() };
    await this.ctx.storage.put('blob', next);
    return { status: 200, out: { ok: true, rev: next.rev } };
  }
}

/* ---------- Vermittlung zu COROS ---------- */
async function relay(req, url, env) {
  let target;
  try { target = new URL(url.searchParams.get('u') || ''); } catch (e) { return json({ error: 'bad_target' }, 400); }
  const testOk = env && env.RELAY_TEST_HOST && target.host === env.RELAY_TEST_HOST;
  if (!testOk && (target.protocol !== 'https:' || !RELAY_HOST.test(target.hostname))) return json({ error: 'host_not_allowed' }, 403);
  const headers = new Headers();
  for (const h of ['content-type', 'authorization', 'accept', 'mcp-protocol-version', 'mcp-session-id']) { const v = req.headers.get(h); if (v) headers.set(h, v); }
  const init = { method: req.method, headers, redirect: 'manual' };
  if (!['GET', 'HEAD'].includes(req.method)) init.body = await req.arrayBuffer();
  const r = await fetch(target.toString(), init);
  const out = new Headers(CORS);
  for (const h of ['content-type', 'mcp-session-id', 'location', 'www-authenticate']) { const v = r.headers.get(h); if (v) out.set(h, v); }
  out.set('Cache-Control', 'no-store');
  return new Response(r.body, { status: r.status, headers: out });
}

/* ---------- MCP-Endpunkt für Claude ---------- */
const TOOLS = [
  {
    name: 'vagus_sync_get',
    description: 'Liest den verschlüsselten Vagus-Abgleichsdatensatz. Gibt {rev, blob} zurück; blob ist mit dem Passwort des Nutzers verschlüsselt (AES-GCM) oder null.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    annotations: { title: 'Abgleich lesen', readOnlyHint: true }
  },
  {
    name: 'vagus_sync_put',
    description: 'Schreibt den verschlüsselten Vagus-Abgleichsdatensatz, nur wenn rev dem aktuellen Stand entspricht. Gibt {ok, rev} oder {ok:false, conflict:true, rev} zurück.',
    inputSchema: { type: 'object', properties: { rev: { type: 'integer', description: 'Zuletzt gelesene Revision' }, blob: { type: 'object', description: 'Verschlüsselter Datensatz {v, salt, iv, ct}' } }, required: ['rev', 'blob'], additionalProperties: false },
    annotations: { title: 'Abgleich schreiben', readOnlyHint: false, destructiveHint: false }
  }
];
async function mcp(req, store) {
  if (req.method === 'GET') return new Response('Dieser Endpunkt spricht MCP über POST.', { status: 405, headers: { Allow: 'POST', ...CORS } });
  if (req.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);
  let msg; try { msg = await req.json(); } catch (e) { return json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, 400); }
  const handle = async m => {
    const id = m && m.id;
    if (!m || typeof m.method !== 'string') return { jsonrpc: '2.0', id: id ?? null, error: { code: -32600, message: 'Invalid Request' } };
    if (m.method.startsWith('notifications/')) return null;
    switch (m.method) {
      case 'initialize': {
        const asked = m.params && m.params.protocolVersion;
        return { jsonrpc: '2.0', id, result: { protocolVersion: MCP_VERSIONS.includes(asked) ? asked : MCP_VERSIONS[0], capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'vagus-sync', version: '1.1.0' }, instructions: 'Speicher für den verschlüsselten Geräteabgleich der App Vagus.' } };
      }
      case 'ping': return { jsonrpc: '2.0', id, result: {} };
      case 'tools/list': return { jsonrpc: '2.0', id, result: { tools: TOOLS } };
      case 'tools/call': {
        const name = m.params && m.params.name; const args = (m.params && m.params.arguments) || {};
        let out;
        if (name === 'vagus_sync_get') out = await store.readBlob();
        else if (name === 'vagus_sync_put') out = (await store.putBlob(args.rev, args.blob)).out;
        else return { jsonrpc: '2.0', id, error: { code: -32602, message: 'Unknown tool: ' + name } };
        return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(out) }], structuredContent: out, isError: false } };
      }
      default: return { jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found' } };
    }
  };
  if (Array.isArray(msg)) { const res = (await Promise.all(msg.map(handle))).filter(Boolean); return res.length ? json(res) : new Response(null, { status: 202, headers: CORS }); }
  const res = await handle(msg);
  return res ? json(res) : new Response(null, { status: 202, headers: CORS });
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    const url = new URL(req.url);
    const p = url.pathname.split('/').filter(Boolean);
    if (!env.STORE) return json({ service: 'vagus-sync', ok: false, error: 'store_missing' }, 500);
    if (p.length === 0) return json({ service: 'vagus-sync', ok: true });
    const store = env.STORE.get(env.STORE.idFromName('main'));
    const key = p[1];
    if (!KEY_RX.test(key || '')) return json({ error: p.length ? 'forbidden' : 'not_found' }, p.length ? 403 : 404);
    const h = await hashKey(key);
    if (p[0] === 'mcp') { if (!(await store.isOwner(h))) return json({ error: 'forbidden' }, 403); return mcp(req, store); }
    if (p[0] === 'v1') {
      const route = p[2];
      if (route === 'claim' && req.method === 'POST') { const r = await store.claim(h); return json(r, r.error ? 403 : 200); }
      if (!(await store.isOwner(h))) return json({ error: 'forbidden' }, 403);
      if (route === 'blob' && req.method === 'GET') return json(await store.readBlob());
      if (route === 'blob' && req.method === 'PUT') { let b; try { b = await req.json(); } catch (e) { return json({ error: 'bad_json' }, 400); } const r = await store.putBlob(b.rev, b.blob); return json(r.out, r.status); }
      if (route === 'relay') return relay(req, url, env);
    }
    return json({ error: 'not_found' }, 404);
  }
};
