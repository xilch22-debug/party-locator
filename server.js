// Party Locator - zero-dependency Node server (Node 16+).
// Run: GOOGLE_MAPS_API_KEY=your_key node server.js
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const MAPS_KEY = process.env.GOOGLE_MAPS_API_KEY || '';
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;
const PUBLIC_DIR = path.join(__dirname, 'public');
const STALE_MS = 2 * 60 * 1000;        // drop people who stopped sharing
const PARTY_TTL_MS = 12 * 60 * 60 * 1000;

const parties = new Map(); // code -> party

const clean = (s, n) => String(s || '').replace(/[<>]/g, '').trim().slice(0, n);
const validCoord = (lat, lng) =>
  typeof lat === 'number' && typeof lng === 'number' &&
  lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180;

// ---- Password helpers (scrypt, per-party salt) ----
const hashPw = (pw, salt) => crypto.scryptSync(String(pw || ''), salt, 32);
const checkPw = (party, pw) => crypto.timingSafeEqual(hashPw(pw, party.salt), party.pwHash);
const attempts = new Map(); // "ip:code" -> { n, until }
const lockedOut = key => { const a = attempts.get(key); return a && a.until > Date.now(); };
const recordFail = key => {
  const a = attempts.get(key) || { n: 0, until: 0 };
  if (++a.n >= 5) { a.until = Date.now() + 60000; a.n = 0; } // 5 misses -> 1 minute lockout
  attempts.set(key, a);
};

function newCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code;
  do {
    code = Array.from(crypto.randomBytes(5), b => chars[b % chars.length]).join('');
  } while (parties.has(code));
  return code;
}

function snapshot(p) {
  return {
    code: p.code,
    name: p.name,
    public: p.public,
    locked: !!p.pwHash,
    people: [...p.people.values()],
    pins: p.pins,
  };
}

function broadcast(p) {
  const data = `data: ${JSON.stringify(snapshot(p))}\n\n`;
  for (const res of p.clients) res.write(data);
}

function distanceKm(aLat, aLng, bLat, bLng) {
  const R = 6371, rad = Math.PI / 180;
  const dLat = (bLat - aLat) * rad, dLng = (bLng - aLng) * rad;
  const h = Math.sin(dLat / 2) ** 2 +
    Math.cos(aLat * rad) * Math.cos(bLat * rad) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', c => {
      raw += c;
      if (raw.length > 10000) { reject(new Error('too large')); req.destroy(); }
    });
    req.on('end', () => {
      try { resolve(raw ? JSON.parse(raw) : {}); } catch (e) { reject(e); }
    });
  });
}

const send = (res, status, obj) => {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
};

// Supabase REST API connection
async function dbRequest(endpoint, method = 'GET', body = null, prefer = 'return=representation') {
  if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
    throw new Error('Supabase credentials are missing');
  }

  const response = await fetch(
    `${SUPABASE_URL.replace(/\/$/, '')}/rest/v1/${endpoint}`,
    {
      method,
      headers: {
        apikey: SUPABASE_SECRET_KEY,
        Authorization: `Bearer ${SUPABASE_SECRET_KEY}`,
        'Content-Type': 'application/json',
        Prefer: prefer
      },
      ...(body === null ? {} : { body: JSON.stringify(body) })
    }
  );

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Supabase error ${response.status}: ${error}`);
  }

  const result = await response.text();
  return result ? JSON.parse(result) : null;
}

// Restore saved parties from Supabase
async function restoreParties() {
  console.log('Loading parties from Supabase...');

  const [partyRows, peopleRows, pinRows] = await Promise.all([
    dbRequest('parties?select=*'),
    dbRequest('party_people?select=*'),
    dbRequest('party_pins?select=*')
  ]);

  for (const row of partyRows) {
    const party = {
      code: row.code,
      name: row.name,
      public: row.is_public,
      people: new Map(),
      pins: [],
      clients: new Set(),
      createdAt: Number(row.created_at),
      lastActive: Number(row.last_active),
      salt: row.salt ? Buffer.from(row.salt, 'hex') : null,
      pwHash: row.pw_hash ? Buffer.from(row.pw_hash, 'hex') : null,
      tokens: new Set()
    };

    for (const person of peopleRows) {
      if (person.party_code === row.code) {
        party.people.set(person.id, {
          id: person.id,
          name: person.name,
          lat: Number(person.lat),
          lng: Number(person.lng),
          accuracy: person.accuracy,
          updatedAt: Number(person.updated_at)
        });
      }
    }

    party.pins = pinRows
      .filter(pin => pin.party_code === row.code)
      .map(pin => ({
        id: pin.id,
        name: pin.name,
        by: pin.created_by,
        lat: Number(pin.lat),
        lng: Number(pin.lng),
        createdAt: Number(pin.created_at)
      }));

    parties.set(party.code, party);
  }

  console.log(`Restored ${parties.size} parties from Supabase.`);
}

// Periodic cleanup
setInterval(() => {
  const now = Date.now();
  for (const [k, a] of attempts) if (a.until && a.until < now) attempts.delete(k);
  for (const [code, p] of parties) {
    let changed = false;
    for (const [id, person] of p.people) {
      if (now - person.updatedAt > STALE_MS) { p.people.delete(id); changed = true; }
    }
    if (changed) broadcast(p);
    if (now - p.lastActive > PARTY_TTL_MS && p.clients.size === 0) parties.delete(code);
  }
}, 15000);

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const p = url.pathname;

  try {
    // ---- API ----
    if (p === '/api/config' && req.method === 'GET') {
      return send(res, 200, { mapsKey: MAPS_KEY });
    }

    if (p === '/api/parties' && req.method === 'GET') {
      const lat = parseFloat(url.searchParams.get('lat'));
      const lng = parseFloat(url.searchParams.get('lng'));
      const hasPos = validCoord(lat, lng);
      const list = [...parties.values()]
        .filter(x => x.public && !x.pwHash && x.pins.length)
        .map(x => {
          const pin = x.pins[0];
          return {
            code: x.code, name: x.name, people: x.people.size,
            pin: { lat: pin.lat, lng: pin.lng, name: pin.name },
            distanceKm: hasPos ? distanceKm(lat, lng, pin.lat, pin.lng) : null,
          };
        });
      if (hasPos) list.sort((a, b) => a.distanceKm - b.distanceKm);
      return send(res, 200, list.slice(0, 30));
    }

    if (p === '/api/party' && req.method === 'POST') {
      const body = await readBody(req);
      const name = clean(body.name, 60);
      if (!name) return send(res, 400, { error: 'Party name required' });
      const password = typeof body.password === 'string' ? body.password : '';
      if (password && (password.length < 4 || password.length > 64)) {
        return send(res, 400, { error: 'Password must be 4 to 64 characters' });
      }
      const party = {
        code: newCode(), name,
        public: !!body.public && !password, // password-protected parties are never listed
        people: new Map(), pins: [], clients: new Set(), lastActive: Date.now(),
        salt: null, pwHash: null, tokens: new Set(),
      };
      if (password) {
        party.salt = crypto.randomBytes(16);
        party.pwHash = hashPw(password, party.salt);
      }
      parties.set(party.code, party);
      await savePartyToDb(party);
      return send(res, 201, snapshot(party));
    }

    let m = p.match(/^\/api\/party\/([A-Za-z0-9]+)(?:\/(stream|location|pin|leave|join|pin\/([a-f0-9]+)))?$/);
    if (m) {
      const party = parties.get(m[1].toUpperCase());
      if (!party) return send(res, 404, { error: 'Party not found' });
      const action = m[2] || '';
      party.lastActive = Date.now();

      // Joining: checks the password and hands back a session token for protected parties
      if (action === 'join' && req.method === 'POST') {
        const b = await readBody(req);
        if (!party.pwHash) return send(res, 200, { token: '', party: snapshot(party) });
        const key = `${req.socket.remoteAddress}:${party.code}`;
        if (lockedOut(key)) return send(res, 429, { error: 'Too many wrong attempts. Try again in a minute.' });
        if (typeof b.password !== 'string' || !checkPw(party, b.password)) {
          recordFail(key);
          return send(res, 401, { error: b.password ? 'Wrong password' : 'This party needs a password', locked: true });
        }
        attempts.delete(key);
        const token = crypto.randomBytes(16).toString('hex');
        if (party.tokens.size >= 500) party.tokens.delete(party.tokens.values().next().value);
        party.tokens.add(token);
        return send(res, 200, { token, party: snapshot(party) });
      }

      // Every other action on a protected party needs a valid token
      if (party.pwHash) {
        const tokenIn = req.headers['x-party-token'] || url.searchParams.get('token') || '';
        if (!party.tokens.has(tokenIn)) return send(res, 401, { error: 'Password required', locked: true });
      }

      if (!action && req.method === 'GET') return send(res, 200, snapshot(party));

      if (action === 'stream' && req.method === 'GET') {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive',
        });
        res.write(`data: ${JSON.stringify(snapshot(party))}\n\n`);
        party.clients.add(res);
        const ping = setInterval(() => res.write(': ping\n\n'), 25000);
        req.on('close', () => { clearInterval(ping); party.clients.delete(res); });
        return;
      }

      if (action === 'location' && req.method === 'POST') {
        const b = await readBody(req);
        if (!validCoord(b.lat, b.lng) || !b.id) return send(res, 400, { error: 'Bad location' });
        const person = {
  id: String(b.id).slice(0, 40),
  name: clean(b.name, 30) || 'Guest',
  lat: b.lat,
  lng: b.lng,
  accuracy: typeof b.accuracy === 'number' ? Math.round(b.accuracy) : null,
  updatedAt: Date.now(),
};

party.people.set(person.id, person);

await savePersonToDb(party.code, person);

broadcast(party);
return send(res, 200, { ok: true });
      }

      if (action === 'leave' && req.method === 'POST') {
        const b = await readBody(req);
        const personId = String(b.id);
party.people.delete(personId);

await deletePersonFromDb(party.code, personId);

broadcast(party);
return send(res, 200, { ok: true });
      }

      if (action === 'pin' && req.method === 'POST') {
        const b = await readBody(req);
        if (!validCoord(b.lat, b.lng)) return send(res, 400, { error: 'Bad location' });
        if (party.pins.length >= 20) return send(res, 400, { error: 'Pin limit reached' });
        const pin = {
  id: crypto.randomBytes(4).toString('hex'),
  name: clean(b.name, 60) || 'Meetup spot',
  by: clean(b.by, 30) || 'Guest',
  lat: b.lat,
  lng: b.lng,
  createdAt: Date.now(),
};

party.pins.push(pin);

await savePinToDb(party.code, pin);

broadcast(party);
return send(res, 201, { ok: true });
      }

      if (m[3] && req.method === 'DELETE') {
  party.pins = party.pins.filter(x => x.id !== m[3]);

  await deletePinFromDb(m[3]);

  broadcast(party);
  return send(res, 200, { ok: true });
}

      return send(res, 405, { error: 'Method not allowed' });
    }

    // ---- Static files ----
    let file = p === '/' ? '/index.html' : p;
    const full = path.normalize(path.join(PUBLIC_DIR, file));
    if (!full.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end(); }
    fs.readFile(full, (err, data) => {
      if (err) { res.writeHead(404); return res.end('Not found'); }
      res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream' });
      res.end(data);
    });
  } catch (e) {
    send(res, 400, { error: 'Bad request' });
  }
});

restoreParties()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`Party Locator running on http://localhost:${PORT}`);
      if (!MAPS_KEY) console.log('No GOOGLE_MAPS_API_KEY set: using basic embedded Google Maps fallback.');
    });
  })
  .catch(error => {
    console.error('Failed to restore parties from Supabase:', error);
    process.exit(1);
  });

async function savePartyToDb(party) {
  await dbRequest('parties?on_conflict=code', 'POST', {
    code: party.code,
    name: party.name,
    is_public: party.public,
    salt: party.salt ? party.salt.toString('hex') : null,
    pw_hash: party.pwHash ? party.pwHash.toString('hex') : null,
    created_at: party.createdAt || party.lastActive,
    last_active: party.lastActive
  }, 'resolution=merge-duplicates,return=minimal');
}

async function savePersonToDb(code, person) {
  await dbRequest('party_people?on_conflict=party_code,id', 'POST', {
    party_code: code,
    id: person.id,
    name: person.name,
    lat: person.lat,
    lng: person.lng,
    accuracy: person.accuracy,
    updated_at: person.updatedAt
  }, 'resolution=merge-duplicates,return=minimal');
}

async function deletePersonFromDb(code, id) {
  await dbRequest(
    `party_people?party_code=eq.${encodeURIComponent(code)}&id=eq.${encodeURIComponent(id)}`,
    'DELETE',
    null,
    'return=minimal'
  );
}

async function savePinToDb(code, pin) {
  await dbRequest('party_pins', 'POST', {
    id: pin.id,
    party_code: code,
    name: pin.name,
    created_by: pin.by,
    lat: pin.lat,
    lng: pin.lng,
    created_at: pin.createdAt
  }, 'return=minimal');
}

async function deletePinFromDb(id) {
  await dbRequest(
    `party_pins?id=eq.${encodeURIComponent(id)}`,
    'DELETE',
    null,
    'return=minimal'
  );
}

async function deletePartyFromDb(code) {
  await dbRequest(
    `parties?code=eq.${encodeURIComponent(code)}`,
    'DELETE',
    null,
    'return=minimal'
  );
}
