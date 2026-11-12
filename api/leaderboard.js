
const crypto = require('node:crypto');

const HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store'
};

function send(res, status, body) {
  res.writeHead(status, HEADERS);
  res.end(JSON.stringify(body));
}

function secret() {
  return process.env.LEADERBOARD_SECRET || '';
}

function sign(payload) {
  return crypto.createHmac('sha256', secret())
    .update(payload).digest('hex');
}

function makeToken() {
  const issued = Date.now().toString();
  const nonce = crypto.randomBytes(12).toString('hex');
  const payload = issued + '.' + nonce;
  return payload + '.' + sign(payload);
}

function checkToken(token) {
  if (typeof token !== 'string' || token.length > 200) return null;

  const parts = token.split('.');
  if (parts.length !== 3) return null;

  const payload = parts[0] + '.' + parts[1];
  const expected = sign(payload);

  if (
    parts[2].length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(parts[2]), Buffer.from(expected))
  ) return null;

  const age = Date.now() - Number(parts[0]);
  return age >= 0 && age <= 21600000 ? age : null;
}

function config() {
  const url = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

  if (!url || !key || !secret()) {
    throw new Error('Missing configuration');
  }

  return { url, key };
}

async function database(path, method = 'GET', body) {
  const { url, key } = config();

  const response = await fetch(url + '/rest/v1/' + path, {
    method,
    headers: {
      apikey: key,
      Authorization: 'Bearer ' + key,
      'Content-Type': 'application/json',
      Prefer: 'return=minimal'
    },
    body: body ? JSON.stringify(body) : undefined
  });

  if (!response.ok) {
    throw new Error('Database error: ' + response.status);
  }

  return method === 'GET' ? response.json() : null;
}

module.exports = async function handler(req, res) {
  try {
    config();

    if (req.method === 'GET') {
      if (req.query.mode === 'session') {
        return send(res, 200, { token: makeToken() });
      }

      const scores = await database(
        'kicki_scores?select=name,score&order=score.desc,created_at.asc&limit=10'
      );

      return send(res, 200, { scores });
    }

    if (req.method !== 'POST') {
      return send(res, 405, { error: 'Method not allowed' });
    }

    let data = req.body;
    if (typeof data === 'string') {
      try { data = JSON.parse(data); } catch {}
    }

    const name = typeof data?.name === 'string'
      ? data.name.trim() : '';
    const score = data?.score;
    const age = checkToken(data?.token);

    if (!name || name.length > 16 || /[<>\x00-\x1f]/.test(name)) {
      return send(res, 400, { error: 'Ogiltigt namn' });
    }

    if (!Number.isSafeInteger(score) || score < 0 || score > 300000) {
      return send(res, 400, { error: 'Ogiltig poäng' });
    }

    if (age === null) {
      return send(res, 400, { error: 'Starta en ny spelomgång' });
    }

    const seconds = age / 1000;
    if (seconds < 5 || score > 15000 + seconds * 500) {
      return send(res, 400, { error: 'Poängen kunde inte godkännas' });
    }

    const fingerprint = crypto.createHash('sha256')
      .update(data.token).digest('hex');

    try {
      await database('kicki_scores', 'POST', {
        name,
        score,
        run_id: fingerprint
      });
    } catch (error) {
      if (error.message.includes('409')) {
        return send(res, 409, { error: 'Resultatet är redan sparat' });
      }
      throw error;
    }

    return send(res, 201, { ok: true });
  } catch {
    return send(res, 503, {
      error: 'Topplistan är ännu inte tillgänglig'
    });
  }
};
