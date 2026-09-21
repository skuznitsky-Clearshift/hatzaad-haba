/* =====================================================================
   הצעד הבא — שרת סנכרון וניטור  (Cloudflare Worker + KV)   גרסה 2
   =====================================================================
   מה השתנה מגרסה 1, ולמה:

   1. לכל פרופיל יש עכשיו **מפתח משלו**, לא סוד גלובלי אחד.
      בגרסה 1 כל מכשיר שהוגדר לסנכרון החזיק את אותו SECRET, ולכן
      יכול היה לדרוס פרופיל של משפחה אחרת אם ידע את הקוד; וקריאת
      פרופיל הייתה פתוחה לגמרי. עכשיו הכתיבה והקריאה דורשות מפתח
      אישי, בדיוק כמו במנגנון החדרים. פרופילים ישנים שעוד אין
      להם מפתח ממשיכים לעבוד, והכתיבה הראשונה עם מפתח "תופסת"
      אותם — כך אפשר לשדרג בלי לנתק אף אחד.

   2. חיבור מכשיר נוסף, ושיתוף עם הגננת, נעשים בהזמנה חד-פעמית
      (/p/<CODE>/invite ו-/join) ולא בהעברת הסוד עצמו. כל מכשיר
      וכל חבר מקבלים מפתח אישי שאפשר לשלול בהמשך.

   3. נוסף מסלול ניטור /ev שמקבל **סיכום יומי דחוס בלי שמות**.
      בגרסה 1 הפינג ספר רק פתיחות אפליקציה, ולכן אי אפשר היה
      לדעת למה ילד הפסיק לשחק. עכשיו נשמר, לכל ילד ולכל משחקון,
      מה הרמה ואיך היא נעה, אחוז ההצלחה, זמן התגובה החציוני,
      וכמה סבבים ננטשו באמצע — וזה בדיוק ההבדל בין "קל לו מדי"
      לבין "קשה לו מדי" לבין "פשוט נעלם".

   ---------------------------------------------------------------------
   פרטיות
   ---------------------------------------------------------------------
   מסלול הניטור לא מקבל שמות ילדים ולא נתוני יומן התפתחותי. ילד
   מיוצג במספר סידורי בתוך הפרופיל ובגיל בחודשים. השמות ממשיכים
   להישמר רק בפרופיל עצמו (/p), שמוגן במפתח ושייך להורה.

   ---------------------------------------------------------------------
   ממשק
   ---------------------------------------------------------------------
   GET  /p/<CODE>            -> {ok, data, at}.  X-Profile-Key אם נתפס.
   PUT  /p/<CODE>            -> גוף = state.     X-Profile-Key (או SECRET לישנים).
   POST /p/<CODE>/invite     -> {ok, inv}.       X-Profile-Key.
   POST /p/<CODE>/join       -> גוף {inv, who}.  מחזיר {ok, key, data}.

   GET  /k/<SID>             -> חדר של ילד אחד (ללא שינוי מגרסה 1)
   PUT  /k/<SID>  ·  POST /k/<SID>/invite  ·  POST /k/<SID>/join

   POST /ev                  -> גוף = {dev, code|null, day, kids:[...]}
   POST /ping                -> נשאר לתאימות לאחור עם מכשירים ישנים

   GET  /admin/users         -> רשימת המשתמשים עם סיכום
   GET  /admin/user/<UID>    -> פירוט מלא של משתמש אחד
   GET  /admin/list          -> תצוגת גרסה 1, נשמרה לתאימות
   GET  /admin/device/<DEV>  -> תצוגת גרסה 1, נשמרה לתאימות
   ===================================================================== */

const CODE_RE = /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{6}$/;
const ID_RE   = /^[A-Za-z0-9_-]{10,64}$/;
const DEV_RE  = /^[A-Za-z0-9]{12,24}$/;
const DAY_RE  = /^\d{4}-\d{2}-\d{2}$/;
const GID_RE  = /^[a-z0-9_-]{1,24}$/;

const MAX_P    = 256 * 1024;
const MAX_K    = 64 * 1024;
const MAX_EV   = 64 * 1024;
const INV_TTL  = 14 * 24 * 3600 * 1000;
const MAX_KEYS = 40;
const MAX_DAYS = 370;
const MAX_DEV_PROFILES = 8;

/* גבולות לרשומת הניטור, כדי שהיא לא תתפח בלי גבול */
const EV_DAYS  = 180;   /* ימי פעילות שנשמרים לכל משחקון */
const EV_HIST  = 80;    /* נקודות במסלול הרמות */
const EV_KIDS  = 12;    /* ילדים לפרופיל */
const EV_GAMES = 24;    /* משחקונים */

function cors(extra = {}) {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Secret, X-Room-Key, X-Profile-Key, X-Admin-Secret',
    'Access-Control-Max-Age': '86400',
    ...extra,
  };
}
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: cors({ 'Content-Type': 'application/json; charset=utf-8' }),
  });

async function sha(s) {
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s)));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
}
function rand(n) {
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const u = new Uint8Array(n);
  crypto.getRandomValues(u);
  let s = '';
  for (const x of u) s += A[x % A.length];
  return s;
}
const num = (x, lo, hi) => {
  const v = Number(x);
  if (!isFinite(v)) return null;
  return Math.max(lo, Math.min(hi, v));
};
/* גוזם מפה לפי מפתח ממוין, ומשאיר את האחרונים */
function trimMap(m, keep) {
  const ks = Object.keys(m).sort();
  if (ks.length > keep) ks.slice(0, ks.length - keep).forEach(k => delete m[k]);
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors() });
    const url = new URL(request.url);
    if (!env.NS) return json({ ok: false, error: 'kv_not_bound' }, 500);

    /* =================================================================
       פרופיל — המכשירים של אותו הורה, ומי שהוא שיתף איתו
       ================================================================= */
    const mp = url.pathname.match(/^\/p\/([^/]+)(?:\/(invite|join))?\/?$/);
    if (mp) {
      const code = decodeURIComponent(mp[1]).toUpperCase();
      const act  = mp[2] || '';
      if (!CODE_RE.test(code)) return json({ ok: false, error: 'bad_code' }, 400);
      const kvKey = 'p:' + code;

      const load = async () => {
        const raw = await env.NS.get(kvKey);
        if (!raw) return null;
        try { return JSON.parse(raw); } catch { return null; }
      };
      /* פרופיל "נתפס" ברגע שיש לו בעלים. עד אז הוא מתנהג כמו בגרסה 1. */
      const claimed = rec => !!(rec && rec.owner);
      const member = async (rec, key) => {
        if (!key) return false;
        const h = await sha(key);
        return !!(rec && rec.keys && rec.keys[h]);
      };

      if (request.method === 'GET' && !act) {
        const rec = await load();
        if (!rec) return json({ ok: true, data: null, at: null, claimed: false });
        if (claimed(rec) && !(await member(rec, request.headers.get('X-Profile-Key')))) {
          return json({ ok: false, error: 'unauthorized' }, 401);
        }
        return json({ ok: true, data: rec.data, at: rec.at, claimed: claimed(rec) });
      }

      if (request.method === 'PUT' && !act) {
        const body = await request.text();
        if (!body) return json({ ok: false, error: 'empty' }, 400);
        if (body.length > MAX_P) return json({ ok: false, error: 'too_large' }, 413);
        let data; try { data = JSON.parse(body); } catch { return json({ ok: false, error: 'bad_json' }, 400); }
        if (!data || !Array.isArray(data.kids)) return json({ ok: false, error: 'bad_shape' }, 400);

        const key = request.headers.get('X-Profile-Key') || '';
        let rec = await load();
        const at = new Date().toISOString();

        if (claimed(rec)) {
          if (!(await member(rec, key))) return json({ ok: false, error: 'unauthorized' }, 401);
          rec.data = data;
          rec.at = at;
        } else if (key) {
          /* הכתיבה הראשונה עם מפתח הופכת את הכותב לבעלים. כך פרופיל
             ישן עובר לבעלות בלי שההורה עושה דבר, בפתיחה הבאה. */
          const h = await sha(key);
          rec = { v: 2, at, data, owner: h, keys: { [h]: { at, label: 'ראשון' } }, inv: {} };
        } else {
          /* מכשיר ישן שעוד לא שודרג — הסוד הגלובלי, כמו בגרסה 1 */
          if (!env.SECRET) return json({ ok: false, error: 'secret_not_set' }, 500);
          if (request.headers.get('X-Secret') !== env.SECRET)
            return json({ ok: false, error: 'unauthorized' }, 401);
          rec = rec || { v: 1 };
          rec.at = at;
          rec.data = data;
        }
        await env.NS.put(kvKey, JSON.stringify(rec));
        return json({ ok: true, at, claimed: claimed(rec) });
      }

      /* הזמנה חד-פעמית — לחיבור מכשיר נוסף או לשיתוף הפרופיל */
      if (request.method === 'POST' && act === 'invite') {
        const rec = await load();
        if (!rec) return json({ ok: false, error: 'no_profile' }, 404);
        if (!claimed(rec)) return json({ ok: false, error: 'not_claimed' }, 409);
        if (!(await member(rec, request.headers.get('X-Profile-Key'))))
          return json({ ok: false, error: 'unauthorized' }, 401);
        const inv = rand(16);
        const now = Date.now();
        rec.inv = rec.inv || {};
        Object.keys(rec.inv).forEach(x => { if ((rec.inv[x].exp || 0) < now) delete rec.inv[x]; });
        rec.inv[await sha(inv)] = { at: now, exp: now + INV_TTL };
        await env.NS.put(kvKey, JSON.stringify(rec));
        return json({ ok: true, inv });
      }

      if (request.method === 'POST' && act === 'join') {
        const rec = await load();
        if (!rec) return json({ ok: false, error: 'no_profile' }, 404);
        if (!claimed(rec)) return json({ ok: false, error: 'not_claimed' }, 409);
        let body; try { body = await request.json(); } catch { body = null; }
        const inv = body && body.inv;
        if (!inv) return json({ ok: false, error: 'no_invite' }, 400);
        const ih = await sha(inv);
        const r = (rec.inv || {})[ih];
        if (!r) return json({ ok: false, error: 'invite_used' }, 410);
        if ((r.exp || 0) < Date.now()) {
          delete rec.inv[ih];
          await env.NS.put(kvKey, JSON.stringify(rec));
          return json({ ok: false, error: 'invite_expired' }, 410);
        }
        if (Object.keys(rec.keys || {}).length >= MAX_KEYS)
          return json({ ok: false, error: 'profile_full' }, 409);
        delete rec.inv[ih];
        const key = rand(22);
        rec.keys = rec.keys || {};
        rec.keys[await sha(key)] = { at: Date.now(), label: String((body && body.who) || '').slice(0, 40) };
        await env.NS.put(kvKey, JSON.stringify(rec));
        return json({ ok: true, key, data: rec.data || null, at: rec.at || null });
      }

      return json({ ok: false, error: 'method_not_allowed' }, 405);
    }

    /* =================================================================
       חדר של ילד אחד — ללא שינוי מגרסה 1
       ================================================================= */
    const mk = url.pathname.match(/^\/k\/([^/]+)(?:\/(invite|join))?\/?$/);
    if (mk) {
      const sid = decodeURIComponent(mk[1]);
      const act = mk[2] || '';
      if (!ID_RE.test(sid)) return json({ ok: false, error: 'bad_sid' }, 400);
      const kvKey = 'k:' + sid;
      const load = async () => {
        const raw = await env.NS.get(kvKey);
        if (!raw) return null;
        try { return JSON.parse(raw); } catch { return null; }
      };

      if (request.method === 'GET' && !act) {
        const room = await load();
        if (!room) return json({ ok: true, kid: null, at: null, del: 0 });
        return json({ ok: true, kid: room.kid || null, at: room.at || null, del: room.del || 0 });
      }

      if (request.method === 'PUT' && !act) {
        const key = request.headers.get('X-Room-Key') || '';
        if (!key) return json({ ok: false, error: 'no_room_key' }, 401);
        const body = await request.text();
        if (!body) return json({ ok: false, error: 'empty' }, 400);
        if (body.length > MAX_K) return json({ ok: false, error: 'too_large' }, 413);
        let data; try { data = JSON.parse(body); } catch { return json({ ok: false, error: 'bad_json' }, 400); }
        if (!data || !data.kid || typeof data.kid !== 'object')
          return json({ ok: false, error: 'bad_shape' }, 400);
        const h = await sha(key);
        let room = await load();
        const at = new Date().toISOString();
        if (!room) {
          room = { v: 1, at, kid: data.kid, owner: h, keys: { [h]: { at } }, inv: {} };
        } else {
          if (!room.keys || !room.keys[h]) return json({ ok: false, error: 'unauthorized' }, 401);
          room.kid = data.kid;
          room.at = at;
          if (data.del && room.owner === h) room.del = Date.now();
        }
        await env.NS.put(kvKey, JSON.stringify(room));
        return json({ ok: true, at, owner: room.owner === h });
      }

      if (request.method === 'POST' && act === 'invite') {
        const key = request.headers.get('X-Room-Key') || '';
        const room = await load();
        if (!room) return json({ ok: false, error: 'no_room' }, 404);
        const h = await sha(key);
        if (!room.keys || !room.keys[h]) return json({ ok: false, error: 'unauthorized' }, 401);
        const inv = rand(16);
        const now = Date.now();
        room.inv = room.inv || {};
        Object.keys(room.inv).forEach(x => { if ((room.inv[x].exp || 0) < now) delete room.inv[x]; });
        room.inv[await sha(inv)] = { at: now, exp: now + INV_TTL };
        await env.NS.put(kvKey, JSON.stringify(room));
        return json({ ok: true, inv });
      }

      if (request.method === 'POST' && act === 'join') {
        const room = await load();
        if (!room) return json({ ok: false, error: 'no_room' }, 404);
        let body; try { body = await request.json(); } catch { body = null; }
        const inv = body && body.inv;
        if (!inv) return json({ ok: false, error: 'no_invite' }, 400);
        const ih = await sha(inv);
        const rec = (room.inv || {})[ih];
        if (!rec) return json({ ok: false, error: 'invite_used' }, 410);
        if ((rec.exp || 0) < Date.now()) {
          delete room.inv[ih];
          await env.NS.put(kvKey, JSON.stringify(room));
          return json({ ok: false, error: 'invite_expired' }, 410);
        }
        if (Object.keys(room.keys || {}).length >= MAX_KEYS)
          return json({ ok: false, error: 'room_full' }, 409);
        delete room.inv[ih];
        const key = rand(22);
        room.keys = room.keys || {};
        room.keys[await sha(key)] = { at: Date.now(), label: (body && body.who) || '' };
        await env.NS.put(kvKey, JSON.stringify(room));
        return json({ ok: true, key, kid: room.kid || null, at: room.at || null });
      }

      return json({ ok: false, error: 'method_not_allowed' }, 405);
    }

    /* =================================================================
       ניטור — סיכום יומי דחוס, בלי שמות
       =================================================================
       הלקוח צובר במכשיר ושולח פעם בכמה דקות. השרת ממזג לתוך רשומת
       משתמש אחת. מיזוג ולא דריסה, כי אותו הורה יכול לשלוח משני
       מכשירים באותו יום.

       גוף הבקשה:
       { dev, code|null, day:"YYYY-MM-DD",
         kids: [ { i:<מספר סידורי>, am:<גיל בחודשים>, opens:<n>,
                   games: [ { g:<id>, lv:<רמה נוכחית>, rounds, ok,
                              acc:<0..1>, med:<שניות>, up, dn, ab } ] } ] }
       ================================================================= */
    if (url.pathname === '/ev' && request.method === 'POST') {
      const text = await request.text();
      if (!text) return json({ ok: false, error: 'empty' }, 400);
      if (text.length > MAX_EV) return json({ ok: false, error: 'too_large' }, 413);
      let b; try { b = JSON.parse(text); } catch { return json({ ok: false, error: 'bad_json' }, 400); }

      const dev  = String((b && b.dev) || '');
      const day  = String((b && b.day) || '');
      const code = (b && b.code) ? String(b.code).toUpperCase() : null;
      if (!DEV_RE.test(dev)) return json({ ok: false, error: 'bad_dev' }, 400);
      if (!DAY_RE.test(day)) return json({ ok: false, error: 'bad_day' }, 400);
      if (code && !CODE_RE.test(code)) return json({ ok: false, error: 'bad_code' }, 400);
      if (!Array.isArray(b.kids)) return json({ ok: false, error: 'bad_shape' }, 400);

      /* המשתמש הוא הפרופיל אם יש, ואחרת המכשיר. כך מכשיר שעוד לא
         סונכרן עדיין נספר, ומתמזג לפרופיל ברגע שיקבל קוד. */
      const uid = code ? ('c' + code) : ('d' + dev);
      const kvKey = 'u:' + uid;
      const raw = await env.NS.get(kvKey);
      let u; try { u = raw ? JSON.parse(raw) : null; } catch { u = null; }
      const now = new Date().toISOString();
      if (!u || typeof u !== 'object') u = { v: 2, f: now, l: now, ld: day, code: code || null, devs: [], kids: {} };
      u.l = now;
      /* ld = יום הפעילות האחרון, ולא זמן ההעלאה. מכשיר שהיה לא
         מקוון ושולח אחר כך את מה שהצטבר לא ייחשב פעיל היום. */
      if (day > (u.ld || '')) u.ld = day;
      u.code = code || u.code || null;
      u.devs = u.devs || [];
      if (u.devs.indexOf(dev) < 0 && u.devs.length < MAX_DEV_PROFILES) u.devs.push(dev);

      for (const kin of b.kids.slice(0, EV_KIDS)) {
        const i = num(kin && kin.i, 0, 99);
        if (i === null) continue;
        const slot = String(Math.round(i));
        u.kids[slot] = u.kids[slot] || { f: now, l: now, ld: day, am: null, days: {}, games: {} };
        const K = u.kids[slot];
        K.l = now;
        if (day > (K.ld || '')) K.ld = day;
        const am = num(kin.am, 0, 300);
        if (am !== null) K.am = Math.round(am);
        const opens = num(kin.opens, 0, 500) || 0;
        if (opens) K.days[day] = (K.days[day] || 0) + Math.round(opens);
        trimMap(K.days, EV_DAYS);

        for (const gin of (Array.isArray(kin.games) ? kin.games : []).slice(0, EV_GAMES)) {
          const g = String((gin && gin.g) || '');
          if (!GID_RE.test(g)) continue;
          if (!K.games[g] && Object.keys(K.games).length >= EV_GAMES) continue;
          K.games[g] = K.games[g] || { f: now, l: now, ld: day, lv: null, rounds: 0, ok: 0, up: 0, dn: 0, ab: 0, days: {}, hist: [] };
          const G = K.games[g];
          G.l = now;
          if (day > (G.ld || '')) G.ld = day;

          const rounds = num(gin.rounds, 0, 500) || 0;
          const okn    = num(gin.ok, 0, 5000) || 0;
          const up     = num(gin.up, 0, 100) || 0;
          const dn     = num(gin.dn, 0, 100) || 0;
          const ab     = num(gin.ab, 0, 200) || 0;
          const acc    = num(gin.acc, 0, 1);
          const med    = num(gin.med, 0, 600);
          const lv     = num(gin.lv, 1, 20);

          G.rounds += Math.round(rounds);
          G.ok     += Math.round(okn);
          G.up     += Math.round(up);
          G.dn     += Math.round(dn);
          G.ab     += Math.round(ab);

          /* יום = כמה סבבים, אחוז הצלחה משוקלל, וזמן חציוני אחרון */
          const d = G.days[day] || { n: 0, acc: 0, med: null, ab: 0 };
          const prevN = d.n;
          d.n += Math.round(rounds);
          d.ab += Math.round(ab);
          if (acc !== null && d.n > 0) d.acc = ((d.acc * prevN) + acc * Math.round(rounds)) / d.n;
          if (med !== null) d.med = med;
          G.days[day] = d;
          trimMap(G.days, EV_DAYS);

          /* מסלול הרמה — נקודה חדשה רק כשהרמה באמת השתנתה */
          if (lv !== null) {
            const last = G.hist.length ? G.hist[G.hist.length - 1] : null;
            if (!last || last.lv !== lv) G.hist.push({ d: day, lv });
            if (G.hist.length > EV_HIST) G.hist.splice(0, G.hist.length - EV_HIST);
            G.lv = lv;
          }
        }
      }

      const metadata = { l: u.l, c: u.code || '', k: Object.keys(u.kids).length };
      await env.NS.put(kvKey, JSON.stringify(u), { metadata });
      return json({ ok: true });
    }

    /* ---------- הפינג הישן, לתאימות לאחור ---------- */
    if (url.pathname === '/ping' && request.method === 'POST') {
      let body; try { body = await request.json(); } catch { return json({ ok: false, error: 'bad_json' }, 400); }
      const dev = String((body && body.dev) || '');
      const day = String((body && body.day) || '');
      const code = (body && body.code) ? String(body.code).toUpperCase() : null;
      if (!DEV_RE.test(dev)) return json({ ok: false, error: 'bad_dev' }, 400);
      if (!DAY_RE.test(day)) return json({ ok: false, error: 'bad_day' }, 400);
      if (code && !CODE_RE.test(code)) return json({ ok: false, error: 'bad_code' }, 400);

      const key = 'd:' + dev;
      const raw = await env.NS.get(key);
      let rec; try { rec = raw ? JSON.parse(raw) : null; } catch { rec = null; }
      const now = new Date().toISOString();
      if (!rec || typeof rec !== 'object') rec = { f: now, l: now, profiles: [], days: {} };
      rec.l = now;
      rec.days = rec.days || {};
      rec.days[day] = (rec.days[day] || 0) + 1;
      trimMap(rec.days, MAX_DAYS);
      rec.profiles = rec.profiles || [];
      if (code && rec.profiles.indexOf(code) < 0 && rec.profiles.length < MAX_DEV_PROFILES) rec.profiles.push(code);
      const metadata = { l: rec.l, n: Object.keys(rec.days).length, p: rec.profiles };
      await env.NS.put(key, JSON.stringify(rec), { metadata });
      return json({ ok: true });
    }

    /* =================================================================
       ניהול
       ================================================================= */
    const isAdmin = () => !!env.ADMIN_SECRET && request.headers.get('X-Admin-Secret') === env.ADMIN_SECRET;
    const adminGate = () => {
      if (!env.ADMIN_SECRET) return json({ ok: false, error: 'admin_secret_not_set' }, 500);
      if (!isAdmin()) return json({ ok: false, error: 'unauthorized' }, 401);
      return null;
    };

    if (url.pathname === '/admin/users') {
      const bad = adminGate(); if (bad) return bad;

      const users = [];
      let cur;
      do {
        const page = await env.NS.list({ prefix: 'u:', cursor: cur, limit: 1000 });
        for (const k of page.keys) {
          const raw = await env.NS.get(k.name);
          let u; try { u = JSON.parse(raw); } catch { u = null; }
          if (!u) continue;
          users.push(summarize(k.name.slice(2), u));
        }
        cur = page.list_complete ? undefined : page.cursor;
      } while (cur);

      /* שמות הילדים נשלפים מהפרופיל עצמו רק אם הוא עוד לא נתפס
         במפתח. מרגע שיש בעלים — גם הניהול לא רואה אותם. */
      for (const us of users) {
        if (!us.code) continue;
        const raw = await env.NS.get('p:' + us.code);
        let rec; try { rec = JSON.parse(raw); } catch { rec = null; }
        if (!rec) continue;
        us.profileAt = rec.at || null;
        us.claimed = !!rec.owner;
        us.members = rec.keys ? Object.keys(rec.keys).length : 0;
        us.kidsInProfile = (rec.data && Array.isArray(rec.data.kids)) ? rec.data.kids.length : null;
      }

      users.sort((a, b) => (b.l || '').localeCompare(a.l || ''));
      return json({
        ok: true,
        generatedAt: new Date().toISOString(),
        schemaVersion: 2,
        userCount: users.length,
        activeCount: users.filter(u => u.days7 > 0).length,
        users,
      });
    }

    const mu = url.pathname.match(/^\/admin\/user\/([^/]+)\/?$/);
    if (mu) {
      const bad = adminGate(); if (bad) return bad;
      const uid = decodeURIComponent(mu[1]);
      const raw = await env.NS.get('u:' + uid);
      let u; try { u = raw ? JSON.parse(raw) : null; } catch { u = null; }
      if (!u) return json({ ok: true, user: null });
      return json({ ok: true, user: { id: uid, ...u, summary: summarize(uid, u) } });
    }

    /* ---------- תצוגות גרסה 1, נשמרו כדי לא לשבור דשבורד ישן ---------- */
    if (url.pathname === '/admin/list') {
      const bad = adminGate(); if (bad) return bad;
      const profiles = [];
      let pCursor;
      do {
        const page = await env.NS.list({ prefix: 'p:', cursor: pCursor, limit: 1000 });
        for (const k of page.keys) {
          const raw = await env.NS.get(k.name);
          let rec; try { rec = JSON.parse(raw); } catch { rec = null; }
          const kids = (rec && rec.data && Array.isArray(rec.data.kids)) ? rec.data.kids : [];
          let lastLog = null;
          kids.forEach(kd => (kd.logs || []).forEach(l => { if (!lastLog || l.d > lastLog) lastLog = l.d; }));
          profiles.push({
            code: k.name.slice(2), at: rec ? rec.at : null, kids: kids.length,
            names: (rec && rec.owner) ? kids.map(() => '—') : kids.map(kd => kd.name || '?'),
            logCount: kids.reduce((n, kd) => n + ((kd.logs || []).length), 0),
            lastLog, deviceIds: [], days: {},
          });
        }
        pCursor = page.list_complete ? undefined : page.cursor;
      } while (pCursor);

      const rooms = [];
      let kCursor;
      do {
        const page = await env.NS.list({ prefix: 'k:', cursor: kCursor, limit: 1000 });
        for (const k of page.keys) {
          const raw = await env.NS.get(k.name);
          let room; try { room = JSON.parse(raw); } catch { room = null; }
          rooms.push({
            sid: k.name.slice(2), at: room ? room.at : null,
            kid: room && room.kid ? (room.kid.name || '?') : null,
            members: room && room.keys ? Object.keys(room.keys).length : 0,
            deleted: !!(room && room.del),
          });
        }
        kCursor = page.list_complete ? undefined : page.cursor;
      } while (kCursor);

      const devices = [];
      let dCursor;
      do {
        const page = await env.NS.list({ prefix: 'd:', cursor: dCursor, limit: 1000 });
        for (const k of page.keys) {
          const m = k.metadata || {};
          devices.push({ id: k.name.slice(2), last: m.l || null, activeDays: m.n || 0, profiles: m.p || [] });
        }
        dCursor = page.list_complete ? undefined : page.cursor;
      } while (dCursor);

      const byCode = {};
      profiles.forEach(p => { byCode[p.code] = p; });
      devices.forEach(dv => { (dv.profiles || []).forEach(c => { if (byCode[c]) byCode[c].deviceIds.push(dv.id); }); });
      for (const p of profiles) {
        for (const did of p.deviceIds) {
          const raw = await env.NS.get('d:' + did);
          let rec; try { rec = JSON.parse(raw); } catch { rec = null; }
          if (!rec || !rec.days) continue;
          Object.keys(rec.days).forEach(d => { p.days[d] = (p.days[d] || 0) + rec.days[d]; });
        }
      }
      profiles.sort((a, b) => (b.at || '').localeCompare(a.at || ''));
      rooms.sort((a, b) => (b.at || '').localeCompare(a.at || ''));
      devices.sort((a, b) => (b.last || '').localeCompare(a.last || ''));
      return json({
        ok: true, generatedAt: new Date().toISOString(), schemaVersion: 1,
        profileCount: profiles.length, deviceCount: devices.length,
        orphanDeviceCount: devices.filter(d => !d.profiles.length).length,
        roomCount: rooms.length, profiles, devices, rooms,
      });
    }

    const mdv = url.pathname.match(/^\/admin\/device\/([^/]+)\/?$/);
    if (mdv) {
      const bad = adminGate(); if (bad) return bad;
      const dev = decodeURIComponent(mdv[1]);
      if (!DEV_RE.test(dev)) return json({ ok: false, error: 'bad_dev' }, 400);
      const raw = await env.NS.get('d:' + dev);
      let rec; try { rec = raw ? JSON.parse(raw) : null; } catch { rec = null; }
      if (!rec) return json({ ok: true, device: null });
      return json({ ok: true, device: { id: dev, first: rec.f || null, last: rec.l || null, profiles: rec.profiles || [], days: rec.days || {} } });
    }

    return json({ ok: false, error: 'not_found' }, 404);
  },
};

/* =====================================================================
   הקריאה של הנתונים — כאן נמצאת התובנה
   =====================================================================
   השאלה "למה הוא הפסיק" מוכרעת משלושה סימנים שנאספים ממילא:
   כיוון תנועת הרמה, אחוז ההצלחה, ושיעור הנטישה באמצע סבב.

     שלט ומשתעמם  — רמה מקסימלית שיושבת, דיוק גבוה מאוד, מהיר,
                     ובלי ירידות. אין לאן להתקדם, אז הוא עזב.
     קשה מדי       — ירידות רמה, דיוק נמוך, ושיעור נטישה גבוה.
     פשוט נעלם     — לא שיחק זמן רב, אבל בלי אף אחד משני הסימנים.
                     הסיבה כנראה מחוץ לאפליקציה.

   הסף נקבע לפי מה שהמשחק עצמו עושה: הוא מעלה רמה אחרי סבב מושלם,
   ומוריד אחרי שלוש טעויות. לכן דיוק מעל 0.9 הוא "קל לו", ומתחת
   ל-0.65 הוא "קשה לו" — אותם מספרים בדיוק שבהם המשחק מחליט.
   ===================================================================== */
const MAX_LEVEL = 5;
const MIN_ROUNDS = 4;   /* מתחת לזה לא מסיקים כלום */

/* מודדים מיום הפעילות האחרון (ld). זמן ההעלאה (l) הוא רק גיבוי
   לרשומות ישנות שנכתבו לפני שהשדה הזה נוסף. */
function daysSince(rec) {
  const d = rec && rec.ld;
  if (d && DAY_RE.test(d)) {
    const t = Date.parse(d + 'T00:00:00Z');
    if (isFinite(t)) return Math.max(0, Math.floor((Date.now() - t) / 86400000));
  }
  const iso = rec && rec.l;
  if (!iso) return null;
  const t = Date.parse(iso);
  if (!isFinite(t)) return null;
  return Math.floor((Date.now() - t) / 86400000);
}
function sumDays(map, fromDay) {
  let n = 0;
  for (const d of Object.keys(map || {})) {
    if (fromDay && d < fromDay) continue;
    const v = map[d];
    n += (typeof v === 'number') ? v : (v && v.n) || 0;
  }
  return n;
}
function dayKey(offset) {
  const t = new Date(Date.now() - offset * 86400000);
  return t.getFullYear() + '-' + String(t.getMonth() + 1).padStart(2, '0') + '-' + String(t.getDate()).padStart(2, '0');
}

function verdictFor(G) {
  const idle = daysSince(G);
  const days = Object.keys(G.days || {}).sort();
  const recent = days.slice(-10);
  let n = 0, accW = 0, ab = 0;
  recent.forEach(d => {
    const x = G.days[d] || {};
    n += x.n || 0; ab += x.ab || 0;
    accW += (x.acc || 0) * (x.n || 0);
  });
  const acc = n ? accW / n : null;
  const abRate = (n + ab) ? ab / (n + ab) : 0;
  const atTop = (G.lv || 0) >= MAX_LEVEL;

  /* פחות מכאן זה רעש. סבב בודד חלש קורה לכל ילד, ומסקנה שנאמרת
     עליו היא בדיוק סוג התובנה שאי אפשר לפעול לפיה. */
  if (n < MIN_ROUNDS)
    return { code: 'none', why: 'עוד לא שיחק מספיק כדי להסיק', acc, abRate, idle };

  if (acc !== null && acc >= 0.9 && atTop && G.dn === 0)
    return { code: 'mastered', why: 'שלט ברמה הגבוהה ואין לאן להתקדם', acc, abRate, idle };
  if ((acc !== null && acc < 0.65) || G.dn >= 2 || abRate > 0.3)
    return { code: 'too_hard', why: 'יורד ברמות, מדייק פחות או נוטש סבבים', acc, abRate, idle };
  if (idle !== null && idle >= 14)
    return { code: 'quiet', why: 'לא שיחק לאחרונה, בלי סימן של קושי או שעמום', acc, abRate, idle };
  return { code: 'ok', why: 'מתקדם בקצב סביר', acc, abRate, idle };
}

function summarize(uid, u) {
  const d7 = dayKey(7), d30 = dayKey(30), d60 = dayKey(60);
  const kids = [];
  let days7 = 0, days30 = 0, prev30 = 0;

  for (const slot of Object.keys(u.kids || {})) {
    const K = u.kids[slot];
    const k7 = sumDays(K.days, d7), k30 = sumDays(K.days, d30);
    const kPrev = sumDays(K.days, d60) - k30;
    days7 += k7; days30 += k30; prev30 += kPrev;

    const games = Object.keys(K.games || {}).map(g => {
      const G = K.games[g];
      return {
        g, lv: G.lv, rounds: G.rounds, up: G.up, dn: G.dn, ab: G.ab,
        last: G.ld || G.l, idle: daysSince(G),
        verdict: verdictFor(G),
      };
    }).sort((a, b) => (b.rounds || 0) - (a.rounds || 0));

    kids.push({
      slot: Number(slot), am: K.am, first: K.f, last: K.ld || K.l,
      idle: daysSince(K), rounds7: k7, rounds30: k30, prev30: kPrev,
      games,
      /* המסקנה ברמת הילד היא החמורה מבין המשחקונים שהוא באמת שיחק */
      verdict: pickVerdict(games.map(x => x.verdict)),
    });
  }

  kids.sort((a, b) => a.slot - b.slot);
  /* בלי חודש קודם להשוות אליו אין מגמה. "עלייה של 100%" מול אפס
     היא מספר שנראה כמו תובנה ואינו אחת. */
  const trend = prev30 === 0 ? null : (days30 - prev30) / prev30;

  /* שלושים יום אחרונים כמערך אחד, כדי שהרשימה תוכל לצייר ספארקליין
     בלי בקשה נוספת לכל משתמש */
  const spark = [];
  for (let i = 29; i >= 0; i--) {
    const d = dayKey(i);
    let n = 0;
    for (const slot of Object.keys(u.kids || {})) n += (u.kids[slot].days || {})[d] || 0;
    spark.push(n);
  }

  return {
    id: uid, code: u.code || null, devices: (u.devs || []).length,
    first: u.f, l: u.ld || u.l, idle: daysSince(u),
    kidCount: kids.length, days7, days30, prev30, trend, spark,
    kids,
    verdict: pickVerdict(kids.map(k => k.verdict)),
  };
}

/* קשה מדי גובר על שעמום, ושניהם גוברים על "פשוט נעלם" — כי
   שעמום הוא בעיה שאפשר לפתור בתוכן, וקושי הוא בעיה שמאבדת ילד. */
function pickVerdict(list) {
  const order = ['too_hard', 'mastered', 'quiet', 'ok'];
  for (const code of order) {
    const hit = list.find(v => v && v.code === code);
    if (hit) return hit;
  }
  return { code: 'none', why: 'אין עדיין מספיק נתונים', acc: null, abRate: 0, idle: null };
}
