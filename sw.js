/* הצעד הבא — service worker
   אסטרטגיה: cache-first לקליפה, עם רענון ברקע.
   כשמעלים גרסה חדשה — משנים את CACHE, וזה מוחק את הישן. */
const CACHE = 'hatzaad-haba-v14';
const SHELL = ['./', './index.html', './manifest.webmanifest', './icon-192.png', './icon-512.png'];
/* המשחקים כבדים — הם נכנסים למטמון בפעם הראשונה שמשחקים בהם, לא בהתקנה */

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if(req.method !== 'GET') return;                       /* סנכרון ענן לא נכנס למטמון */
  const url = new URL(req.url);
  if(url.origin !== self.location.origin) return;        /* בקשות חוץ — ישר לרשת */

  e.respondWith(
    caches.match(req).then(hit => {
      const net = fetch(req).then(res => {
        if(res && res.status === 200){
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(req, copy));
        }
        return res;
      }).catch(() => hit);
      return hit || net;
    })
  );
});
