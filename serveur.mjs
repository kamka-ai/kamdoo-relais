/**
 * Relais des notifications de Kamdoo (aucune dépendance, aucune base, aucun journal du contenu).
 *
 * POST /v1/inscription  {plateforme, jeton, environnement, vapid, etiquette}
 *   → {endpoint} : une adresse Web Push propre au téléphone. Le jeton Apple / Google y est SCELLÉ (AES-256-GCM,
 *     clé RELAIS_SECRET) : l'ERP qui la garde ne voit pas le jeton, et le relais n'a rien à stocker.
 * POST /v1/e/<scellé>   (Odoo, Web Push RFC 8030/8291/8292)
 *   → vérifie la signature VAPID (seul l'ERP inscrit peut écrire à ce téléphone), puis transmet le message
 *     CHIFFRÉ tel quel à Apple (APNs) ou Google (FCM). Le relais n'a pas la clé : il ne peut pas le lire.
 * GET  /v1/f/<id>       message trop long pour tenir dans la notification : gardé 10 minutes en mémoire, remis
 *                       une seule fois au téléphone qui le demande, puis effacé.
 * GET  /sante
 */
import crypto from 'node:crypto';
import http from 'node:http';
import http2 from 'node:http2';

const PORT = Number(process.env.PORT || 8080);
const ORIGINE = (process.env.RELAIS_ORIGINE || 'https://push.kamdoo.kamka-it.com').replace(/\/$/, '');
const SECRET = process.env.RELAIS_SECRET ? Buffer.from(process.env.RELAIS_SECRET, 'base64') : null;
const APNS = process.env.APNS_CLE && process.env.APNS_CLE_ID && process.env.APNS_EQUIPE
  ? { cle: process.env.APNS_CLE.replace(/\\n/g, '\n'), id: process.env.APNS_CLE_ID, equipe: process.env.APNS_EQUIPE, sujet: process.env.APNS_SUJET || 'com.kamkait.kamdoo' }
  : null;
const FCM = process.env.FCM_COMPTE ? JSON.parse(process.env.FCM_COMPTE) : null;
// La clé collée dans Coolify s'ouvre-t-elle (clé P-256, retours à la ligne gardés) ? Dit par /sante, sans la montrer.
function cleLisible(cle, courbe) {
  try {
    const k = crypto.createPrivateKey(cle);
    return !courbe || k.asymmetricKeyDetails?.namedCurve === courbe;
  } catch {
    return false;
  }
}
const APNS_VALIDE = !!APNS && /^[A-Z0-9]{10}$/.test(APNS.id) && cleLisible(APNS.cle, 'prime256v1');
const FCM_VALIDE = !!FCM && cleLisible(FCM.private_key);
// Essais locaux : rien n'est envoyé à Apple ni à Google, la notification est écrite sur la sortie.
const FAUX = process.env.RELAIS_FAUX === '1';

const INLINE_MAX = 3000; // caractères base64url : au-delà, le téléphone vient chercher le message
const GARDE_MS = 10 * 60 * 1000;
const gardes = new Map(); // id → { donnees, fin }

const b64u = (b) => Buffer.from(b).toString('base64url');
const deB64u = (s) => Buffer.from(s, 'base64url');

// --- Sceau du jeton du téléphone ---

function sceller(objet) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', SECRET, iv);
  const corps = Buffer.concat([c.update(JSON.stringify(objet)), c.final()]);
  return b64u(Buffer.concat([iv, corps, c.getAuthTag()]));
}

function desceller(texte) {
  const brut = deB64u(texte);
  if (brut.length < 29) throw new Error('scellé');
  const d = crypto.createDecipheriv('aes-256-gcm', SECRET, brut.subarray(0, 12));
  d.setAuthTag(brut.subarray(brut.length - 16));
  return JSON.parse(Buffer.concat([d.update(brut.subarray(12, brut.length - 16)), d.final()]).toString());
}

const empreinte = (vapid) => b64u(crypto.createHash('sha256').update(vapid).digest()).slice(0, 22);

// --- Signature VAPID (RFC 8292) : « vapid t=<JWT ES256>, k=<clé publique> » ---

function cleP256(brute) {
  const o = deB64u(brute);
  if (o.length !== 65 || o[0] !== 4) throw new Error('clé VAPID');
  return crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b64u(o.subarray(1, 33)), y: b64u(o.subarray(33)) }, format: 'jwk' });
}

function verifierVapid(entete, attendue) {
  const m = /^vapid\s+t=([^,\s]+)\s*,\s*k=([^,\s]+)/i.exec(entete || '');
  if (!m) return 'autorisation absente';
  const [, jeton, k] = m;
  if (empreinte(k) !== attendue) return 'clé VAPID inconnue pour ce téléphone';
  const [h, p, s] = jeton.split('.');
  if (!h || !p || !s) return 'jeton VAPID mal formé';
  const valide = crypto.verify('sha256', Buffer.from(`${h}.${p}`), { key: cleP256(k), dsaEncoding: 'ieee-p1363' }, deB64u(s));
  if (!valide) return 'signature VAPID invalide';
  const charge = JSON.parse(deB64u(p).toString());
  const maintenant = Date.now() / 1000;
  if (charge.aud !== ORIGINE) return 'audience VAPID';
  if (!(charge.exp > maintenant && charge.exp < maintenant + 25 * 3600)) return 'jeton VAPID expiré';
  return null;
}

// --- Apple (APNs, jeton de fournisseur ES256) ---

let jetonApns = { valeur: '', fin: 0 };
function jetonFournisseur() {
  if (Date.now() < jetonApns.fin) return jetonApns.valeur;
  const h = b64u(JSON.stringify({ alg: 'ES256', kid: APNS.id }));
  const p = b64u(JSON.stringify({ iss: APNS.equipe, iat: Math.floor(Date.now() / 1000) }));
  const s = crypto.sign('sha256', Buffer.from(`${h}.${p}`), { key: APNS.cle, dsaEncoding: 'ieee-p1363' });
  jetonApns = { valeur: `${h}.${p}.${b64u(s)}`, fin: Date.now() + 45 * 60 * 1000 };
  return jetonApns.valeur;
}

const connexionsApns = {};
function connexionApns(environnement) {
  const hote = environnement === 'sandbox' ? 'https://api.sandbox.push.apple.com' : 'https://api.push.apple.com';
  const c = connexionsApns[hote];
  if (c && !c.closed && !c.destroyed) return c;
  const nouvelle = http2.connect(hote);
  nouvelle.on('error', () => {});
  nouvelle.on('goaway', () => nouvelle.close());
  connexionsApns[hote] = nouvelle;
  return nouvelle;
}

function envoyerApns(scelle, k) {
  const corps = JSON.stringify({
    // Texte neutre, remplacé sur le téléphone par le vrai message déchiffré (extension de notification).
    aps: { alert: { title: 'Kamdoo', body: '…' }, 'mutable-content': 1, sound: 'default', 'thread-id': k.a },
    k,
  });
  if (FAUX) return Promise.resolve(console.log('APNS', scelle.e, corps) ?? 200);
  return new Promise((resoudre) => {
    const flux = connexionApns(scelle.e).request({
      ':method': 'POST',
      ':path': `/3/device/${scelle.t}`,
      authorization: `bearer ${jetonFournisseur()}`,
      'apns-topic': APNS.sujet,
      'apns-push-type': 'alert',
      'apns-priority': '10',
      'apns-expiration': String(Math.floor(Date.now() / 1000) + 3600),
    });
    let statut = 0;
    let reponse = '';
    flux.on('response', (h) => (statut = Number(h[':status'])));
    flux.on('data', (d) => (reponse += d));
    flux.on('end', () => {
      // Jeton périmé (app désinstallée…) : 410 pour qu'Odoo oublie l'appareil.
      if (statut === 410 || /BadDeviceToken|DeviceTokenNotForTopic|Unregistered/.test(reponse)) resoudre(410);
      else resoudre(statut === 200 ? 200 : 502);
    });
    flux.on('error', () => resoudre(502));
    flux.end(corps);
  });
}

// --- Google (FCM HTTP v1, compte de service) ---

let jetonFcm = { valeur: '', fin: 0 };
async function jetonGoogle() {
  if (Date.now() < jetonFcm.fin) return jetonFcm.valeur;
  const maintenant = Math.floor(Date.now() / 1000);
  const h = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const p = b64u(JSON.stringify({ iss: FCM.client_email, scope: 'https://www.googleapis.com/auth/firebase.messaging', aud: 'https://oauth2.googleapis.com/token', iat: maintenant, exp: maintenant + 3600 }));
  const s = crypto.sign('sha256', Buffer.from(`${h}.${p}`), FCM.private_key);
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${h}.${p}.${b64u(s)}` }),
  });
  const j = await r.json().catch(() => ({}));
  // Gardé seulement si Google l'a vraiment délivré : un refus (clé révoquée, horloge…) gardé 45 minutes
  // ferait échouer en silence tous les envois Android pendant ce temps.
  if (!r.ok || !j.access_token) {
    console.error('FCM jeton refusé', r.status, j.error ?? '');
    return null;
  }
  jetonFcm = { valeur: j.access_token, fin: Date.now() + 45 * 60 * 1000 };
  return jetonFcm.valeur;
}

async function envoyerFcm(scelle, k, nouvelEssai = true) {
  const message = { message: { token: scelle.t, data: { k: JSON.stringify(k) }, android: { priority: 'HIGH', ttl: '3600s' } } };
  if (FAUX) return console.log('FCM', JSON.stringify(message)) ?? 200;
  const jeton = await jetonGoogle();
  if (!jeton) return 502;
  const r = await fetch(`https://fcm.googleapis.com/v1/projects/${FCM.project_id}/messages:send`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${jeton}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(message),
  });
  if (r.ok) return 200;
  const texte = await r.text();
  // Jeton expiré ou retiré côté Google : un nouveau, une seule fois.
  if (r.status === 401 && nouvelEssai) {
    jetonFcm = { valeur: '', fin: 0 };
    return envoyerFcm(scelle, k, false);
  }
  if (r.status === 404 || /UNREGISTERED|INVALID_ARGUMENT.*token/i.test(texte)) return 410;
  // Le code d'erreur seul : ni le jeton du téléphone ni le message (chiffré) ne vont dans les journaux.
  console.error('FCM refus', r.status, /"status":\s*"([A-Z_]+)"/.exec(texte)?.[1] ?? '');
  return 502;
}

// --- Limites simples, par adresse IP ---

const compteurs = new Map();
function tropDeDemandes(ip, max) {
  const minute = Math.floor(Date.now() / 60000);
  const cle = `${ip}|${minute}`;
  const n = (compteurs.get(cle) ?? 0) + 1;
  compteurs.set(cle, n);
  return n > max;
}

// Chaque minute : les messages longs non retirés à 10 minutes, et les compteurs par adresse IP des minutes
// passées (une adresse ne reste pas en mémoire plus de deux minutes ; elle n'est jamais écrite).
setInterval(() => {
  const maintenant = Date.now();
  for (const [id, g] of gardes) if (g.fin < maintenant) gardes.delete(id);
  const minute = `|${Math.floor(maintenant / 60000)}`;
  for (const c of compteurs.keys()) if (!c.endsWith(minute)) compteurs.delete(c);
}, 60000).unref();

// --- Serveur ---

function lireCorps(req, max) {
  return new Promise((resoudre, rejeter) => {
    const morceaux = [];
    let taille = 0;
    req.on('data', (d) => {
      taille += d.length;
      if (taille > max) {
        rejeter(new Error('trop long'));
        req.destroy();
      } else morceaux.push(d);
    });
    req.on('end', () => resoudre(Buffer.concat(morceaux)));
    req.on('error', rejeter);
  });
}

function repondre(res, statut, objet) {
  res.writeHead(statut, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(objet === undefined ? '' : JSON.stringify(objet));
}

const serveur = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://relais');
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  try {
    if (req.method === 'GET' && url.pathname === '/sante') return repondre(res, 200, { ok: !!SECRET, apns: !!APNS, apns_cle_valide: APNS_VALIDE, fcm: !!FCM, fcm_cle_valide: FCM_VALIDE });
    if (!SECRET) return repondre(res, 503, { erreur: 'RELAIS_SECRET manquant' });

    if (req.method === 'POST' && url.pathname === '/v1/inscription') {
      if (tropDeDemandes(ip, 30)) return repondre(res, 429, { erreur: 'trop de demandes' });
      const d = JSON.parse((await lireCorps(req, 4096)).toString());
      const valide =
        ['ios', 'android'].includes(d.plateforme) &&
        typeof d.jeton === 'string' && d.jeton.length >= 32 && d.jeton.length <= 4096 &&
        typeof d.vapid === 'string' && /^[A-Za-z0-9_-]{80,100}$/.test(d.vapid) &&
        typeof d.etiquette === 'string' && /^[A-Za-z0-9_-]{4,40}$/.test(d.etiquette);
      if (!valide) return repondre(res, 400, { erreur: 'inscription invalide' });
      if ((d.plateforme === 'ios' && !APNS && !FAUX) || (d.plateforme === 'android' && !FCM && !FAUX)) return repondre(res, 503, { erreur: 'plateforme non configurée' });
      const scelle = sceller({ p: d.plateforme, t: d.jeton, e: d.environnement === 'sandbox' ? 'sandbox' : 'production', k: empreinte(d.vapid), a: d.etiquette });
      return repondre(res, 200, { endpoint: `${ORIGINE}/v1/e/${scelle}` });
    }

    const envoi = /^\/v1\/e\/([A-Za-z0-9_-]+)$/.exec(url.pathname);
    if (req.method === 'POST' && envoi) {
      if (tropDeDemandes(ip, 600)) return repondre(res, 429, { erreur: 'trop de demandes' });
      let scelle;
      try {
        scelle = desceller(envoi[1]);
      } catch {
        return repondre(res, 404, { erreur: 'adresse inconnue' });
      }
      const refus = verifierVapid(req.headers.authorization, scelle.k);
      if (refus) return repondre(res, 401, { erreur: refus });
      if (String(req.headers['content-encoding']).toLowerCase() !== 'aes128gcm') return repondre(res, 415, { erreur: 'aes128gcm attendu' });
      const chiffre = await lireCorps(req, 8192);
      const texte = b64u(chiffre);
      const k = { a: scelle.a, o: ORIGINE };
      if (texte.length <= INLINE_MAX) k.c = texte;
      else {
        const id = b64u(crypto.randomBytes(16));
        gardes.set(id, { donnees: chiffre, fin: Date.now() + GARDE_MS });
        k.f = id;
      }
      const statut = scelle.p === 'ios' ? await envoyerApns(scelle, k) : await envoyerFcm(scelle, k);
      // 201 : ce qu'attend Odoo d'un service Web Push ; 410 : il oublie l'appareil.
      return repondre(res, statut === 200 ? 201 : statut);
    }

    const retrait = /^\/v1\/f\/([A-Za-z0-9_-]+)$/.exec(url.pathname);
    if (req.method === 'GET' && retrait) {
      const g = gardes.get(retrait[1]);
      gardes.delete(retrait[1]);
      if (!g || g.fin < Date.now()) return repondre(res, 404, { erreur: 'introuvable' });
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-store' });
      return res.end(g.donnees);
    }
    return repondre(res, 404, { erreur: 'introuvable' });
  } catch (e) {
    return repondre(res, 400, { erreur: 'requête invalide' });
  }
});

serveur.listen(PORT, () => console.log(`relais Kamdoo sur :${PORT} (apns: ${!!APNS}${APNS && !APNS_VALIDE ? ' — CLÉ ILLISIBLE' : ''}, fcm: ${!!FCM}${FCM && !FCM_VALIDE ? ' — CLÉ ILLISIBLE' : ''}${FAUX ? ', essai' : ''})`));
