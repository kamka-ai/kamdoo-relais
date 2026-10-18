# Kamdoo notification relay

The relay that carries notifications from your company's Odoo to the **[Kamdoo](https://kamdoo.kamka-it.com)** app, through Apple (APNs) and Google (FCM).

It forwards messages that Odoo has already encrypted for one phone. It **cannot read them**: the decryption key never leaves the phone. It **stores nothing**: no database, nothing written to disk. One file, no dependencies: [`serveur.mjs`](serveur.mjs).

*[Version française plus bas.](#français)*

## How it works

1. **The phone** creates a P-256 key pair for each company. It registers with the relay, which returns a delivery address, and gives your Odoo that address and its public key.
2. **Your Odoo** encrypts each notification for that phone (Web Push, RFC 8291: ECDH, HKDF-SHA-256, AES-128-GCM), signs the request (VAPID, RFC 8292) and posts it to the delivery address.
3. **The relay** checks the signature, then passes the encrypted message as it is to Apple or Google.
4. **The phone** decrypts it and shows it.

| Route | Called by | What it does |
|---|---|---|
| `POST /v1/inscription` | the app | Returns a delivery address. The phone's Apple or Google token is **sealed** inside it (AES-256-GCM, key `RELAIS_SECRET`), with a fingerprint of the ERP's VAPID key and a 16-character label. Nothing is stored. |
| `POST /v1/e/<sealed>` | Odoo | Opens the seal, refuses any request whose VAPID signature does not match the fingerprint (only the ERP the phone registered with can write to it), then forwards the encrypted message. Answers 410 when Apple or Google report an uninstalled app, so Odoo forgets the device. |
| `GET /v1/f/<id>` | the app | A message too long for a notification: kept in memory, handed over **once**, then erased; erased after 10 minutes if nobody asks. |
| `GET /sante` | monitoring | Whether each key is present and readable, never showing it. |

On iPhone, Apple only sees a neutral text ("Kamdoo", "…") that Kamdoo's notification extension replaces with the decrypted message. On Android, Google gets a data-only message that the app decrypts. Both expire after one hour.

## What it keeps, exactly

- **No database, no file.** Nothing about phones, messages or companies is written to disk.
- **The phone's token** lives sealed in the delivery address, which your Odoo keeps. The relay opens it for one delivery, then forgets it.
- **Long messages:** at most 10 minutes in memory, handed over once.
- **Caller IP addresses:** counted in memory to block abuse (too many requests per minute), erased within two minutes, never written.
- **Logs:** the startup line and, when Google refuses a delivery, the error code. Never an identifier, an address or any content.

Run it behind a reverse proxy that does not log its requests. Ours is Traefik with `traefik.http.routers.<router>.observability.accesslogs=false` on the relay's routers.

## Configuration

| Variable | Secret | Purpose |
|---|:-:|---|
| `RELAIS_SECRET` | yes | 32 bytes, base64 (`openssl rand -base64 32`): seals the phone's token |
| `RELAIS_ORIGINE` | no | Public address of the relay, e.g. `https://push.example.com` |
| `APNS_CLE` | yes | Content of the Apple `.p8` key (Apple Push Notifications service) |
| `APNS_CLE_ID` | no | ID of that key (10 characters) |
| `APNS_EQUIPE` | no | Apple team ID |
| `APNS_SUJET` | no | App bundle ID (default `com.kamkait.kamdoo`) |
| `FCM_COMPTE` | yes | JSON of a Firebase service account allowed to send messages |
| `PORT` | no | Listening port (default `8080`) |

Secrets go in your host's environment variables, never in the repository.

## Run

```
docker build -t kamdoo-relais .
docker run -p 8080:8080 -e RELAIS_SECRET=... -e RELAIS_ORIGINE=https://push.example.com ... kamdoo-relais
```

Local test without Apple or Google, notifications printed instead of sent:

```
RELAIS_SECRET=$(openssl rand -base64 32) RELAIS_FAUX=1 RELAIS_ORIGINE=http://localhost:8080 node serveur.mjs
```

The Odoo side is the free module **[kamdoo_connect](https://github.com/kamka-ai/kamdoo-odoo)** on Odoo 14 to 16; Odoo 17 and later do Web Push natively.

## License

[LGPL-3](LICENSE). Published by [Kamka IT](https://kamka-it.com) · contact@kamka-it.com · [Privacy policy](https://kamdoo.kamka-it.com/privacy.html)

---

## Français

Le relais qui transporte les notifications de l'Odoo de votre société jusqu'à l'app **[Kamdoo](https://kamdoo.kamka-it.com)**, par Apple (APNs) et Google (FCM).

Il transmet des messages qu'Odoo a déjà chiffrés pour un seul téléphone. Il **ne peut pas les lire** : la clé de déchiffrement ne quitte jamais le téléphone. Il **ne stocke rien** : ni base de données, ni écriture sur disque. Un seul fichier, sans dépendance : [`serveur.mjs`](serveur.mjs).

### Comment ça marche

1. **Le téléphone** crée une paire de clés P-256 par société. Il s'inscrit auprès du relais, qui lui rend une adresse de livraison, et donne à votre Odoo cette adresse et sa clé publique.
2. **Votre Odoo** chiffre chaque notification pour ce téléphone (Web Push, RFC 8291 : ECDH, HKDF-SHA-256, AES-128-GCM), signe l'envoi (VAPID, RFC 8292) et le poste à l'adresse de livraison.
3. **Le relais** vérifie la signature, puis transmet le message chiffré tel quel à Apple ou Google.
4. **Le téléphone** le déchiffre et l'affiche.

| Route | Appelée par | Ce qu'elle fait |
|---|---|---|
| `POST /v1/inscription` | l'app | Rend une adresse de livraison. Le jeton Apple ou Google du téléphone y est **scellé** (AES-256-GCM, clé `RELAIS_SECRET`), avec une empreinte de la clé VAPID de l'ERP et une étiquette de 16 caractères. Rien n'est stocké. |
| `POST /v1/e/<scellé>` | Odoo | Ouvre le sceau, refuse tout envoi dont la signature VAPID ne correspond pas à l'empreinte (seul l'ERP auquel le téléphone s'est inscrit peut lui écrire), puis transmet le message chiffré. Répond 410 quand Apple ou Google signalent une app désinstallée : Odoo oublie l'appareil. |
| `GET /v1/f/<id>` | l'app | Un message trop long pour une notification : gardé en mémoire, remis **une seule fois**, puis effacé ; effacé au bout de 10 minutes s'il n'est pas demandé. |
| `GET /sante` | la surveillance | Si chaque clé est présente et lisible, sans jamais la montrer. |

Sur iPhone, Apple ne voit qu'un texte neutre (« Kamdoo », « … ») que l'extension de notification de Kamdoo remplace par le message déchiffré. Sur Android, Google reçoit un message de données seules, déchiffré par l'app. Les deux expirent au bout d'une heure.

### Ce qu'il garde, exactement

- **Aucune base, aucun fichier.** Rien sur les téléphones, les messages ou les sociétés n'est écrit sur disque.
- **Le jeton du téléphone** est scellé dans l'adresse de livraison, que garde votre Odoo. Le relais l'ouvre le temps d'un envoi, puis l'oublie.
- **Messages longs** : 10 minutes au plus en mémoire, remis une seule fois.
- **Adresses IP des appelants** : comptées en mémoire pour bloquer les abus (trop de demandes à la minute), effacées en deux minutes au plus, jamais écrites.
- **Journal** : la ligne de démarrage et, si Google refuse un envoi, le code d'erreur. Jamais d'identifiant, d'adresse ni de contenu.

Faites-le tourner derrière un proxy qui ne journalise pas ses requêtes. Le nôtre est Traefik, avec `traefik.http.routers.<routeur>.observability.accesslogs=false` sur les routeurs du relais.

### Configuration

Les variables sont dans le tableau anglais plus haut. Les secrets vont dans les variables d'environnement de l'hébergeur, jamais dans le dépôt. Essai local sans Apple ni Google : `RELAIS_FAUX=1` (les notifications sont écrites au lieu d'être envoyées).

Côté Odoo : le module gratuit **[kamdoo_connect](https://github.com/kamka-ai/kamdoo-odoo)** sur Odoo 14 à 16 ; Odoo 17 et suivants font le Web Push d'eux-mêmes.

### Licence

[LGPL-3](LICENSE). Édité par [Kamka IT](https://kamka-it.com) · contact@kamka-it.com · [Politique de confidentialité](https://kamdoo.kamka-it.com/confidentialite.html)
