// Contrôle des licences des dépendances (spec : specs/dependency-management.md). Source : package-lock.json.
//   node scripts/check-licenses.mjs           vérifie (CI) : politique, dérive de licence, inventaire à jour
//   node scripts/check-licenses.mjs --update  régénère specs/licenses.lock.json (à relire dans la PR)
//   node scripts/check-licenses.mjs --fix     met à jour la colonne « V. used » de l'inventaire
// Échoue si : licence interdite ou non revue, licence qui change pour un paquet déjà connu, nouveau paquet absent du
// snapshot, dépendance directe absente de l'inventaire ou avec une version périmée.
import { existsSync, readFileSync, writeFileSync } from "node:fs";

const LOCK = "specs/licenses.lock.json";
const POLICY = "specs/licenses-policy.json";
const INVENTAIRE = "specs/third-party-libraries.md";
const args = new Set(process.argv.slice(2));

// Les binaires natifs optionnels diffèrent selon la plateforme (macOS en local, Linux en CI) : on les replie sur le nom nu.
const PLATEFORME =
  /-(darwin|linux|win32|freebsd|android|openharmony|wasm32)(-[a-z0-9_]+)*$/;
const normaliser = (nom) => nom.replace(PLATEFORME, "");

const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
const installes = new Map(); // nom normalisé → { license, prod, versions:Set }
const versionsPar = new Map();
for (const [chemin, p] of Object.entries(lock.packages)) {
  if (!chemin) continue;
  const nom = chemin.split("node_modules/").pop();
  const cle = normaliser(nom);
  const e = installes.get(cle) ?? {
    license: p.license ?? "UNKNOWN",
    prod: false,
    versions: new Set(),
  };
  e.versions.add(p.version);
  if (!p.dev) e.prod = true;
  installes.set(cle, e);
  versionsPar.set(nom, new Set([...(versionsPar.get(nom) ?? []), p.version]));
}

const politique = JSON.parse(readFileSync(POLICY, "utf8"));
const autorisees = new Set(politique.allowed);
const interdit = new RegExp(politique.deniedPattern, "i");
const erreurs = [];

const jetons = (expr) =>
  expr
    .split(/\s+(?:OR|AND)\s+|[()]/)
    .map((s) => s.trim())
    .filter(Boolean);
function licenceAcceptable(expr) {
  const t = jetons(expr);
  return /\sOR\s/.test(expr) && !/\sAND\s/.test(expr)
    ? t.some((x) => autorisees.has(x))
    : t.every((x) => autorisees.has(x));
}

for (const [nom, e] of installes) {
  if (licenceAcceptable(e.license)) continue;
  const revue = politique.reviewed[nom];
  if (interdit.test(e.license))
    erreurs.push(`Licence interdite : ${nom} (${e.license}).`);
  else if (!revue)
    erreurs.push(
      `Licence non autorisée et non revue : ${nom} (${e.license}) — ajouter à ${POLICY} avec justification, ou retirer.`,
    );
  else if (revue.license !== e.license)
    erreurs.push(
      `Licence revue ${nom} : attendu ${revue.license}, trouvé ${e.license} — revoir.`,
    );
}

// Snapshot : détecte les changements de licence d'un paquet connu et les nouveaux paquets.
const instantane = {};
for (const nom of [...installes.keys()].sort()) {
  const e = installes.get(nom);
  instantane[nom] = { license: e.license, prod: e.prod };
}
if (args.has("--update")) {
  writeFileSync(LOCK, JSON.stringify(instantane, null, 2) + "\n");
  console.log(`${LOCK} régénéré (${Object.keys(instantane).length} paquets).`);
} else {
  const connu = existsSync(LOCK) ? JSON.parse(readFileSync(LOCK, "utf8")) : {};
  for (const [nom, e] of Object.entries(instantane)) {
    if (!connu[nom])
      erreurs.push(
        `Nouveau paquet absent du snapshot : ${nom} (${e.license}) — lancer --update et relire.`,
      );
    else if (connu[nom].license !== e.license)
      erreurs.push(
        `CHANGEMENT DE LICENCE : ${nom} ${connu[nom].license} → ${e.license}`,
      );
    else if (connu[nom].prod !== e.prod)
      erreurs.push(
        `Portée modifiée (dev↔prod) : ${nom} — lancer --update et relire.`,
      );
  }
}

// Inventaire : chaque dépendance directe a une ligne, avec la version installée.
const racine = JSON.parse(readFileSync("package.json", "utf8"));
const directes = new Set(
  Object.keys({ ...racine.dependencies, ...racine.devDependencies }),
);
let md = readFileSync(INVENTAIRE, "utf8");
const lignes = md.split("\n");
for (const nom of [...directes].sort()) {
  const i = lignes.findIndex(
    (l) => l.startsWith("|") && l.split("|")[1].trim() === `\`${nom}\``,
  );
  if (i < 0) {
    erreurs.push(`Dépendance directe absente de ${INVENTAIRE} : ${nom}`);
    continue;
  }
  const attendu = [...(versionsPar.get(nom) ?? [])].sort().join(", ");
  const cellules = lignes[i].split("|");
  if (cellules[6].trim() === attendu) continue;
  if (args.has("--fix")) {
    cellules[6] = ` ${attendu} `;
    lignes[i] = cellules.join("|");
  } else
    erreurs.push(
      `Version périmée dans ${INVENTAIRE} : ${nom} (documenté ${cellules[6].trim()}, installé ${attendu}) — lancer --fix.`,
    );
}
if (args.has("--fix")) {
  writeFileSync(INVENTAIRE, lignes.join("\n"));
  console.log("Colonne V. used mise à jour.");
}

if (erreurs.length && !args.has("--update") && !args.has("--fix")) {
  console.error(erreurs.join("\n"));
  process.exit(1);
}
if (!args.has("--update") && !args.has("--fix"))
  console.log(
    `Licences OK (${installes.size} paquets, ${directes.size} dépendances directes inventoriées).`,
  );
