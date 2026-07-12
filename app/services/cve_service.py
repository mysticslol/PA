import os
import json
from typing import List, Dict, Optional, Tuple
from app.models.schemas import Vulnerabilite, ResultatCVE

DOSSIER_CVE = "./data/cve"
index_cve: Optional[Dict] = None


def lire_fichier_cve(data: dict) -> Optional[dict]:
    # Extrait les informations utiles d'un fichier CVE au format CVElist V5
    try:
        meta     = data.get("cveMetadata", {})
        cve_id   = meta.get("cveId", "")
        statut   = meta.get("state", "")

        if not cve_id or statut == "REJECTED":
            return None

        cna = data.get("containers", {}).get("cna", {})

        descriptions = cna.get("descriptions", [])
        description  = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            ""
        )
        if not description:
            return None

        score = None
        for metric in cna.get("metrics", []):
            if "cvssV3_1" in metric:
                score = metric["cvssV3_1"].get("baseScore")
                break
            if "cvssV4_0" in metric:
                score = metric["cvssV4_0"].get("baseScore")
                break
            if "cvssV3_0" in metric:
                score = metric["cvssV3_0"].get("baseScore")
                break
            if "cvssV2_0" in metric:
                score = metric["cvssV2_0"].get("baseScore")

        produits = []
        for affected in cna.get("affected", []):
            vendeur = affected.get("vendor", "")
            produit = affected.get("product", "")
            if vendeur and produit:
                produits.append(f"{vendeur} {produit}")

        cwes = []
        for pt in cna.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe = desc.get("cweId", "")
                if cwe:
                    cwes.append(f"{cwe}: {desc.get('description', '')}")

        refs = [
            r.get("url", "")
            for r in cna.get("references", [])[:3]
            if r.get("url")
        ]

        return {
            "description": description,
            "score":       score,
            "produits":    list(set(produits))[:5],
            "references":  refs,
            "cwes":        cwes,
            "titre":       cna.get("title", ""),
        }

    except (KeyError, TypeError):
        return None


def charger_index() -> Dict:
    # Parcourt le dossier CVE et charge toutes les entrées en mémoire (une seule fois)
    global index_cve
    if index_cve is not None:
        return index_cve

    index_cve = {}

    if not os.path.isdir(DOSSIER_CVE):
        print(f"[CVE] Dossier introuvable : {DOSSIER_CVE}")
        return index_cve

    nb      = 0
    erreurs = 0

    for racine, dossiers, fichiers in os.walk(DOSSIER_CVE):
        dossiers.sort(reverse=True)

        for fichier in fichiers:
            if not fichier.endswith(".json"):
                continue

            chemin = os.path.join(racine, fichier)
            try:
                with open(chemin, "r", encoding="utf-8") as f:
                    data = json.load(f)

                if data.get("dataType") == "CVE_RECORD":
                    cve_id = data.get("cveMetadata", {}).get("cveId", "")
                    info   = lire_fichier_cve(data)
                    if cve_id and info:
                        index_cve[cve_id] = info
                        nb += 1

            except (json.JSONDecodeError, UnicodeDecodeError):
                erreurs += 1

    print(f"[CVE] {nb} entrées chargées, {erreurs} erreurs ignorées")
    return index_cve


MOTS_CLES = {
    "c": {
        "Buffer/String":       ["buffer overflow", "buffer over-read", "stack overflow",
                                "heap overflow", "out-of-bounds", "strcpy", "gets", "memcpy"],
        "Pointeur nul":        ["null pointer", "null dereference", "segmentation fault"],
        "Gestion mémoire":     ["use-after-free", "double free", "memory leak", "heap corruption"],
        "Dépassement entier":  ["integer overflow", "integer underflow", "integer wrap"],
        "Injection de commandes": ["command injection", "os command", "shell injection"],
        "Fonction dangereuse": ["buffer overflow", "stack overflow", "arbitrary code"],
    },
    "python": {
        "Sérialisation / Crypto":    ["deserialization", "pickle", "weak cryptography", "md5", "sha1"],
        "Injection de commandes":    ["command injection", "os command injection", "shell injection"],
        "Injection de templates":    ["template injection", "server-side template", "ssti", "jinja"],
        "Configuration TLS/SSL":     ["ssl", "tls", "certificate validation", "man-in-the-middle"],
        "Sécurité générale":         ["sql injection", "cross-site scripting", "xss", "csrf"],
        "Assertions / Tests":        ["improper input validation", "missing validation"],
        "Configuration application": ["hardcoded", "hardcoded password", "hardcoded credential"],
    },
}

CWE_VERS_CATEGORIE = {
    "CWE-120": "Buffer/String",    "CWE-121": "Buffer/String",
    "CWE-122": "Buffer/String",    "CWE-125": "Buffer/String",
    "CWE-787": "Buffer/String",    "CWE-119": "Buffer/String",
    "CWE-476": "Pointeur nul",
    "CWE-416": "Gestion mémoire",  "CWE-415": "Gestion mémoire",
    "CWE-401": "Gestion mémoire",
    "CWE-190": "Dépassement entier", "CWE-191": "Dépassement entier",
    "CWE-78":  "Injection de commandes", "CWE-77": "Injection de commandes",
    "CWE-502": "Sérialisation / Crypto", "CWE-327": "Sérialisation / Crypto",
    "CWE-89":  "Sécurité générale", "CWE-79": "Sécurité générale",
    "CWE-798": "Configuration application",
    "CWE-94":  "Injection de templates", "CWE-1336": "Injection de templates",
    "CWE-295": "Configuration TLS/SSL",
}


def score_en_severite(score: Optional[float]) -> str:
    # Convertit un score CVSS numérique en niveau de sévérité (standard CVSS v3.1)
    if score is None:
        return "inconnue"
    if score >= 9.0:
        return "critique"
    if score >= 7.0:
        return "haute"
    if score >= 4.0:
        return "moyenne"
    return "basse"


def corréler_cve(
    vulnerabilites: List[Vulnerabilite],
    langage: str,
) -> Tuple[List[Vulnerabilite], List[ResultatCVE]]:
    # Relie chaque vulnérabilité détectée aux CVE correspondantes dans la base ANSSI
    index = charger_index()
    if not index:
        return vulnerabilites, []

    mots_cles     = MOTS_CLES.get(langage, {})
    cve_trouvees: Dict[str, ResultatCVE] = {}
    vulns_enrichies = []

    for vuln in vulnerabilites:
        cves_liees = []
        mots       = mots_cles.get(vuln.categorie, [])

        if not mots:
            vulns_enrichies.append(vuln)
            continue

        for cve_id, info in index.items():
            desc  = info["description"].lower()
            titre = info.get("titre", "").lower()

            match_texte = any(m in desc or m in titre for m in mots)
            match_cwe   = any(
                CWE_VERS_CATEGORIE.get(c.split(":")[0], "") == vuln.categorie
                for c in info.get("cwes", [])
            )

            if not (match_texte or match_cwe):
                continue

            s = info.get("score")
            if cve_id not in cve_trouvees:
                cve_trouvees[cve_id] = ResultatCVE(
                    cve_id            = cve_id,
                    description       = info["description"][:300],
                    cvss_score        = s,
                    severite          = score_en_severite(s),
                    produits_affectes = info["produits"],
                    references        = info["references"],
                )
            cves_liees.append(cve_id)

        scores = [
            index[c]["score"]
            for c in cves_liees
            if index.get(c, {}).get("score")
        ]
        vuln_copy = vuln.model_copy(update={
            "cve_ids":    cves_liees[:5],
            "cvss_score": max(scores) if scores else None,
        })
        vulns_enrichies.append(vuln_copy)

    top_cve = sorted(
        cve_trouvees.values(),
        key=lambda c: c.cvss_score or 0,
        reverse=True
    )[:20]

    return vulns_enrichies, top_cve
