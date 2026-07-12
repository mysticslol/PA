import asyncio
import tempfile
import os
import re
import csv
import xml.etree.ElementTree as ET
from io import StringIO
from typing import List, Tuple
from app.models.schemas import Vulnerabilite, Severite as SeveriteEnum, AnalyseStructurelle


FONCTIONS_DANGEREUSES = [
    "gets", "strcpy", "strcat", "sprintf", "scanf", "vsprintf",
    "memcpy", "memmove", "strncpy", "strncat", "snprintf",
    "system", "popen", "exec", "execl", "execv", "execlp",
    "malloc", "free", "realloc", "printf", "fprintf",
]

SUGGESTIONS_CPPCHECK = {
    "bufferAccessOutOfBounds": "Vérifiez les bornes du tableau avant l'accès.",
    "nullPointer":   "Vérifiez que le pointeur n'est pas NULL avant de le déréférencer.",
    "memoryLeak":    "Libérez la mémoire allouée avec free() dans tous les chemins d'exécution.",
    "uninitvar":     "Initialisez la variable avant utilisation.",
    "useAfterFree":  "N'accédez plus à la mémoire après l'avoir libérée avec free().",
    "doubleFree":    "Assurez-vous de ne libérer la mémoire qu'une seule fois.",
    "resourceLeak":  "Fermez les ressources (fichiers, sockets) dans tous les chemins d'exécution.",
    "integerOverflow": "Vérifiez les limites des entiers pour éviter le dépassement.",
}

SUGGESTIONS_FLAWFINDER = {
    "gets":    "Remplacez gets() par fgets(buf, sizeof(buf), stdin) — gets() est interdit en C11.",
    "strcpy":  "Remplacez strcpy() par strncpy() ou strlcpy() avec vérification de taille.",
    "strcat":  "Remplacez strcat() par strncat() avec vérification de la taille du buffer.",
    "sprintf": "Remplacez sprintf() par snprintf() avec la taille du buffer en paramètre.",
    "scanf":   "Limitez la taille de la saisie : scanf(\"%9s\", buf) pour un buffer de 10 octets.",
    "system":  "Évitez system() — utilisez exec() avec des arguments contrôlés.",
    "memcpy":  "Vérifiez que la taille copiée ne dépasse pas la taille du buffer destination.",
}


def severite_cppcheck(niveau: str) -> SeveriteEnum:
    # Convertit le niveau cppcheck en notre propre échelle de sévérité
    niveaux = {
        "error":       SeveriteEnum.HAUTE,
        "warning":     SeveriteEnum.MOYENNE,
        "style":       SeveriteEnum.BASSE,
        "performance": SeveriteEnum.BASSE,
        "portability": SeveriteEnum.BASSE,
        "information": SeveriteEnum.INFO,
    }
    return niveaux.get(niveau.lower(), SeveriteEnum.INFO)


def severite_flawfinder(niveau: int) -> SeveriteEnum:
    # Convertit le niveau flawfinder (0-5) en notre propre échelle de sévérité
    if niveau >= 4:
        return SeveriteEnum.CRITIQUE
    if niveau >= 3:
        return SeveriteEnum.HAUTE
    if niveau >= 2:
        return SeveriteEnum.MOYENNE
    if niveau >= 1:
        return SeveriteEnum.BASSE
    return SeveriteEnum.INFO


def categorie_cppcheck(eid: str) -> str:
    # Détermine la catégorie de faille selon l'identifiant d'erreur cppcheck
    if any(k in eid for k in ("buffer", "Array", "Bounds")):
        return "Débordement de tampon"
    if any(k in eid for k in ("memory", "leak", "free", "alloc")):
        return "Gestion mémoire"
    if "null" in eid.lower():
        return "Pointeur nul"
    if "uninit" in eid:
        return "Variable non initialisée"
    if "integer" in eid.lower() or "overflow" in eid.lower():
        return "Dépassement entier"
    return "Qualité de code"


def suggestion_cppcheck(eid: str) -> str:
    # Retourne un conseil de correction selon le type d'erreur détecté
    for cle, conseil in SUGGESTIONS_CPPCHECK.items():
        if cle in eid:
            return conseil
    return "Examinez ce point et appliquez les bonnes pratiques de sécurité C."


def suggestion_flawfinder(fonction: str) -> str:
    # Retourne un conseil de correction selon la fonction dangereuse détectée
    for cle, conseil in SUGGESTIONS_FLAWFINDER.items():
        if cle.lower() in fonction.lower():
            return conseil
    return "Consultez la documentation CERT-C pour les alternatives sécurisées."


async def lancer_cppcheck(chemin: str) -> List[Vulnerabilite]:
    # Lance cppcheck sur le fichier C et retourne les erreurs détectées
    vulns = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "cppcheck", "--xml", "--xml-version=2",
            "--enable=all", "--inconclusive",
            "--suppress=missingIncludeSystem",
            chemin,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        sortie = stderr.decode("utf-8", errors="replace")

        if not sortie.strip().startswith("<"):
            return vulns

        racine = ET.fromstring(sortie)
        ids_ignores = (
            "missingInclude", "missingIncludeSystem",
            "unmatchedSuppression", "checkersReport"
        )

        for erreur in racine.iter("error"):
            eid    = erreur.get("id", "unknown")
            niveau = erreur.get("severity", "information")
            msg    = erreur.get("verbose", erreur.get("msg", ""))
            loc    = erreur.find("location")
            ligne  = int(loc.get("line", 0)) if loc is not None else None

            if eid in ids_ignores:
                continue

            vulns.append(Vulnerabilite(
                id          = f"cppcheck-{eid}",
                titre       = f"[cppcheck] {eid}",
                description = msg,
                severite    = severite_cppcheck(niveau),
                ligne       = ligne,
                outil       = "cppcheck",
                categorie   = categorie_cppcheck(eid),
                suggestion  = suggestion_cppcheck(eid),
            ))

    except (asyncio.TimeoutError, FileNotFoundError, ET.ParseError):
        pass

    return vulns


async def lancer_flawfinder(chemin: str) -> List[Vulnerabilite]:
    # Lance flawfinder sur le fichier C et retourne les fonctions dangereuses détectées
    vulns = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "flawfinder", "--quiet", "--dataonly", "--csv", chemin,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        sortie = stdout.decode("utf-8", errors="replace")

        lecteur = csv.reader(StringIO(sortie))
        for colonnes in lecteur:
            if len(colonnes) < 8:
                continue
            if colonnes[0].strip().lower() == "file":
                continue

            try:
                ligne    = int(colonnes[1].strip())
                niveau   = int(colonnes[4].strip())
                fonction = colonnes[6].strip()
                desc     = colonnes[7].strip()
            except (ValueError, IndexError):
                continue

            vulns.append(Vulnerabilite(
                id          = f"flawfinder-{fonction}-{ligne}",
                titre       = f"[flawfinder] {fonction}",
                description = desc,
                severite    = severite_flawfinder(niveau),
                ligne       = ligne,
                outil       = "flawfinder",
                categorie   = "Buffer/String",
                suggestion  = suggestion_flawfinder(fonction),
            ))

    except (asyncio.TimeoutError, FileNotFoundError):
        pass

    return vulns


def analyser_structure(code: str) -> AnalyseStructurelle:
    # Analyse la structure du code C sans l'exécuter (regex sur le texte brut)
    lignes = code.splitlines()
    nb     = len(lignes)

    fonctions    = re.findall(
        r'^\s*(?:[\w\*]+\s+)+(\w+)\s*\([^)]*\)\s*\{',
        code, re.MULTILINE
    )
    commentaires = re.findall(
        r'//.*$|/\*.*?\*/',
        code, re.MULTILINE | re.DOTALL
    )
    includes = re.findall(r'#include\s*[<"]([^>"]+)[>"]', code)

    fonctions_dang = [
        f for f in FONCTIONS_DANGEREUSES
        if re.search(rf'\b{f}\s*\(', code)
    ]

    if nb < 50:
        complexite = "Faible"
    elif nb < 200:
        complexite = "Modérée"
    elif nb < 500:
        complexite = "Élevée"
    else:
        complexite = "Très élevée"

    return AnalyseStructurelle(
        nb_lignes             = nb,
        nb_fonctions          = len(fonctions),
        nb_commentaires       = len(commentaires),
        complexite_estimee    = complexite,
        imports_detectes      = includes,
        fonctions_dangereuses = fonctions_dang,
    )


async def analyser_c(code: str) -> Tuple[List[Vulnerabilite], AnalyseStructurelle]:
    # Point d'entrée principal — lance cppcheck et flawfinder en parallèle
    structure = analyser_structure(code)

    with tempfile.NamedTemporaryFile(
        suffix=".c", mode="w", delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        chemin = f.name

    try:
        cppcheck, flawfinder = await asyncio.gather(
            lancer_cppcheck(chemin),
            lancer_flawfinder(chemin),
        )
    finally:
        os.unlink(chemin)

    vus   = set()
    vulns = []
    for v in cppcheck + flawfinder:
        cle = (v.ligne, v.outil, v.id)
        if cle not in vus:
            vus.add(cle)
            vulns.append(v)

    for fn in structure.fonctions_dangereuses:
        match = re.search(rf'\b{fn}\s*\(', code)
        if not match:
            continue

        ligne = code[:match.start()].count('\n') + 1
        cle   = (ligne, "structurel", fn)

        if cle in vus:
            continue

        vus.add(cle)
        sev = SeveriteEnum.HAUTE if fn in ("gets", "system") else SeveriteEnum.MOYENNE
        vulns.append(Vulnerabilite(
            id          = f"struct-{fn}",
            titre       = f"Fonction dangereuse : {fn}()",
            description = f"L'utilisation de {fn}() est reconnue comme dangereuse.",
            severite    = sev,
            ligne       = ligne,
            outil       = "analyse-structurelle",
            categorie   = "Fonction dangereuse",
            suggestion  = suggestion_flawfinder(fn),
        ))

    ordre = ["critique", "haute", "moyenne", "basse", "info"]
    vulns.sort(key=lambda v: ordre.index(v.severite.value))

    return vulns, structure
