import asyncio
import tempfile
import os
import re
import json
from typing import List, Tuple
from app.models.schemas import Vulnerabilite, Severite as SeveriteEnum, AnalyseStructurelle


NIVEAUX_BANDIT = {
    "HIGH":   SeveriteEnum.HAUTE,
    "MEDIUM": SeveriteEnum.MOYENNE,
    "LOW":    SeveriteEnum.BASSE,
}

FONCTIONS_DANGEREUSES = [
    "eval", "exec", "compile",
    "pickle.loads", "pickle.load",
    "os.system", "subprocess.call", "subprocess.Popen",
    "input", "__import__", "open",
]

SUGGESTIONS = {
    "B101": "Retirez les assertions en production ou utilisez une validation explicite.",
    "B102": "N'utilisez pas exec() — c'est une porte d'entrée pour l'injection de code.",
    "B103": "Les permissions de fichiers trop permissives exposent des données sensibles.",
    "B104": "N'écoutez pas sur 0.0.0.0 sans contrôle d'accès réseau.",
    "B105": "Ne hardcodez jamais de mots de passe — utilisez des variables d'environnement.",
    "B106": "Utilisez secrets.token_hex() au lieu de valeurs fixes.",
    "B107": "Les mots de passe dans les arguments sont visibles dans les logs.",
    "B108": "Les fichiers temporaires prédictibles sont exploitables — utilisez tempfile.mkstemp().",
    "B110": "Un except vide masque les erreurs — loguez au minimum l'exception.",
    "B201": "Flask en mode debug expose un débogueur — désactivez en production.",
    "B301": "pickle.loads() avec des données non fiables permet l'exécution de code arbitraire.",
    "B302": "marshal n'est pas sécurisé pour les données non fiables.",
    "B303": "MD5 et SHA1 sont cryptographiquement faibles — utilisez SHA256 ou plus.",
    "B304": "Les algorithmes faibles (DES, RC4) ne protègent pas vos données.",
    "B307": "eval() exécute du code arbitraire — n'utilisez jamais avec des entrées utilisateur.",
    "B311": "random n'est pas cryptographiquement sécurisé — utilisez le module secrets.",
    "B320": "xml.etree est vulnérable au XXE — utilisez defusedxml.",
    "B401": "Telnet transmet en clair — utilisez SSH.",
    "B501": "La validation SSL désactivée expose aux attaques MITM.",
    "B601": "L'injection de commandes shell est critique — utilisez subprocess avec une liste.",
    "B602": "subprocess avec shell=True est vulnérable — passez une liste d'arguments.",
    "B603": "Vérifiez les entrées passées à subprocess.",
    "B604": "L'exécution de code shell depuis des entrées non contrôlées est dangereuse.",
    "B605": "os.system() est vulnérable à l'injection — utilisez subprocess.run().",
    "B608": "Requête SQL construite par concaténation — utilisez des requêtes paramétrées.",
    "B701": "Jinja2 sans auto-échappement est vulnérable au XSS.",
}


def categorie_bandit(test_id: str) -> str:
    # Retourne la catégorie de sécurité selon le numéro de règle bandit
    num = int(test_id[1:]) if test_id[1:].isdigit() else 0

    if 100 <= num <= 199:
        return "Assertions / Tests"
    if 200 <= num <= 299:
        return "Configuration application"
    if 300 <= num <= 399:
        return "Sérialisation / Crypto"
    if 400 <= num <= 499:
        return "Protocoles non sécurisés"
    if 500 <= num <= 599:
        return "Configuration TLS/SSL"
    if 600 <= num <= 699:
        return "Injection de commandes"
    if 700 <= num <= 799:
        return "Injection de templates"

    return "Sécurité générale"


async def lancer_bandit(chemin: str) -> List[Vulnerabilite]:
    # Lance bandit sur le fichier Python et retourne les vulnérabilités détectées
    vulns = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "bandit", "-f", "json", "-q", "-ll", chemin,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        sortie = stdout.decode("utf-8", errors="replace")

        if not sortie.strip():
            return vulns

        data = json.loads(sortie)
        for r in data.get("results", []):
            test_id  = r.get("test_id", "")
            severite = NIVEAUX_BANDIT.get(
                r.get("issue_severity", "LOW"),
                SeveriteEnum.BASSE
            )
            vulns.append(Vulnerabilite(
                id          = f"bandit-{test_id}",
                titre       = f"[bandit] {r.get('test_name', '')}",
                description = r.get("issue_text", ""),
                severite    = severite,
                ligne       = r.get("line_number"),
                colonne     = r.get("col_offset"),
                outil       = "bandit",
                categorie   = categorie_bandit(test_id),
                suggestion  = SUGGESTIONS.get(test_id, f"Consultez la doc bandit : {test_id}"),
            ))

    except (asyncio.TimeoutError, FileNotFoundError, json.JSONDecodeError):
        pass

    return vulns


async def lancer_pyflakes(chemin: str) -> List[Vulnerabilite]:
    # Lance pyflakes pour détecter les problèmes de qualité (imports inutilisés, etc.)
    vulns = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "python3", "-m", "pyflakes", chemin,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=20)
        sortie = (stdout + stderr).decode("utf-8", errors="replace")

        for ligne in sortie.strip().splitlines():
            match = (
                re.match(r".+:(\d+):\d+\s+(.+)", ligne)
                or re.match(r".+:(\d+):\s+(.+)", ligne)
            )
            if match:
                vulns.append(Vulnerabilite(
                    id          = f"pyflakes-{match.group(1)}",
                    titre       = "[pyflakes] Problème de code",
                    description = match.group(2),
                    severite    = SeveriteEnum.BASSE,
                    ligne       = int(match.group(1)),
                    outil       = "pyflakes",
                    categorie   = "Qualité de code",
                    suggestion  = "Corrigez les imports inutilisés et variables non définies.",
                ))

    except (asyncio.TimeoutError, FileNotFoundError):
        pass

    return vulns


def analyser_structure(code: str) -> AnalyseStructurelle:
    # Analyse la structure du code Python sans l'exécuter (regex sur le texte brut)
    lignes = code.splitlines()
    nb     = len(lignes)

    fonctions    = re.findall(r'^\s*(?:async\s+)?def\s+(\w+)\s*\(', code, re.MULTILINE)
    commentaires = re.findall(r'#.*$|""".*?"""|\'\'\'.*?\'\'\'', code, re.MULTILINE | re.DOTALL)
    imports      = re.findall(r'^(?:import|from)\s+([\w.]+)', code, re.MULTILINE)

    fonctions_dang = [
        fn for fn in FONCTIONS_DANGEREUSES
        if re.search(fn.replace(".", r"\.") + r"\s*\(", code)
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
        imports_detectes      = list(set(imports)),
        fonctions_dangereuses = fonctions_dang,
    )


async def analyser_python(code: str) -> Tuple[List[Vulnerabilite], AnalyseStructurelle]:
    # Point d'entrée principal — lance bandit et pyflakes en parallèle
    structure = analyser_structure(code)

    with tempfile.NamedTemporaryFile(
        suffix=".py", mode="w", delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        chemin = f.name

    try:
        bandit, pyflakes = await asyncio.gather(
            lancer_bandit(chemin),
            lancer_pyflakes(chemin)
        )
    finally:
        os.unlink(chemin)

    vus   = set()
    vulns = []
    for v in bandit + pyflakes:
        cle = (v.ligne, v.outil, v.id)
        if cle not in vus:
            vus.add(cle)
            vulns.append(v)

    ordre = ["critique", "haute", "moyenne", "basse", "info"]
    vulns.sort(key=lambda v: ordre.index(v.severite.value))

    return vulns, structure
