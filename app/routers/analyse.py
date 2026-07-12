import uuid
import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db, RapportDB
from app.models.schemas import DemandeAnalyse, RapportAnalyse, Langage, Mode
from app.engines.moteur_c import analyser_c
from app.engines.moteur_python import analyser_python
from app.services.cve_service import corréler_cve
from app.services.rapport_service import sauvegarder_json, sauvegarder_html

router = APIRouter()

POIDS = {
    "critique": 25,
    "haute":    10,
    "moyenne":   4,
    "basse":     1,
    "info":      0,
}


def calculer_score(vulns) -> int:
    # Score de 0 à 100 — chaque vulnérabilité retire des points selon sa sévérité
    penalite = 0
    for v in vulns:
        penalite += POIDS.get(v.severite.value, 0)
    return max(0, 100 - penalite)


def generer_resume(rapport: RapportAnalyse) -> str:
    # Génère une phrase de synthèse lisible à partir des résultats de l'analyse
    if rapport.nb_vulnerabilites == 0:
        return "Aucune vulnérabilité détectée. Le code semble sûr."

    texte = []
    texte.append(
        f"Analyse {rapport.mode} de {rapport.nom_fichier} "
        f"({rapport.langage.upper()}) : "
        f"{rapport.nb_vulnerabilites} problème(s) détecté(s)."
    )

    if rapport.nb_critique > 0:
        texte.append(
            f"{rapport.nb_critique} vulnérabilité(s) CRITIQUE(S) "
            f"à corriger immédiatement."
        )
    if rapport.nb_haute > 0:
        texte.append(
            f"{rapport.nb_haute} vulnérabilité(s) de sévérité HAUTE."
        )

    fns = rapport.analyse_structurelle.fonctions_dangereuses
    if fns:
        texte.append(f"Fonctions dangereuses détectées : {', '.join(fns)}.")

    if rapport.cve_correlees:
        nb = len(rapport.cve_correlees)
        texte.append(
            f"Mode avancé : {nb} CVE corrélée(s) depuis la base ANSSI."
        )

    return " ".join(texte)


@router.post("/", response_model=RapportAnalyse)
async def lancer_analyse(
    demande: DemandeAnalyse,
    db: AsyncSession = Depends(get_db)
):
    if not demande.code.strip():
        raise HTTPException(status_code=400, detail="Le code source est vide.")

    if len(demande.code) > 500_000:
        raise HTTPException(
            status_code=400,
            detail="Code trop long (limite : 500 000 caractères)."
        )

    rapport_id  = str(uuid.uuid4())
    nom_fichier = demande.nom_fichier or f"code.{demande.langage.value}"
    date        = datetime.utcnow()

    if demande.langage == Langage.C:
        vulns, structure = await analyser_c(demande.code)
    elif demande.langage == Langage.PYTHON:
        vulns, structure = await analyser_python(demande.code)
    else:
        raise HTTPException(status_code=400, detail="Langage non supporté.")

    cve_correlees = []
    if demande.mode == Mode.AVANCE:
        vulns, cve_correlees = corréler_cve(vulns, demande.langage.value)

    score = calculer_score(vulns)

    compteurs = {"critique": 0, "haute": 0, "moyenne": 0, "basse": 0}
    for v in vulns:
        if v.severite.value in compteurs:
            compteurs[v.severite.value] += 1

    rapport = RapportAnalyse(
        id                   = rapport_id,
        nom_fichier          = nom_fichier,
        langage              = demande.langage.value,
        mode                 = demande.mode.value,
        date_analyse         = date.strftime("%Y-%m-%d %H:%M:%S UTC"),
        duree_ms             = 0,
        score_securite       = score,
        nb_vulnerabilites    = len(vulns),
        nb_critique          = compteurs["critique"],
        nb_haute             = compteurs["haute"],
        nb_moyenne           = compteurs["moyenne"],
        nb_basse             = compteurs["basse"],
        vulnerabilites       = vulns,
        analyse_structurelle = structure,
        cve_correlees        = cve_correlees,
        resume               = "",
    )
    rapport = rapport.model_copy(update={"resume": generer_resume(rapport)})

    sauvegarder_json(rapport)
    sauvegarder_html(rapport)

    db.add(RapportDB(
        id            = rapport_id,
        nom_fichier   = nom_fichier,
        langage       = demande.langage.value,
        mode          = demande.mode.value,
        date_analyse  = date,
        score_securite    = score,
        nb_vulnerabilites = len(vulns),
        nb_critique   = compteurs["critique"],
        nb_haute      = compteurs["haute"],
        nb_moyenne    = compteurs["moyenne"],
        nb_basse      = compteurs["basse"],
        vulnerabilites_json       = json.dumps([v.model_dump() for v in vulns], default=str),
        analyse_structurelle_json = json.dumps(structure.model_dump()),
        cve_correlees_json        = json.dumps([c.model_dump() for c in cve_correlees], default=str),
        resume      = rapport.resume,
        code_source = demande.code[:10000],
    ))
    await db.commit()

    return rapport
