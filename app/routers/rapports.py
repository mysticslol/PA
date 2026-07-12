import os
import json
import asyncio
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.database import get_db, RapportDB
from app.services.rapport_service import REPORTS_DIR, generer_pdf

router = APIRouter()


@router.get("/")
async def lister_rapports(
    limite: int = 20,
    db: AsyncSession = Depends(get_db)
):
    # Retourne les dernières analyses enregistrées en base
    resultat = await db.execute(
        select(RapportDB)
        .order_by(desc(RapportDB.date_analyse))
        .limit(limite)
    )
    rapports = resultat.scalars().all()

    return [
        {
            "id":               r.id,
            "nom_fichier":      r.nom_fichier,
            "langage":          r.langage,
            "mode":             r.mode,
            "date_analyse":     r.date_analyse.isoformat() if r.date_analyse else None,
            "score_securite":   r.score_securite,
            "nb_vulnerabilites": r.nb_vulnerabilites,
            "nb_critique":      r.nb_critique,
            "nb_haute":         r.nb_haute,
        }
        for r in rapports
    ]


@router.get("/{rapport_id}")
async def obtenir_rapport(
    rapport_id: str,
    db: AsyncSession = Depends(get_db)
):
    # Retourne le détail complet d'un rapport par son identifiant
    resultat = await db.execute(
        select(RapportDB).where(RapportDB.id == rapport_id)
    )
    r = resultat.scalar_one_or_none()

    if not r:
        raise HTTPException(status_code=404, detail="Rapport non trouvé.")

    return {
        "id":             r.id,
        "nom_fichier":    r.nom_fichier,
        "langage":        r.langage,
        "mode":           r.mode,
        "date_analyse":   r.date_analyse.isoformat() if r.date_analyse else None,
        "score_securite": r.score_securite,
        "nb_vulnerabilites": r.nb_vulnerabilites,
        "nb_critique":    r.nb_critique,
        "nb_haute":       r.nb_haute,
        "nb_moyenne":     r.nb_moyenne,
        "nb_basse":       r.nb_basse,
        "vulnerabilites":       json.loads(r.vulnerabilites_json or "[]"),
        "analyse_structurelle": json.loads(r.analyse_structurelle_json or "{}"),
        "cve_correlees":        json.loads(r.cve_correlees_json or "[]"),
        "resume":         r.resume,
    }


@router.get("/{rapport_id}/json")
async def telecharger_json(rapport_id: str):
    # Télécharge le rapport au format JSON simplifié
    chemin = os.path.join(REPORTS_DIR, f"{rapport_id}.json")

    if not os.path.isfile(chemin):
        raise HTTPException(status_code=404, detail="Fichier JSON introuvable.")

    return FileResponse(
        chemin,
        media_type="application/json",
        filename=f"rapport_{rapport_id}.json"
    )


@router.get("/{rapport_id}/pdf")
async def telecharger_pdf(rapport_id: str):
    # Génère le PDF si nécessaire puis le télécharge
    chemin_pdf = os.path.join(REPORTS_DIR, f"{rapport_id}.pdf")

    if not os.path.isfile(chemin_pdf):
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, generer_pdf, rapport_id)
        except FileNotFoundError:
            raise HTTPException(
                status_code=404,
                detail="Rapport source introuvable."
            )
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Erreur lors de la génération du PDF : {e}"
            )

    if not os.path.isfile(chemin_pdf):
        raise HTTPException(
            status_code=500,
            detail="Le PDF n'a pas pu être généré."
        )

    return FileResponse(
        chemin_pdf,
        media_type="application/pdf",
        filename=f"rapport_{rapport_id}.pdf"
    )


@router.delete("/{rapport_id}")
async def supprimer_rapport(
    rapport_id: str,
    db: AsyncSession = Depends(get_db)
):
    # Supprime le rapport de la base et les fichiers associés (json, html, pdf)
    resultat = await db.execute(
        select(RapportDB).where(RapportDB.id == rapport_id)
    )
    rapport = resultat.scalar_one_or_none()

    if not rapport:
        raise HTTPException(status_code=404, detail="Rapport non trouvé.")

    await db.delete(rapport)
    await db.commit()

    for ext in ("json", "html", "pdf"):
        chemin = os.path.join(REPORTS_DIR, f"{rapport_id}.{ext}")
        if os.path.isfile(chemin):
            os.unlink(chemin)

    return {"message": "Rapport supprimé."}
