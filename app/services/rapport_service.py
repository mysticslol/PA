import json
import os
from app.models.schemas import RapportAnalyse

REPORTS_DIR = "./reports"


def couleur_score(score: int) -> str:
    # Retourne une couleur hex selon le score (vert, orange ou rouge)
    if score >= 80:
        return "#1D9E75"
    if score >= 50:
        return "#BA7517"
    return "#E24B4A"


def couleur_severite(severite: str) -> str:
    # Retourne la couleur associée à chaque niveau de sévérité
    couleurs = {
        "critique": "#E24B4A",
        "haute":    "#D85A30",
        "moyenne":  "#BA7517",
        "basse":    "#1D9E75",
        "info":     "#378ADD",
    }
    return couleurs.get(severite, "#888780")


def generer_html(rapport: RapportAnalyse) -> str:
    # Génère le contenu HTML du rapport pour l'export PDF
    score_color = couleur_score(rapport.score_securite)

    lignes_tableau = ""
    for v in rapport.vulnerabilites:
        couleur = couleur_severite(v.severite.value)
        ligne   = f"Ligne {v.ligne}" if v.ligne else "—"
        lignes_tableau += (
            f"<tr>"
            f"<td><span style='background:{couleur};color:#fff;"
            f"padding:2px 8px;border-radius:4px;font-size:12px'>"
            f"{v.severite.value.upper()}</span></td>"
            f"<td>{v.titre}</td>"
            f"<td>{ligne}</td>"
            f"<td style='font-size:12px'>{v.suggestion or '—'}</td>"
            f"</tr>"
        )

    html = (
        "<!DOCTYPE html><html lang='fr'><head><meta charset='UTF-8'>"
        f"<title>Rapport CodeShield — {rapport.nom_fichier}</title>"
        "<style>"
        "body{font-family:Arial,sans-serif;margin:40px;color:#1a1a1a}"
        "h1{border-bottom:2px solid #2563EB;padding-bottom:8px}"
        "h2{color:#2563EB;margin-top:28px}"
        "table{width:100%;border-collapse:collapse;margin-top:12px}"
        "th{background:#2563EB;color:white;padding:8px 12px;text-align:left;font-size:13px}"
        "td{padding:8px 12px;border-bottom:1px solid #e0e0e0;font-size:13px;vertical-align:top}"
        f".score{{font-size:52px;font-weight:bold;color:{score_color}}}"
        ".resume{background:#EFF6FF;border-left:4px solid #2563EB;"
        "padding:14px;border-radius:4px;margin:16px 0}"
        "</style></head><body>"
        "<h1>Rapport d'analyse — CodeShield</h1>"
        f"<p style='color:#666;font-size:13px'>"
        f"Fichier : <strong>{rapport.nom_fichier}</strong> | "
        f"Langage : <strong>{rapport.langage.upper()}</strong> | "
        f"Date : <strong>{rapport.date_analyse}</strong></p>"
        f"<div style='display:flex;align-items:center;gap:24px;margin:20px 0'>"
        f"<div><div style='font-size:13px;color:#666'>Score de sécurité</div>"
        f"<div class='score'>{rapport.score_securite}/100</div></div>"
        f"<div style='font-size:15px'>"
        f"<strong>{rapport.nb_vulnerabilites}</strong> problème(s) détecté(s)"
        f"</div></div>"
        f"<div class='resume'>{rapport.resume}</div>"
        "<h2>Corrections recommandées</h2>"
        "<table><thead>"
        "<tr><th>Sévérité</th><th>Problème</th><th>Localisation</th><th>Solution</th></tr>"
        f"</thead><tbody>{lignes_tableau}</tbody></table>"
        "</body></html>"
    )

    return html


def sauvegarder_json(rapport: RapportAnalyse) -> str:
    # Sauvegarde un rapport simplifié en JSON (score, résumé, corrections)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    chemin = os.path.join(REPORTS_DIR, f"{rapport.id}.json")

    contenu = {
        "fichier":       rapport.nom_fichier,
        "date":          rapport.date_analyse,
        "score":         rapport.score_securite,
        "nb_problemes":  rapport.nb_vulnerabilites,
        "resume":        rapport.resume,
        "corrections": [
            {
                "severite": v.severite if isinstance(v.severite, str) else v.severite.value,
                "ligne":    v.ligne,
                "probleme": v.titre,
                "solution": v.suggestion,
            }
            for v in rapport.vulnerabilites
        ],
    }

    with open(chemin, "w", encoding="utf-8") as f:
        json.dump(contenu, f, ensure_ascii=False, indent=2, default=str)

    return chemin


def sauvegarder_html(rapport: RapportAnalyse) -> str:
    # Sauvegarde le rapport au format HTML (utilisé comme source pour le PDF)
    os.makedirs(REPORTS_DIR, exist_ok=True)
    chemin = os.path.join(REPORTS_DIR, f"{rapport.id}.html")

    with open(chemin, "w", encoding="utf-8") as f:
        f.write(generer_html(rapport))

    return chemin


def generer_pdf(rapport_id: str) -> str:
    # Génère un PDF à partir du HTML sauvegardé via WeasyPrint
    from weasyprint import HTML

    chemin_html = os.path.join(REPORTS_DIR, f"{rapport_id}.html")
    chemin_pdf  = os.path.join(REPORTS_DIR, f"{rapport_id}.pdf")

    if not os.path.isfile(chemin_html):
        raise FileNotFoundError(f"Fichier HTML introuvable : {chemin_html}")

    HTML(filename=chemin_html).write_pdf(chemin_pdf)
    return chemin_pdf
