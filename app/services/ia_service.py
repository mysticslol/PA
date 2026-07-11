# =============================================================
# ia_service.py — Infrastructure d'analyse par IA
# =============================================================
# Ce module prépare la connexion entre CodeShield et un modèle
# de langage (LLM) open source tournant localement via Ollama.
#
# Modèle prévu : Mistral 7B (via Ollama sur la même VM)
# Statut : Infrastructure prête — modèle désactivé
# Raison : Les requêtes prenaient 3+ minutes sur la configuration
#          actuelle. Nécessite un serveur avec GPU dédié.
# =============================================================

import httpx
from typing import Optional

# URL du serveur Ollama (tourne sur la même VM que CodeShield)
OLLAMA_URL = "http://localhost:11434"

# Modèle à utiliser — Mistral 7B pour l'analyse de sécurité
MODELE = "mistral"

# Temps maximum d'attente pour une réponse du modèle (en secondes)
TIMEOUT = 120

# Prompt système envoyé au modèle avant chaque analyse
PROMPT_SYSTEME = """Tu es un expert en sécurité informatique spécialisé dans l'analyse
de code source. Ton rôle est d'analyser le code fourni, d'identifier les vulnérabilités
de sécurité, et d'expliquer clairement les risques en français. Sois précis et concis."""


async def analyser_avec_ia(code: str, langage: str) -> Optional[str]:
    """
    Envoie le code au modèle IA local et retourne son analyse.

    Le modèle reçoit le code source et génère une explication
    en langage naturel des vulnérabilités détectées.

    Args:
        code: Le code source à analyser
        langage: Le langage de programmation (c ou python)

    Returns:
        L'analyse textuelle du modèle, ou None si indisponible
    """

    # Prompt utilisateur envoyé au modèle
    prompt = f"""Analyse ce code {langage.upper()} et identifie les vulnérabilités de sécurité.
Pour chaque problème trouvé, explique : le risque, la ligne concernée, et comment le corriger.

```{langage}
{code}
```"""

    # === MODÈLE DÉSACTIVÉ ===
    # Le code ci-dessous est fonctionnel mais le modèle n'est pas lancé
    # car les requêtes prenaient trop de temps sur cette configuration.
    # Sur un serveur avec GPU, décommenter le bloc suivant :

    # try:
    #     async with httpx.AsyncClient(timeout=TIMEOUT) as client:
    #         response = await client.post(
    #             f"{OLLAMA_URL}/api/generate",
    #             json={
    #                 "model": MODELE,
    #                 "prompt": prompt,
    #                 "system": PROMPT_SYSTEME,
    #                 "stream": False,
    #             }
    #         )
    #         data = response.json()
    #         return data.get("response", "").strip()
    # except (httpx.ConnectError, httpx.TimeoutException):
    #     return None

    return None


async def verifier_disponibilite() -> bool:
    """
    Vérifie si le serveur Ollama est accessible et le modèle chargé.

    Returns:
        True si Ollama tourne et le modèle est disponible, False sinon
    """

    # === VÉRIFICATION DÉSACTIVÉE ===
    # try:
    #     async with httpx.AsyncClient(timeout=5) as client:
    #         response = await client.get(f"{OLLAMA_URL}/api/tags")
    #         modeles = response.json().get("models", [])
    #         return any(m.get("name", "").startswith(MODELE) for m in modeles)
    # except (httpx.ConnectError, httpx.TimeoutException):
    #     return False

    return False
