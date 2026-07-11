from pydantic import BaseModel
from typing import Optional, List
from enum import Enum


class Langage(str, Enum):
    C      = "c"
    PYTHON = "python"


class Mode(str, Enum):
    CLASSIQUE = "classique"
    AVANCE    = "avance"


class Severite(str, Enum):
    CRITIQUE = "critique"
    HAUTE    = "haute"
    MOYENNE  = "moyenne"
    BASSE    = "basse"
    INFO     = "info"


class DemandeAnalyse(BaseModel):
    code:        str
    langage:     Langage
    mode:        Mode = Mode.CLASSIQUE
    nom_fichier: Optional[str] = None


class Vulnerabilite(BaseModel):
    id:          str
    titre:       str
    description: str
    severite:    Severite
    ligne:       Optional[int]   = None
    colonne:     Optional[int]   = None
    outil:       str
    categorie:   str
    suggestion:  Optional[str]   = None
    cve_ids:     Optional[List[str]] = []
    cvss_score:  Optional[float] = None


class AnalyseStructurelle(BaseModel):
    nb_lignes:            int
    nb_fonctions:         int
    nb_commentaires:      int
    complexite_estimee:   str
    imports_detectes:     List[str]
    fonctions_dangereuses: List[str]


class ResultatCVE(BaseModel):
    cve_id:            str
    description:       str
    cvss_score:        Optional[float]
    severite:          str
    produits_affectes: List[str]
    references:        List[str]


class RapportAnalyse(BaseModel):
    id:               str
    nom_fichier:      str
    langage:          str
    mode:             str
    date_analyse:     str
    duree_ms:         int
    score_securite:   int
    nb_vulnerabilites: int
    nb_critique:      int
    nb_haute:         int
    nb_moyenne:       int
    nb_basse:         int
    vulnerabilites:        List[Vulnerabilite]
    analyse_structurelle:  AnalyseStructurelle
    cve_correlees:         Optional[List[ResultatCVE]] = []
    resume:           str
