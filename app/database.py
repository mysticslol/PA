from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import Column, String, Integer, Text, DateTime
from datetime import datetime

DATABASE_URL = "sqlite+aiosqlite:///./data/analyseur.db"

engine = create_async_engine(DATABASE_URL, echo=False)
Base = declarative_base()
SessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class RapportDB(Base):
    __tablename__ = "rapports"

    id              = Column(String,   primary_key=True)
    nom_fichier     = Column(String,   nullable=False)
    langage         = Column(String,   nullable=False)
    mode            = Column(String,   nullable=False)
    date_analyse    = Column(DateTime, default=datetime.utcnow)
    score_securite  = Column(Integer,  default=100)
    nb_vulnerabilites = Column(Integer, default=0)
    nb_critique     = Column(Integer,  default=0)
    nb_haute        = Column(Integer,  default=0)
    nb_moyenne      = Column(Integer,  default=0)
    nb_basse        = Column(Integer,  default=0)
    vulnerabilites_json       = Column(Text, default="[]")
    analyse_structurelle_json = Column(Text, default="{}")
    cve_correlees_json        = Column(Text, default="[]")
    resume      = Column(Text, default="")
    code_source = Column(Text, default="")


async def init_db():
    # Crée les tables si elles n'existent pas encore
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    # Fournit une session à chaque requête et la ferme automatiquement après
    async with SessionLocal() as session:
        yield session
