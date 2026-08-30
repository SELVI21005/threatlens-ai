from fastapi import FastAPI

from app.database import Base, engine
from app.models import db_models
from app.routes import auth_routes

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.include_router(auth_routes.router)


@app.get("/")
def read_root():
    return {"status": "ThreatLens AI backend is running"}