from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"status": "ThreatLens AI backend is running"}