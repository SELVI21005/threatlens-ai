from app.database import Base, engine
from app.models import db_models

Base.metadata.create_all(bind=engine)
print("Tables created successfully!")