from app import db

db.drop_all()  # Drop all tables
db.create_all()  # Recreate tables
