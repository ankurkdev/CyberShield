from backend.database import engine


try:
    with engine.connect() as connection:
        print("SUCCESS: Connected to PostgreSQL!")
except Exception as error:
    print("ERROR: Could not connect to PostgreSQL.")
    print(error)