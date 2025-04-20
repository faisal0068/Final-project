#!/bin/bash

# Install dependencies from requirements.txt
pip install -r requirements.txt

# Perform any other build steps (e.g., migrations, static files collection)
flask db upgrade  # Uncomment if you're using Flask-Migrate

# Start the app (via gunicorn)
exec gunicorn --bind 0.0.0.0:$PORT app:app
