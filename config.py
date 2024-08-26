import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'secret_key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:////tmp/site.db'

    SQLALCHEMY_TRACK_MODIFICATIONS = False
