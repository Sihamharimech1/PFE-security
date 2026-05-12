# storage/mongo_client.py

import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()


class MongoDBClient:
    def __init__(self):
        mongo_uri = os.getenv("MONGO_URI")
        db_name = os.getenv("MONGO_DB_NAME")

        if not mongo_uri:
            raise ValueError("MONGO_URI is not set")
        if not db_name:
            raise ValueError("MONGO_DB_NAME is not set")

        self.client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
        self.client.admin.command("ping")
        self.db = self.client[db_name]

    def get_collection(self, collection_name):
        return self.db[collection_name]