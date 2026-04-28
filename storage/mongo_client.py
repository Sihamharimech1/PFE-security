# storage/mongo_client.py

import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()


class MongoDBClient:
    def __init__(self):
        mongo_uri = os.getenv("MONGO_URI")
        db_name = os.getenv("MONGO_DB_NAME")

        self.client = MongoClient(mongo_uri)
        self.db = self.client[db_name]

    def get_collection(self, collection_name):
        return self.db[collection_name]