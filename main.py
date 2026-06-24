import os
from fastapi import FastAPI, Query
from dotenv import load_dotenv
from pymongo import MongoClient

# Load environment variables
load_dotenv()

app = FastAPI(title="OWASP MongoDB Security Lab")

# MongoDB connection
uri = os.getenv("MONGODB_URI")
db_name = os.getenv("MONGODB_DATABASE", "Jira")
col_name = os.getenv("MONGODB_COLLECTION", "page_index_summaries")

client = MongoClient(uri)
db = client[db_name]
col = db[col_name]

# Helper to serialize MongoDB documents (converting ObjectId to string)
def serialize_doc(doc):
    if not doc:
        return None
    doc["_id"] = str(doc["_id"])
    return doc

@app.get("/")
def read_root():
    return {"message": "Welcome to the OWASP MongoDB Security Lab FastAPI app!"}

@app.get("/pages")
def get_pages():
    """
    Safe endpoint: Queries documents where parentId is not null.
    """
    try:
        query = {"parentId": {"$ne": None}}
        cursor = col.find(query)
        pages = [serialize_doc(doc) for doc in cursor]
        return {"status": "success", "count": len(pages), "data": pages}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/search-safe")
def search_safe(title: str = Query(..., description="The title of the page to find")):
    """
    Safe endpoint: MongoDB queries with parameterized keys are safe from standard SQL-like injection
    because MongoDB treats the input strictly as a value/literal.
    """
    try:
        # Strict value mapping: title is treated strictly as a string literal
        query = {"title": title}
        cursor = col.find(query)
        results = [serialize_doc(doc) for doc in cursor]
        return {"status": "success", "count": len(results), "data": results}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/search-vulnerable-where")
def search_vulnerable_where(title: str = Query(..., description="The title of the page to find")):
    """
    Vulnerable endpoint: Uses MongoDB '$where' operator with dynamic JavaScript string evaluation.
    This allows a NoSQL injection leading to arbitrary JS execution on the MongoDB server.
    
    Example payload for title:
        x' || '1' == '1
    """
    try:
        # VULNERABLE: Direct string interpolation into JavaScript context
        js_query = {"$where": f"this.title == '{title}'"}
        cursor = col.find(js_query)
        results = [serialize_doc(doc) for doc in cursor]
        return {"status": "success", "count": len(results), "data": results}
    except Exception as e:
        return {"status": "error", "message": str(e)}
