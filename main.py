import os
import json
from fastapi import FastAPI, Query
from dotenv import load_dotenv
from pymongo import MongoClient

# Load environment variables
load_dotenv()

app = FastAPI(title="OWASP MongoDB Security Lab - Production App")

# MongoDB connection
uri = os.getenv("MONGODB_URI")
db_name = os.getenv("MONGODB_DATABASE", "Jira")
col_name = os.getenv("MONGODB_COLLECTION", "page_index_summaries")

client = MongoClient(uri)
db = client[db_name]
col = db[col_name]

def serialize_doc(doc):
    if not doc:
        return None
    doc["_id"] = str(doc["_id"])
    return doc

@app.get("/pages")
def get_pages(title: str = Query(None, description="Title of the page to query")):
    """
    Production Endpoint:
    If no title is provided, returns all pages with parentId not null.
    If a title is provided, searches for pages by title.
    
    WARNING: The search by title is intentionally implemented with a NoSQL Injection vulnerability.
    It attempts to parse the 'title' string as JSON. If the user passes a JSON query operator 
    (like {"$ne": "non-existent"}), it will execute as a query object instead of a literal string.
    """
    try:
        if title:
            # Try to parse the input as JSON to support advanced search syntax.
            # This is a classic NoSQL injection pattern where untrusted input changes the query structure.
            try:
                query_val = json.loads(title)
            except json.JSONDecodeError:
                query_val = title
                
            query = {"title": query_val}
        else:
            # Default query: parentId not null
            query = {"parentId": {"$ne": None}}
            
        cursor = col.find(query)
        pages = [serialize_doc(doc) for doc in cursor]
        return {"status": "success", "count": len(pages), "data": pages}
    except Exception as e:
        return {"status": "error", "message": str(e)}
