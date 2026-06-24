import os
from dotenv import load_dotenv
from pymongo import MongoClient

def main():
    # Load environment variables from .env file
    load_dotenv()
    
    uri = os.getenv("MONGODB_URI")
    db_name = os.getenv("MONGODB_DATABASE")
    col_name = os.getenv("MONGODB_COLLECTION")
    
    if not all([uri, db_name, col_name]):
        print("Error: Missing database configuration in environment variables.")
        print("Please check your .env file.")
        return
        
    print(f"Connecting to MongoDB database: {db_name}...")
    try:
        client = MongoClient(uri)
        db = client[db_name]
        col = db[col_name]
        
        # Query to find documents where 'parentId' is not null/None
        query = {"parentId": {"$ne": None}}
        
        # Count documents matching the query
        count = col.count_documents(query)
        print(f"Found {count} documents where 'parentId' is not null.\n")
        
        if count > 0:
            print("Matching Documents:")
            print("=" * 60)
            # Retrieve documents
            documents = col.find(query)
            for doc in documents:
                print(f"pageId:   {doc.get('pageId')}")
                print(f"Title:    {doc.get('title')}")
                print(f"parentId: {doc.get('parentId')}")
                print("-" * 60)
        else:
            print("No documents found with a non-null 'parentId'.")
            
    except Exception as e:
        print(f"An error occurred while connecting or querying: {e}")

if __name__ == "__main__":
    main()
