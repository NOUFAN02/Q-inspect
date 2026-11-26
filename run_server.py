import uvicorn

if __name__ == "__main__":
    print("=" * 65)
    print("  Q INSPECT - THREAT INTELLIGENCE PRE-SCANNER")
    print("=" * 65)
    print("  Web Interface : http://127.0.0.1:8000")
    print("  API Docs      : http://127.0.0.1:8000/docs")
    print("=" * 65)
    uvicorn.run("backend.api:app", host="127.0.0.1", port=8000, reload=True)
