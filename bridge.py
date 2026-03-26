import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from agents.sentinel.scanner import neuro_scan, __version__

app = FastAPI()

# Enable communication between React (5173), Java (8080), and Python (8000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/scan")
def run_scan(target: str = "README.md"):
    # Fix: Use absolute path for reliability
    path = os.path.abspath(target)
    
    if not os.path.exists(path):
        return {"status": "error", "message": f"File {target} not found at {path}"}

    result = neuro_scan(path)
    
    return {
        "version": __version__,
        "target": path,
        "result": result,
        "status": "success"
    }
@app.get("/api")
def get_api_info():
    return {"message": "Welcome to the NEURO-SP API"}
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)