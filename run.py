import uvicorn
import os

if __name__ == "__main__":
    # Get the directory of the run.py script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Construct the path to the app module
    app_module = "app.main:app"

    print("=" * 60)
    print("   Starting AI Security Agent Server (Reload Mode)")
    print("=" * 60)
    print(f"Loading ASGI app from: {app_module}")
    print(f"Dashboard URL: http://localhost:8000")
    print("=" * 60)

    # Run Uvicorn pointing to the app object inside the 'app' package
    uvicorn.run(
        app_module,
        host="0.0.0.0",
        port=8000,
        reload=True,  # <-- CHANGED THIS TO TRUE
        # Specify the app directory to watch
        reload_dirs=[os.path.join(script_dir, "app")]
    )
