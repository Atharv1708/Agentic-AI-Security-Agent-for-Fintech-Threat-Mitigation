import uvicorn
import os

if __name__ == "__main__":

    # Cloud platforms provide PORT via environment variable
    port = int(os.environ.get("PORT", 10000))

    print("=" * 60)
    print("   Starting AI Security Agent Server (Production Mode)")
    print("=" * 60)
    print(f"Listening on: 0.0.0.0:{port}")
    print("=" * 60)

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        reload=False  # ❌ NEVER use reload in production
    )
