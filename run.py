"""
Server startup script for the moku-analyzer FastAPI application.

This script starts the Uvicorn ASGI server to run the FastAPI application.
It configures the server to listen on localhost port 8080 without auto-reload
to prevent job store data from being lost on code changes.
"""

import uvicorn

if __name__ == "__main__":
    # Start the Uvicorn server with the FastAPI app
    # reload=False prevents the server from restarting on code changes,
    # which would clear the in-memory job store
    uvicorn.run("main:app", host="127.0.0.1", port=8080, reload=False)