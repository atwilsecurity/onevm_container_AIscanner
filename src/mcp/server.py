# src/mcp/server.py
import json
import logging
from typing import Dict, Any, Optional
import uuid
from datetime import datetime

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Model Context Protocol Server")

# In-memory context store (replace with database in production)
context_store: Dict[str, Dict[str, Any]] = {}

class Context(BaseModel):
    context_id: Optional[str] = None
    model_name: str
    data: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = None

@app.post("/context")
async def create_context(context: Context):
    # Generate a context ID if not provided
    if not context.context_id:
        context.context_id = f"ctx-{uuid.uuid4()}"
    
    if context.context_id in context_store:
        raise HTTPException(status_code=409, detail="Context already exists")
    
    context_store[context.context_id] = {
        "model_name": context.model_name,
        "data": context.data,
        "metadata": context.metadata or {},
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }
    
    logger.info(f"Created context {context.context_id} for model {context.model_name}")
    return {"status": "created", "context_id": context.context_id}

@app.get("/context/{context_id}")
async def get_context(context_id: str):
    if context_id not in context_store:
        raise HTTPException(status_code=404, detail="Context not found")
    
    return context_store[context_id]

@app.put("/context/{context_id}")
async def update_context(context_id: str, context_update: Context):
    if context_id not in context_store:
        raise HTTPException(status_code=404, detail="Context not found")
    
    # Update the context while preserving created_at
    created_at = context_store[context_id]["created_at"]
    
    context_store[context_id] = {
        "model_name": context_update.model_name,
        "data": context_update.data,
        "metadata": context_update.metadata or {},
        "created_at": created_at,
        "updated_at": datetime.now().isoformat()
    }
    
    logger.info(f"Updated context {context_id} for model {context_update.model_name}")
    return {"status": "updated", "context_id": context_id}

@app.delete("/context/{context_id}")
async def delete_context(context_id: str):
    if context_id not in context_store:
        raise HTTPException(status_code=404, detail="Context not found")
    
    del context_store[context_id]
    logger.info(f"Deleted context {context_id}")
    return {"status": "deleted", "context_id": context_id}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)