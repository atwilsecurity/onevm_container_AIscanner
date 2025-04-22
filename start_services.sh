#!/bin/bash

# Start the MCP server in the background
echo "Starting MCP server..."
python -m src.mcp.server &

# Store the PID of the MCP server
MCP_PID=$!

# Wait for MCP server to start
echo "Waiting for MCP server to start..."
sleep 3

# Start the web app
echo "Starting web application..."
python run_webapp.py

# When the web app exits, kill the MCP server
echo "Shutting down MCP server..."
kill $MCP_PID