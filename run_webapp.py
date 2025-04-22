# run_webapp.py
import sys
import os

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.web.app import app

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)