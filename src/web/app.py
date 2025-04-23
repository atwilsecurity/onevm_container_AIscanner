from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import json
import os
import sys
from datetime import datetime

# Add the project root to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.scanner.vulnerability_scanner import VulnerabilityScanner
from src.scanner.report_generator import ReportGenerator
from src.mcp.client import MCPClient
from src.ai.claude_client import ClaudeAnalyzer
from src.kubernetes.scanner import KubernetesScanner
from src.kubernetes.client import KubernetesClient
from src.chatbot.bot import SecurityChatbot

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Required for flash messages
app.config['APP_NAME'] = 'OneVM'

# Initialize our clients
# Use test_development_key for development/testing purposes
api_key = os.environ.get("MCP_API_KEY", "test_development_key")
scanner = VulnerabilityScanner(mcp_url=os.environ.get("MCP_BASE_URL", "http://localhost:8000"), api_key=api_key)
report_generator = ReportGenerator(mcp_url=os.environ.get("MCP_BASE_URL", "http://localhost:8000"), api_key=api_key)
mcp_client = MCPClient(base_url=os.environ.get("MCP_BASE_URL", "http://localhost:8000"), api_key=api_key)

# Initialize Claude Analyzer (you'll need to set ANTHROPIC_API_KEY env variable)
try:
    anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_api_key:
        # Pass both API keys
        claude_analyzer = ClaudeAnalyzer(
            api_key=anthropic_api_key,
            mcp_url=os.environ.get("MCP_BASE_URL", "http://localhost:8000"),
            mcp_api_key=api_key  # MCP API key from earlier
        )
        claude_available = True
    else:
        print("Claude Analyzer not available: No API key provided")
        claude_available = False
except Exception as e:
    print(f"Claude Analyzer not available: {str(e)}")
    claude_available = False

# Initialize Kubernetes client and scanner
try:
    k8s_client = KubernetesClient()
    k8s_scanner = KubernetesScanner(
        mcp_url=os.environ.get("MCP_BASE_URL", "http://localhost:8000"),
        api_key=api_key
    ) if k8s_client.connected else None
    k8s_available = k8s_client.connected
    if not k8s_available:
        print("Kubernetes is not available: Not connected to a cluster")
except Exception as e:
    print(f"Kubernetes functionality not available: {str(e)}")
    k8s_available = False
    k8s_client = None
    k8s_scanner = None

try:
    chatbot = SecurityChatbot()
    chatbot_available = chatbot.available
except Exception as e:
    print(f"Chatbot not available: {str(e)}")
    chatbot_available = False
    chatbot = None    

@app.route('/')
def index():
    """Home page with form to scan images"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Handle image scan form submission"""
    image_name = request.form.get('image_name')
    
    if not image_name:
        flash('Please enter an image name', 'error')
        return redirect(url_for('index'))
    
    try:
        # Scan the image
        context_id = scanner.scan_image(image_name)
        
        # Redirect to results page
        return redirect(url_for('scan_results', context_id=context_id))
    
    except Exception as e:
        # Log the error
        app.logger.error(f"Error scanning image: {str(e)}")
        
        # Check if it's an MCP connection error
        if "Connection refused" in str(e):
            flash("Unable to connect to the MCP server. Please make sure it's running.", 'error')
        else:
            flash(f'Error scanning image: {str(e)}', 'error')
            
        return redirect(url_for('index'))

@app.route('/results/<context_id>')
def scan_results(context_id):
    """Display scan results for a given context ID"""
    try:
        # Get the scan results from MCP
        scan_result = mcp_client.get_context(context_id)
        
        return render_template('scan_results.html', 
                              context_id=context_id, 
                              scan_result=scan_result)
    
    except Exception as e:
        flash(f'Error retrieving scan results: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/report/<context_id>')
def generate_report(context_id):
    """Generate and display an HTML report"""
    try:
        # Generate a unique report filename
        report_filename = f'report_{context_id}.html'
        report_path = os.path.join(os.path.dirname(__file__), '../../reports', report_filename)
        
        # Ensure reports directory exists
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        # Check if we have an existing report generation process
        report_id = request.args.get('report_id')
        
        if not report_id:
            # Start a new report generation process in a separate thread
            import threading
            
            def generate_report_task():
                try:
                    report_generator.generate_html_report(context_id, report_path)
                except Exception as e:
                    app.logger.error(f"Error in report generation thread: {str(e)}")
            
            # Start the report generation in a background thread
            thread = threading.Thread(target=generate_report_task)
            thread.daemon = True
            thread.start()
            
            # Get the latest report generation context
            latest_reports = mcp_client.list_contexts(model_name="report_generator")
            for report in latest_reports:
                if report['data'].get('original_context_id') == context_id:
                    report_id = report['context_id']
                    break
            
            # If we couldn't find a report ID, redirect to results page with error
            if not report_id:
                flash("Could not track report generation progress", "error")
                return redirect(url_for('scan_results', context_id=context_id))
        
        # Get the report generation status
        report_status = mcp_client.get_context(report_id)
        
        # Check if the report is completed and exists
        if report_status['data']['status'] == "completed" and os.path.exists(report_path):
            # Read the report content
            with open(report_path, 'r') as f:
                report_content = f.read()
            
            return render_template('report.html', 
                                report_content=report_content,
                                report_status="completed")
        else:
            # Still generating, show progress
            return render_template('report.html',
                                report_status=report_status['data']['status'],
                                report_progress=report_status['data']['progress'],
                                report_message=report_status['data']['progress_message'],
                                report_id=report_id)
    
    except Exception as e:
        flash(f'Error generating report: {str(e)}', 'error')
        return redirect(url_for('scan_results', context_id=context_id))

@app.route('/analyze/<context_id>')
def analyze_vulnerabilities(context_id):
    """Use Claude to analyze vulnerabilities"""
    if not claude_available:
        flash('Claude Analyzer is not available. Please set up your API key.', 'error')
        return redirect(url_for('scan_results', context_id=context_id))
    
    try:
        # Get the analysis from Claude
        analysis_context_id = claude_analyzer.analyze_vulnerabilities(context_id)
        
        # Redirect to the analysis results
        return redirect(url_for('analysis_results', context_id=analysis_context_id))
    
    except Exception as e:
        flash(f'Error analyzing vulnerabilities: {str(e)}', 'error')
        return redirect(url_for('scan_results', context_id=context_id))

@app.route('/analysis/<context_id>')
def analysis_results(context_id):
    """Display Claude's analysis results"""
    try:
        # Get the analysis from MCP
        analysis_result = mcp_client.get_context(context_id)
        
        # Get the original scan context
        original_context_id = analysis_result['data'].get('original_context_id')
        original_scan = mcp_client.get_context(original_context_id) if original_context_id else None
        
        # Format the timestamp for better display
        if 'analyzed_at' in analysis_result['data']:
            try:
                # Convert ISO format to datetime object and format
                dt = datetime.fromisoformat(analysis_result['data']['analyzed_at'].replace('Z', '+00:00'))
                analysis_result['data']['analyzed_at'] = dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception as e:
                # If formatting fails, keep the original timestamp
                print(f"Error formatting timestamp: {str(e)}")
        
        return render_template('analysis.html', 
                              context_id=context_id, 
                              analysis=analysis_result,
                              original_scan=original_scan)
    
    except Exception as e:
        flash(f'Error retrieving analysis: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/kubernetes')
def kubernetes_dashboard():
    """Kubernetes scanning dashboard"""
    if not k8s_available:
        flash('Kubernetes functionality is not available. Please check your connection to a Kubernetes cluster.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Get namespaces
        namespaces = k8s_client.list_namespaces()
        
        return render_template('kubernetes.html', 
                              namespaces=namespaces)
    
    except Exception as e:
        flash(f'Error connecting to Kubernetes: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/kubernetes/namespace/<namespace>')
def kubernetes_namespace(namespace):
    """View Kubernetes namespace details"""
    if not k8s_available:
        flash('Kubernetes functionality is not available. Please check your connection to a Kubernetes cluster.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Get namespace resources
        pods = k8s_client.list_pods(namespace)
        deployments = k8s_client.list_deployments(namespace)
        images = k8s_client.get_all_images(namespace)
        
        return render_template('kubernetes_namespace.html',
                              namespace=namespace,
                              pods=pods,
                              deployments=deployments,
                              images=images)
    
    except Exception as e:
        flash(f'Error getting Kubernetes namespace details: {str(e)}', 'error')
        return redirect(url_for('kubernetes_dashboard'))

@app.route('/kubernetes/scan/<namespace>', methods=['POST'])
def kubernetes_scan(namespace):
    """Scan a Kubernetes namespace"""
    if not k8s_available:
        flash('Kubernetes functionality is not available. Please check your connection to a Kubernetes cluster.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Scan the namespace
        context_id = k8s_scanner.scan_namespace(namespace)
        
        # Redirect to results page
        return redirect(url_for('kubernetes_scan_results', context_id=context_id))
    
    except Exception as e:
        flash(f'Error scanning Kubernetes namespace: {str(e)}', 'error')
        return redirect(url_for('kubernetes_namespace', namespace=namespace))

@app.route('/kubernetes/results/<context_id>')
def kubernetes_scan_results(context_id):
    """Display Kubernetes scan results"""
    try:
        # Get the scan results from MCP
        scan_result = mcp_client.get_context(context_id)
        
        return render_template('kubernetes_scan_results.html',
                              context_id=context_id,
                              scan_result=scan_result)
    
    except Exception as e:
        flash(f'Error retrieving Kubernetes scan results: {str(e)}', 'error')
        return redirect(url_for('kubernetes_dashboard'))

@app.route('/api/contexts')
def list_contexts():
    """API endpoint to list available contexts"""
    # This would need to be implemented in your MCP client
    # For now, we'll return a simple message
    return jsonify({"error": "Not implemented yet"})

@app.route('/api/chatbot', methods=['POST'])
def chatbot_response():
    """API endpoint for chatbot responses"""
    if not chatbot_available:
        return jsonify({"error": "Chatbot is not available"}), 503
    
    try:
        data = request.json
        message = data.get('message', '')
        conversation_history = data.get('conversation', [])
        
        if not message:
            return jsonify({"error": "No message provided"}), 400
        
        response = chatbot.get_response(message, conversation_history)
        
        return jsonify({
            "response": response,
            "timestamp": datetime.now().isoformat()
        })
    
    except Exception as e:
        app.logger.error(f"Error in chatbot: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
