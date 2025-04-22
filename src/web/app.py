from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import json
import os
import sys

# Add the project root to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.scanner.vulnerability_scanner import VulnerabilityScanner
from src.scanner.report_generator import ReportGenerator
from src.mcp.client import MCPClient
from src.ai.claude_client import ClaudeAnalyzer
from src.kubernetes.scanner import KubernetesScanner
from src.kubernetes.client import KubernetesClient

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Required for flash messages
app.config['APP_NAME'] = 'OneVM'

# Initialize our clients
scanner = VulnerabilityScanner()
report_generator = ReportGenerator()
mcp_client = MCPClient()

# Initialize Claude Analyzer (you'll need to set ANTHROPIC_API_KEY env variable)
try:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        claude_analyzer = ClaudeAnalyzer(api_key=api_key)
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
    k8s_scanner = KubernetesScanner() if k8s_client.connected else None
    k8s_available = k8s_client.connected
    if not k8s_available:
        print("Kubernetes is not available: Not connected to a cluster")
except Exception as e:
    print(f"Kubernetes functionality not available: {str(e)}")
    k8s_available = False
    k8s_client = None
    k8s_scanner = None

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
        
        # Generate the report
        report_generator.generate_html_report(context_id, report_path)
        
        # Read the report content
        with open(report_path, 'r') as f:
            report_content = f.read()
        
        return render_template('report.html', report_content=report_content)
    
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
