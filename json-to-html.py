#!/usr/bin/env python3

import json
import requests
import subprocess
import sys
import os
from datetime import datetime
import argparse
from collections import Counter

def run_trivy_scan(image_name, output_file):
    """Run Trivy scan and generate JSON report"""
    print(f"🔍 Scanning {image_name} with Trivy...")
    
    cmd = [
        "trivy", "image", 
        "--format", "json", 
        "--output", output_file,
        image_name
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"✅ Trivy scan completed: {output_file}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Trivy scan failed: {e}")
        return False

def summarize_trivy_data(json_data):
    """Summarize Trivy JSON data to reduce payload size"""
    summary = {
        "scan_info": {
            "image_name": "",
            "scan_date": datetime.now().isoformat(),
            "total_vulnerabilities": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        },
        "vulnerabilities": [],
        "top_packages": [],
        "recommendations": []
    }
    
    all_vulns = []
    package_counts = Counter()
    
    # Process results
    if isinstance(json_data, dict) and "Results" in json_data:
        results = json_data["Results"]
        if results and len(results) > 0:
            # Get image name from first result
            summary["scan_info"]["image_name"] = results[0].get("Target", "Unknown")
            
            # Process vulnerabilities
            for result in results:
                if "Vulnerabilities" in result and result["Vulnerabilities"]:
                    for vuln in result["Vulnerabilities"]:
                        severity = vuln.get("Severity", "UNKNOWN")
                        package_name = vuln.get("PkgName", "unknown")
                        
                        # Count vulnerabilities by severity
                        summary["scan_info"]["severity_counts"][severity] += 1
                        summary["scan_info"]["total_vulnerabilities"] += 1
                        
                        # Count packages
                        package_counts[package_name] += 1
                        
                        # Store vulnerability details (limit to important ones)
                        if severity in ["CRITICAL", "HIGH"] or len(all_vulns) < 50:
                            vuln_detail = {
                                "VulnerabilityID": vuln.get("VulnerabilityID", ""),
                                "PkgName": package_name,
                                "InstalledVersion": vuln.get("InstalledVersion", ""),
                                "FixedVersion": vuln.get("FixedVersion", ""),
                                "Severity": severity,
                                "Title": vuln.get("Title", "")[:100],  # Truncate long titles
                                "Description": vuln.get("Description", "")[:200]  # Truncate long descriptions
                            }
                            all_vulns.append(vuln_detail)
    
    # Sort vulnerabilities by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    all_vulns.sort(key=lambda x: severity_order.get(x["Severity"], 4))
    
    summary["vulnerabilities"] = all_vulns[:100]  # Limit to top 100 vulnerabilities
    summary["top_packages"] = [{"package": pkg, "vuln_count": count} 
                              for pkg, count in package_counts.most_common(20)]
    
    return summary

def send_to_ollama(summary_data, model="mistral", ollama_url="http://localhost:11434"):
    """Send summarized data to Ollama and get HTML response"""
    print(f"🤖 Sending summarized data to Ollama ({model})...")
    
    # Create a more focused prompt
    prompt = f"""Create a professional HTML security report for this Docker image vulnerability scan.

SCAN SUMMARY:
- Image: {summary_data['scan_info']['image_name']}
- Total Vulnerabilities: {summary_data['scan_info']['total_vulnerabilities']}
- Critical: {summary_data['scan_info']['severity_counts']['CRITICAL']}
- High: {summary_data['scan_info']['severity_counts']['HIGH']}
- Medium: {summary_data['scan_info']['severity_counts']['MEDIUM']}
- Low: {summary_data['scan_info']['severity_counts']['LOW']}

TOP VULNERABLE PACKAGES:
{json.dumps(summary_data['top_packages'][:10], indent=2)}

CRITICAL & HIGH VULNERABILITIES:
{json.dumps([v for v in summary_data['vulnerabilities'] if v['Severity'] in ['CRITICAL', 'HIGH']][:20], indent=2)}

Create a complete HTML document with:
1. Modern CSS styling with colors (red for critical, orange for high, etc.)
2. Executive summary with key statistics
3. Severity distribution chart using CSS bars
4. Top vulnerable packages table
5. Critical/High vulnerabilities details table
6. Security recommendations
7. Professional layout with headers and sections

Generate only the HTML code, no explanations."""

    # Prepare request for Ollama with shorter timeout
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "top_p": 0.9,
            "num_predict": 3000  # Reduced from 4000
        }
    }
    
    try:
        print("⏳ Waiting for Ollama response (this may take 1-2 minutes)...")
        response = requests.post(
            f"{ollama_url}/api/generate",
            json=payload,
            timeout=180  # Reduced to 3 minutes
        )
        response.raise_for_status()
        
        result = response.json()
        html_content = result.get('response', '')
        
        if html_content:
            print("✅ HTML report generated by Ollama")
            return html_content
        else:
            print("❌ Empty response from Ollama")
            return None
            
    except requests.exceptions.Timeout:
        print("❌ Request timed out. Try using a smaller/faster model.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"❌ Error communicating with Ollama: {e}")
        return None

def create_fallback_html(summary_data):
    """Create a simple HTML report if Ollama fails"""
    html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {summary_data['scan_info']['image_name']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat {{ text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px; }}
        .critical {{ color: #dc3545; font-weight: bold; }}
        .high {{ color: #fd7e14; font-weight: bold; }}
        .medium {{ color: #ffc107; font-weight: bold; }}
        .low {{ color: #28a745; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .severity-critical {{ background-color: #f8d7da; }}
        .severity-high {{ background-color: #fff3cd; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Vulnerability Report</h1>
            <p><strong>Image:</strong> {summary_data['scan_info']['image_name']}</p>
            <p><strong>Scan Date:</strong> {summary_data['scan_info']['scan_date']}</p>
        </div>
        
        <div class="stats">
            <div class="stat">
                <h3>Total Vulnerabilities</h3>
                <div style="font-size: 24px; font-weight: bold;">{summary_data['scan_info']['total_vulnerabilities']}</div>
            </div>
            <div class="stat critical">
                <h3>Critical</h3>
                <div style="font-size: 24px;">{summary_data['scan_info']['severity_counts']['CRITICAL']}</div>
            </div>
            <div class="stat high">
                <h3>High</h3>
                <div style="font-size: 24px;">{summary_data['scan_info']['severity_counts']['HIGH']}</div>
            </div>
            <div class="stat medium">
                <h3>Medium</h3>
                <div style="font-size: 24px;">{summary_data['scan_info']['severity_counts']['MEDIUM']}</div>
            </div>
            <div class="stat low">
                <h3>Low</h3>
                <div style="font-size: 24px;">{summary_data['scan_info']['severity_counts']['LOW']}</div>
            </div>
        </div>
        
        <h2>🔴 Critical & High Severity Vulnerabilities</h2>
        <table>
            <tr>
                <th>CVE ID</th>
                <th>Package</th>
                <th>Severity</th>
                <th>Installed Version</th>
                <th>Fixed Version</th>
                <th>Title</th>
            </tr>
"""
    
    # Add vulnerability rows
    for vuln in summary_data['vulnerabilities']:
        if vuln['Severity'] in ['CRITICAL', 'HIGH']:
            severity_class = f"severity-{vuln['Severity'].lower()}"
            html_template += f"""
            <tr class="{severity_class}">
                <td>{vuln['VulnerabilityID']}</td>
                <td>{vuln['PkgName']}</td>
                <td class="{vuln['Severity'].lower()}">{vuln['Severity']}</td>
                <td>{vuln['InstalledVersion']}</td>
                <td>{vuln.get('FixedVersion', 'N/A')}</td>
                <td>{vuln['Title']}</td>
            </tr>
"""
    
    html_template += """
        </table>
        
        <h2>📦 Most Vulnerable Packages</h2>
        <table>
            <tr>
                <th>Package Name</th>
                <th>Vulnerability Count</th>
            </tr>
"""
    
    # Add package rows
    for pkg in summary_data['top_packages'][:10]:
        html_template += f"""
            <tr>
                <td>{pkg['package']}</td>
                <td>{pkg['vuln_count']}</td>
            </tr>
"""
    
    html_template += """
        </table>
        
        <h2>💡 Recommendations</h2>
        <ul>
            <li>🔄 Update base image to the latest version</li>
            <li>📦 Update vulnerable packages to their fixed versions</li>
            <li>🔍 Implement regular vulnerability scanning in CI/CD pipeline</li>
            <li>🛡️ Use minimal base images (like Alpine) to reduce attack surface</li>
            <li>🚫 Remove unnecessary packages and dependencies</li>
        </ul>
    </div>
</body>
</html>
"""
    
    return html_template

def save_html_report(html_content, output_file):
    """Save HTML content to file"""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"✅ HTML report saved: {output_file}")
        return True
    except Exception as e:
        print(f"❌ Error saving HTML report: {e}")
        return False

def open_report(html_file):
    """Open HTML report in default browser"""
    try:
        if sys.platform.startswith('linux'):
            subprocess.run(['xdg-open', html_file])
        elif sys.platform.startswith('darwin'):
            subprocess.run(['open', html_file])
        elif sys.platform.startswith('win'):
            os.startfile(html_file)
        else:
            print(f"Please open {html_file} in your web browser")
    except Exception as e:
        print(f"Could not auto-open browser: {e}")
        print(f"Please manually open: {html_file}")

def main():
    parser = argparse.ArgumentParser(description='Generate HTML security report from Trivy JSON using Ollama')
    parser.add_argument('image', help='Docker image name to scan')
    parser.add_argument('--model', default='mistral', help='Ollama model name (default: mistral)')
    parser.add_argument('--ollama-url', default='http://localhost:11434', help='Ollama API URL')
    parser.add_argument('--output-dir', default='./reports', help='Output directory for reports')
    parser.add_argument('--no-open', action='store_true', help='Do not auto-open the HTML report')
    parser.add_argument('--fallback-only', action='store_true', help='Skip Ollama and use fallback HTML generator')
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Generate timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # File paths
    json_file = os.path.join(args.output_dir, f"trivy_report_{timestamp}.json")
    html_file = os.path.join(args.output_dir, f"security_report_{timestamp}.html")
    summary_file = os.path.join(args.output_dir, f"summary_{timestamp}.json")
    
    print("🛡️  Optimized Trivy to Ollama HTML Report Generator")
    print(f"📊 Image: {args.image}")
    print(f"🤖 Model: {args.model}")
    print(f"📁 Output: {args.output_dir}")
    print("-" * 50)
    
    # Step 1: Run Trivy scan
    if not run_trivy_scan(args.image, json_file):
        sys.exit(1)
    
    # Step 2: Load and summarize JSON data
    try:
        with open(json_file, 'r') as f:
            json_data = json.load(f)
        print("✅ JSON data loaded successfully")
        
        summary_data = summarize_trivy_data(json_data)
        print(f"✅ Data summarized: {summary_data['scan_info']['total_vulnerabilities']} total vulnerabilities")
        
        # Save summary for debugging
        with open(summary_file, 'w') as f:
            json.dump(summary_data, f, indent=2)
        print(f"✅ Summary saved: {summary_file}")
        
    except Exception as e:
        print(f"❌ Error loading/summarizing JSON: {e}")
        sys.exit(1)
    
    # Step 3: Generate HTML report
    html_content = None
    
    if not args.fallback_only:
        # Try Ollama first
        html_content = send_to_ollama(summary_data, args.model, args.ollama_url)
    
    if not html_content:
        # Use fallback HTML generator
        print("🔄 Using fallback HTML generator...")
        html_content = create_fallback_html(summary_data)
    
    # Step 4: Save HTML report
    if not save_html_report(html_content, html_file):
        sys.exit(1)
    
    # Step 5: Open report
    if not args.no_open:
        open_report(html_file)
    
    print("\n🎉 Report generation completed successfully!")
    print(f"📄 JSON Report: {json_file}")
    print(f"📊 Summary: {summary_file}")
    print(f"🌐 HTML Report: {html_file}")

if __name__ == "__main__":
    main()
