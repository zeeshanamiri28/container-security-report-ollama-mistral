#!/usr/bin/env python3

import json
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

def analyze_trivy_data(json_data):
    """Analyze Trivy JSON data and extract key information"""
    analysis = {
        "scan_info": {
            "image_name": "Unknown",
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_vulnerabilities": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        },
        "vulnerabilities": [],
        "packages": {},
        "summary": {}
    }
    
    all_vulns = []
    package_vuln_count = Counter()
    
    # Process results
    if isinstance(json_data, dict) and "Results" in json_data:
        results = json_data["Results"]
        if results and len(results) > 0:
            # Get image name
            analysis["scan_info"]["image_name"] = results[0].get("Target", "Unknown")
            
            # Process each result
            for result in results:
                target = result.get("Target", "")
                result_type = result.get("Type", "")
                
                if "Vulnerabilities" in result and result["Vulnerabilities"]:
                    for vuln in result["Vulnerabilities"]:
                        severity = vuln.get("Severity", "UNKNOWN")
                        package_name = vuln.get("PkgName", "unknown")
                        vuln_id = vuln.get("VulnerabilityID", "")
                        
                        # Count by severity
                        if severity in analysis["scan_info"]["severity_counts"]:
                            analysis["scan_info"]["severity_counts"][severity] += 1
                        analysis["scan_info"]["total_vulnerabilities"] += 1
                        
                        # Count by package
                        package_vuln_count[package_name] += 1
                        
                        # Store vulnerability details
                        vuln_detail = {
                            "id": vuln_id,
                            "package": package_name,
                            "installed_version": vuln.get("InstalledVersion", ""),
                            "fixed_version": vuln.get("FixedVersion", ""),
                            "severity": severity,
                            "title": vuln.get("Title", "")[:150],
                            "description": vuln.get("Description", "")[:300],
                            "references": vuln.get("References", [])[:3],  # Limit references
                            "target": target,
                            "type": result_type
                        }
                        all_vulns.append(vuln_detail)
    
    # Sort vulnerabilities by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    all_vulns.sort(key=lambda x: severity_order.get(x["severity"], 4))
    
    analysis["vulnerabilities"] = all_vulns
    analysis["packages"] = dict(package_vuln_count.most_common(20))
    
    # Create summary
    analysis["summary"] = {
        "risk_level": "HIGH" if analysis["scan_info"]["severity_counts"]["CRITICAL"] > 0 else
                     "MEDIUM" if analysis["scan_info"]["severity_counts"]["HIGH"] > 0 else "LOW",
        "most_vulnerable_packages": list(package_vuln_count.most_common(5)),
        "critical_high_count": analysis["scan_info"]["severity_counts"]["CRITICAL"] + analysis["scan_info"]["severity_counts"]["HIGH"]
    }
    
    return analysis

def generate_html_report(analysis):
    """Generate a comprehensive HTML security report"""
    
    # Color scheme based on severity
    severity_colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14", 
        "MEDIUM": "#ffc107",
        "LOW": "#28a745",
        "UNKNOWN": "#6c757d"
    }
    
    # Get top vulnerabilities for each severity
    critical_vulns = [v for v in analysis["vulnerabilities"] if v["severity"] == "CRITICAL"][:10]
    high_vulns = [v for v in analysis["vulnerabilities"] if v["severity"] == "HIGH"][:10]
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {analysis['scan_info']['image_name']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .risk-level {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            margin-top: 10px;
        }}
        
        .risk-high {{ background-color: #dc3545; color: white; }}
        .risk-medium {{ background-color: #ffc107; color: #212529; }}
        .risk-low {{ background-color: #28a745; color: white; }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 4px solid;
        }}
        
        .stat-card.total {{ border-left-color: #007bff; }}
        .stat-card.critical {{ border-left-color: #dc3545; }}
        .stat-card.high {{ border-left-color: #fd7e14; }}
        .stat-card.medium {{ border-left-color: #ffc107; }}
        .stat-card.low {{ border-left-color: #28a745; }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .section {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 25px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .section h2 {{
            color: #495057;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 10px;
        }}
        
        .vulnerability-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        
        .vulnerability-table th,
        .vulnerability-table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }}
        
        .vulnerability-table th {{
            background-color: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }}
        
        .vulnerability-table tr:hover {{
            background-color: #f8f9fa;
        }}
        
        .severity-badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
            text-transform: uppercase;
        }}
        
        .severity-critical {{ background-color: #dc3545; }}
        .severity-high {{ background-color: #fd7e14; }}
        .severity-medium {{ background-color: #ffc107; color: #212529; }}
        .severity-low {{ background-color: #28a745; }}
        .severity-unknown {{ background-color: #6c757d; }}
        
        .package-list {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        
        .package-item {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #007bff;
        }}
        
        .package-name {{
            font-weight: bold;
            color: #495057;
        }}
        
        .package-count {{
            color: #6c757d;
            font-size: 0.9em;
        }}
        
        .recommendations {{
            background: #e7f3ff;
            border: 1px solid #b3d9ff;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }}
        
        .recommendations h3 {{
            color: #0056b3;
            margin-bottom: 15px;
        }}
        
        .recommendations ul {{
            list-style-type: none;
            padding-left: 0;
        }}
        
        .recommendations li {{
            padding: 8px 0;
            border-bottom: 1px solid #cce7ff;
        }}
        
        .recommendations li:before {{
            content: "💡 ";
            margin-right: 8px;
        }}
        
        .footer {{
            text-align: center;
            color: #6c757d;
            margin-top: 30px;
            padding: 20px;
            background: white;
            border-radius: 10px;
        }}
        
        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            
            .package-list {{
                grid-template-columns: 1fr;
            }}
            
            .vulnerability-table {{
                font-size: 0.9em;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🛡️ Security Vulnerability Report</h1>
            <div class="subtitle">
                <strong>Image:</strong> {analysis['scan_info']['image_name']}<br>
                <strong>Scan Date:</strong> {analysis['scan_info']['scan_date']}<br>
                <span class="risk-level risk-{analysis['summary']['risk_level'].lower()}">
                    Risk Level: {analysis['summary']['risk_level']}
                </span>
            </div>
        </div>
        
        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card total">
                <div class="stat-number">{analysis['scan_info']['total_vulnerabilities']}</div>
                <div class="stat-label">Total Vulnerabilities</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-number">{analysis['scan_info']['severity_counts']['CRITICAL']}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">{analysis['scan_info']['severity_counts']['HIGH']}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number">{analysis['scan_info']['severity_counts']['MEDIUM']}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number">{analysis['scan_info']['severity_counts']['LOW']}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>"""

    # Critical Vulnerabilities Section
    if critical_vulns:
        html += f"""
        <div class="section">
            <h2>🚨 Critical Vulnerabilities</h2>
            <p>These vulnerabilities require immediate attention and should be fixed as soon as possible.</p>
            <table class="vulnerability-table">
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>Package</th>
                        <th>Installed</th>
                        <th>Fixed In</th>
                        <th>Title</th>
                    </tr>
                </thead>
                <tbody>"""
        
        for vuln in critical_vulns:
            html += f"""
                    <tr>
                        <td><strong>{vuln['id']}</strong></td>
                        <td>{vuln['package']}</td>
                        <td>{vuln['installed_version']}</td>
                        <td>{vuln['fixed_version'] if vuln['fixed_version'] else 'N/A'}</td>
                        <td>{vuln['title']}</td>
                    </tr>"""
        
        html += """
                </tbody>
            </table>
        </div>"""

    # High Vulnerabilities Section
    if high_vulns:
        html += f"""
        <div class="section">
            <h2>⚠️ High Severity Vulnerabilities</h2>
            <p>These vulnerabilities should be addressed promptly to maintain security.</p>
            <table class="vulnerability-table">
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>Package</th>
                        <th>Installed</th>
                        <th>Fixed In</th>
                        <th>Title</th>
                    </tr>
                </thead>
                <tbody>"""
        
        for vuln in high_vulns:
            html += f"""
                    <tr>
                        <td><strong>{vuln['id']}</strong></td>
                        <td>{vuln['package']}</td>
                        <td>{vuln['installed_version']}</td>
                        <td>{vuln['fixed_version'] if vuln['fixed_version'] else 'N/A'}</td>
                        <td>{vuln['title']}</td>
                    </tr>"""
        
        html += """
                </tbody>
            </table>
        </div>"""

    # Most Vulnerable Packages
    html += f"""
        <div class="section">
            <h2>📦 Most Vulnerable Packages</h2>
            <p>These packages have the highest number of vulnerabilities and should be prioritized for updates.</p>
            <div class="package-list">"""
    
    for package, count in analysis['summary']['most_vulnerable_packages']:
        html += f"""
                <div class="package-item">
                    <div class="package-name">{package}</div>
                    <div class="package-count">{count} vulnerabilities</div>
                </div>"""
    
    html += """
            </div>
        </div>"""

    # Recommendations
    html += f"""
        <div class="section">
            <div class="recommendations">
                <h3>🔧 Security Recommendations</h3>
                <ul>
                    <li>Update the base image to the latest stable version</li>
                    <li>Update packages with critical and high vulnerabilities immediately</li>
                    <li>Consider using minimal base images (like Alpine Linux) to reduce attack surface</li>
                    <li>Implement automated vulnerability scanning in your CI/CD pipeline</li>
                    <li>Regularly update dependencies and monitor for new vulnerabilities</li>
                    <li>Remove unnecessary packages and dependencies to minimize risk</li>
                    <li>Use multi-stage builds to exclude build-time dependencies from final images</li>
                    <li>Implement runtime security monitoring for deployed containers</li>
                </ul>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>Report generated by Trivy Container Security Scanner</p>
            <p>Scan completed on {analysis['scan_info']['scan_date']}</p>
        </div>
    </div>
</body>
</html>"""

    return html

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
    parser = argparse.ArgumentParser(description='Generate professional HTML security report from Trivy scan')
    parser.add_argument('image', help='Docker image name to scan')
    parser.add_argument('--output-dir', default='./reports', help='Output directory for reports')
    parser.add_argument('--no-open', action='store_true', help='Do not auto-open the HTML report')
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Generate timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # File paths
    json_file = os.path.join(args.output_dir, f"trivy_report_{timestamp}.json")
    html_file = os.path.join(args.output_dir, f"security_report_{timestamp}.html")
    
    print("🛡️  Professional Trivy HTML Report Generator")
    print(f"📊 Image: {args.image}")
    print(f"📁 Output: {args.output_dir}")
    print("-" * 50)
    
    # Step 1: Run Trivy scan
    if not run_trivy_scan(args.image, json_file):
        sys.exit(1)
    
    # Step 2: Load and analyze JSON data
    try:
        with open(json_file, 'r') as f:
            json_data = json.load(f)
        print("✅ JSON data loaded successfully")
        
        analysis = analyze_trivy_data(json_data)
        print(f"✅ Analysis complete: {analysis['scan_info']['total_vulnerabilities']} total vulnerabilities")
        print(f"   - Critical: {analysis['scan_info']['severity_counts']['CRITICAL']}")
        print(f"   - High: {analysis['scan_info']['severity_counts']['HIGH']}")
        print(f"   - Medium: {analysis['scan_info']['severity_counts']['MEDIUM']}")
        print(f"   - Low: {analysis['scan_info']['severity_counts']['LOW']}")
        
    except Exception as e:
        print(f"❌ Error loading/analyzing JSON: {e}")
        sys.exit(1)
    
    # Step 3: Generate HTML report
    print("🎨 Generating HTML report...")
    html_content = generate_html_report(analysis)
    
    # Step 4: Save HTML report
    if not save_html_report(html_content, html_file):
        sys.exit(1)
    
    # Step 5: Open report
    if not args.no_open:
        print("🌐 Opening HTML report in browser...")
        open_report(html_file)
    
    print("\n🎉 Report generation completed successfully!")
    print(f"📄 JSON Report: {json_file}")
    print(f"🌐 HTML Report: {html_file}")
    print(f"🔍 Risk Level: {analysis['summary']['risk_level']}")

if __name__ == "__main__":
    main()
