#!/usr/bin/env python3
"""
Example Usage Script
Demonstrates how to use the SQL Injection Analyser programmatically
"""

from scanner.input_analyser import InputAnalyser
from scanner.payload_injector import PayloadInjector
from scanner.response_parser import ResponseParser
from scanner.report_generator import ReportGenerator


def example_basic_scan():
    """Example: Basic vulnerability scan"""
    print("="*70)
    print("EXAMPLE 1: Basic Vulnerability Scan")
    print("="*70 + "\n")

    # Initialize components
    analyser = InputAnalyser()
    injector = PayloadInjector(payloads_file='payloads/sql_payloads.txt')
    parser = ResponseParser()

    # Target URL
    url = "http://testphp.vulnweb.com/artists.php?artist=1"

    # Step 1: Identify injection points
    print("[*] Identifying injection points...")
    injection_points = analyser.identify_injection_points(url)
    print(f"[+] Found {len(injection_points)} injection points\n")

    # Step 2: Get baseline
    print("[*] Getting baseline response...")
    baseline = injector.get_baseline_response(url)
    print("[+] Baseline captured\n")

    # Step 3: Test first injection point (limited payloads)
    if injection_points:
        print("[*] Testing first injection point...")
        results = injector.test_injection_point(injection_points[0], max_payloads=5)

        for result in results:
            analysis = parser.analyze_vulnerability(result, baseline)
            if analysis['is_vulnerable']:
                print(f"\n[!] VULNERABILITY FOUND!")
                print(f"    Type: {analysis['vulnerability_type']}")
                print(f"    Severity: {analysis['severity']}")
                print(f"    Payload: {result.get('payload')}")


def example_input_analysis():
    """Example: Input analysis and sanitization checking"""
    print("\n" + "="*70)
    print("EXAMPLE 2: Input Analysis")
    print("="*70 + "\n")

    analyser = InputAnalyser()

    # Test various inputs
    test_inputs = [
        "1234",
        "admin' OR '1'='1",
        "test@example.com",
        "'; DROP TABLE users--",
    ]

    for test_input in test_inputs:
        print(f"\nAnalyzing: {test_input}")
        analysis = analyser.analyze_input_sanitization(test_input)
        print(f"  Risk Level: {analysis['risk_level']}")
        print(f"  Risk Score: {analysis['risk_score']}")
        print(f"  Has SQL Keywords: {analysis['has_sql_keywords']}")
        print(f"  Has Tautology: {analysis['has_tautology']}")


def example_error_detection():
    """Example: SQL error detection"""
    print("\n" + "="*70)
    print("EXAMPLE 3: SQL Error Detection")
    print("="*70 + "\n")

    parser = ResponseParser()

    # Sample responses with SQL errors
    test_responses = [
        "You have an error in your SQL syntax near '1'",
        "PostgreSQL ERROR: relation 'users' does not exist",
        "Microsoft SQL Server Error: Invalid object name",
        "Normal response with no errors",
    ]

    for response in test_responses:
        has_error, db_type = parser.detect_sql_errors(response)
        print(f"\nResponse: {response[:50]}...")
        if has_error:
            print(f"  [!] SQL Error Detected: {db_type}")
        else:
            print(f"  [+] No SQL errors found")


def example_report_generation():
    """Example: Generate security report"""
    print("\n" + "="*70)
    print("EXAMPLE 4: Report Generation")
    print("="*70 + "\n")

    # Sample scan results
    scan_results = {
        'target_url': 'http://example.com/page?id=1',
        'start_time': '2026-02-10 12:00:00',
        'end_time': '2026-02-10 12:05:30',
        'duration': '0:05:30',
        'injection_points': [
            {'type': 'GET', 'parameter': 'id', 'url': 'http://example.com/page?id=1'}
        ],
        'vulnerabilities': [
            {
                'parameter': 'id',
                'method': 'GET',
                'payload': "' OR '1'='1",
                'is_vulnerable': True,
                'vulnerability_type': 'Error-Based SQLi',
                'severity': 'CRITICAL',
                'confidence': 'HIGH',
                'evidence': ['SQL Error: MySQL: You have an error in your SQL syntax']
            }
        ],
        'total_tests': 100,
        'total_payloads': 150
    }

    reporter = ReportGenerator()

    # Generate reports
    print("[*] Generating Markdown report...")
    md_report = reporter.generate_markdown_report(scan_results, 'example_report.md')
    print(f"[+] Markdown report saved: {md_report}")

    print("\n[*] Generating JSON report...")
    json_report = reporter.generate_json_report(scan_results, 'example_report.json')
    print(f"[+] JSON report saved: {json_report}")

    # Print summary
    print("\n[*] Console summary:")
    reporter.print_summary(scan_results)


def main():
    """Run all examples"""
    print("\n")
    print("╔" + "═"*68 + "╗")
    print("║" + " "*20 + "SQL INJECTION ANALYSER" + " "*26 + "║")
    print("║" + " "*25 + "USAGE EXAMPLES" + " "*29 + "║")
    print("╚" + "═"*68 + "╝")
    print("\n")

    try:
        # Run examples
        # example_basic_scan()  # Uncomment to test against vulnerable site
        example_input_analysis()
        example_error_detection()
        example_report_generation()

        print("\n" + "="*70)
        print("All examples completed successfully!")
        print("="*70 + "\n")

    except Exception as e:
        print(f"\n[!] Error running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
