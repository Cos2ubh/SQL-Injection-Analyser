#!/usr/bin/env python3
"""
SQL Injection Analyser - Main Entry Point

A Python security tool that detects SQL injection vulnerabilities by simulating
attack vectors and mapping findings against OWASP principles.

Usage:
    python main.py --url http://example.com/login?id=1
    python main.py --url http://example.com/login --post "username=admin&password=pass"
    python main.py --url http://example.com/login --max-payloads 10 --output report.md

Author: SQL Injection Analyser Team
License: MIT (Educational Use Only)
"""

import argparse
import sys
from datetime import datetime
import os

from scanner.input_analyser import InputAnalyser
from scanner.payload_injector import PayloadInjector
from scanner.response_parser import ResponseParser
from scanner.report_generator import ReportGenerator


class SQLInjectionAnalyser:
    """Main SQL Injection Analyser class"""

    def __init__(self, target_url: str, post_data: dict = None, max_payloads: int = None, timeout: int = 10):
        """
        Initialize SQL Injection Analyser

        Args:
            target_url: Target URL to test
            post_data: POST parameters (optional)
            max_payloads: Maximum number of payloads to test per parameter
            timeout: Request timeout in seconds
        """
        self.target_url = target_url
        self.post_data = post_data
        self.max_payloads = max_payloads
        self.timeout = timeout

        # Initialize components
        self.input_analyser = InputAnalyser()

        # Get payloads file path
        payloads_file = os.path.join(os.path.dirname(__file__), 'payloads', 'sql_payloads.txt')
        self.payload_injector = PayloadInjector(payloads_file=payloads_file, timeout=timeout)

        self.response_parser = ResponseParser()
        self.report_generator = ReportGenerator()

        # Scan results
        self.scan_results = {
            'target_url': target_url,
            'start_time': None,
            'end_time': None,
            'duration': None,
            'injection_points': [],
            'vulnerabilities': [],
            'total_tests': 0,
            'total_payloads': len(self.payload_injector.payloads)
        }

    def run_scan(self):
        """Execute the SQL injection scan"""
        print("\n" + "="*70)
        print("SQL INJECTION ANALYSER")
        print("="*70)
        print(f"\nTarget URL: {self.target_url}")
        print(f"Scan Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\n" + "="*70 + "\n")

        self.scan_results['start_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        start_timestamp = datetime.now()

        # Step 1: Identify injection points
        print("[*] Step 1: Identifying injection points...")
        injection_points = self.input_analyser.identify_injection_points(
            self.target_url,
            self.post_data
        )
        self.scan_results['injection_points'] = injection_points
        print(f"[+] Found {len(injection_points)} potential injection points")

        if not injection_points:
            print("[!] No injection points found. Exiting...")
            return

        # Step 2: Get baseline response
        print("\n[*] Step 2: Getting baseline response...")
        baseline = self.payload_injector.get_baseline_response(self.target_url)
        if baseline.get('error'):
            print(f"[!] Warning: Could not get baseline response: {baseline['error']}")
        else:
            print("[+] Baseline response captured")

        # Step 3: Test each injection point
        print("\n[*] Step 3: Testing injection points...")
        for i, injection_point in enumerate(injection_points, 1):
            print(f"\n[*] Testing injection point {i}/{len(injection_points)}")
            print(f"    Type: {injection_point['type']}")
            print(f"    Parameter: {injection_point['parameter']}")

            # Test with payloads
            injection_results = self.payload_injector.test_injection_point(
                injection_point,
                max_payloads=self.max_payloads
            )

            self.scan_results['total_tests'] += len(injection_results)

            # Analyze each result
            for result in injection_results:
                analysis = self.response_parser.analyze_vulnerability(result, baseline)

                if analysis['is_vulnerable']:
                    # Add vulnerability to results
                    vulnerability = {
                        'parameter': injection_point['parameter'],
                        'method': injection_point['type'],
                        'payload': result.get('payload'),
                        'is_vulnerable': True,
                        'vulnerability_type': analysis['vulnerability_type'],
                        'severity': analysis['severity'],
                        'confidence': analysis['confidence'],
                        'evidence': analysis['evidence']
                    }
                    self.scan_results['vulnerabilities'].append(vulnerability)

                    print(f"    [!] VULNERABILITY FOUND!")
                    print(f"        Type: {analysis['vulnerability_type']}")
                    print(f"        Severity: {analysis['severity']}")
                    print(f"        Payload: {result.get('payload')[:50]}...")

            # Test for time-based blind SQLi
            print(f"    [*] Testing for time-based blind SQLi...")
            is_time_vulnerable, response_time = self.payload_injector.test_blind_sqli_time(
                self.target_url,
                injection_point['parameter'],
                delay=5
            )

            if is_time_vulnerable:
                vulnerability = {
                    'parameter': injection_point['parameter'],
                    'method': injection_point['type'],
                    'payload': 'Time-based payload',
                    'is_vulnerable': True,
                    'vulnerability_type': 'Time-Based Blind SQLi',
                    'severity': 'HIGH',
                    'confidence': 'HIGH',
                    'evidence': [f'Response delayed by {response_time:.2f} seconds']
                }
                self.scan_results['vulnerabilities'].append(vulnerability)
                print(f"    [!] TIME-BASED BLIND SQLI DETECTED!")
                print(f"        Response time: {response_time:.2f}s")

        # Step 4: Generate report
        print("\n[*] Step 4: Generating security audit report...")

        end_timestamp = datetime.now()
        self.scan_results['end_time'] = end_timestamp.strftime('%Y-%m-%d %H:%M:%S')
        duration = end_timestamp - start_timestamp
        self.scan_results['duration'] = str(duration)

        # Print summary
        self.report_generator.print_summary(self.scan_results)

        return self.scan_results

    def save_report(self, output_file: str = None, format: str = 'markdown'):
        """
        Save scan results to file

        Args:
            output_file: Output filename
            format: Report format ('markdown' or 'json')

        Returns:
            Path to saved report
        """
        if format == 'markdown':
            report_path = self.report_generator.generate_markdown_report(
                self.scan_results,
                output_file
            )
        else:
            report_path = self.report_generator.generate_json_report(
                self.scan_results,
                output_file
            )

        return report_path


def parse_post_data(post_string: str) -> dict:
    """
    Parse POST data string into dictionary

    Args:
        post_string: POST data as string (e.g., "username=admin&password=pass")

    Returns:
        Dictionary of POST parameters
    """
    if not post_string:
        return None

    post_data = {}
    pairs = post_string.split('&')
    for pair in pairs:
        if '=' in pair:
            key, value = pair.split('=', 1)
            post_data[key] = value

    return post_data


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='SQL Injection Analyser - Detect SQL injection vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --url http://example.com/page?id=1
  python main.py --url http://example.com/login --post "username=admin&password=pass"
  python main.py --url http://example.com/search?q=test --max-payloads 20 --output custom_report.md

Educational use only. Only test applications you own or have permission to test.
        """
    )

    parser.add_argument(
        '--url',
        required=True,
        help='Target URL to test for SQL injection'
    )

    parser.add_argument(
        '--post',
        help='POST data (format: "param1=value1&param2=value2")',
        default=None
    )

    parser.add_argument(
        '--max-payloads',
        type=int,
        help='Maximum number of payloads to test per parameter (default: all)',
        default=None
    )

    parser.add_argument(
        '--timeout',
        type=int,
        help='Request timeout in seconds (default: 10)',
        default=10
    )

    parser.add_argument(
        '--output',
        help='Output report filename (default: auto-generated)',
        default=None
    )

    parser.add_argument(
        '--format',
        choices=['markdown', 'json'],
        help='Report format (default: markdown)',
        default='markdown'
    )

    parser.add_argument(
        '--no-report',
        action='store_true',
        help='Do not save report to file (print summary only)'
    )

    args = parser.parse_args()

    # Validate URL
    if not args.url.startswith('http://') and not args.url.startswith('https://'):
        print("[!] Error: URL must start with http:// or https://")
        sys.exit(1)

    # Parse POST data
    post_data = parse_post_data(args.post)

    try:
        # Initialize and run scanner
        scanner = SQLInjectionAnalyser(
            target_url=args.url,
            post_data=post_data,
            max_payloads=args.max_payloads,
            timeout=args.timeout
        )

        # Run scan
        results = scanner.run_scan()

        # Save report if requested
        if not args.no_report:
            report_path = scanner.save_report(args.output, args.format)
            print(f"\n[+] Report saved to: {report_path}")

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
