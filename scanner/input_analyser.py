"""
Input Analyser Module
Analyzes user inputs and forms for potential SQL injection vulnerabilities
"""

import re
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Tuple


class InputAnalyser:
    """Analyzes and identifies potential injection points in URLs and forms"""

    def __init__(self):
        self.suspicious_patterns = [
            r"['\"`;]",  # SQL special characters
            r"--",  # SQL comment
            r"/\*.*\*/",  # Multi-line comment
            r"\bOR\b",  # OR keyword
            r"\bAND\b",  # AND keyword
            r"\bUNION\b",  # UNION keyword
            r"\bSELECT\b",  # SELECT keyword
            r"\bINSERT\b",  # INSERT keyword
            r"\bUPDATE\b",  # UPDATE keyword
            r"\bDELETE\b",  # DELETE keyword
            r"\bDROP\b",  # DROP keyword
            r"=\s*=",  # Double equals
            r"\b1=1\b",  # Tautology
        ]

    def extract_parameters(self, url: str) -> Dict[str, List[str]]:
        """
        Extract GET parameters from URL

        Args:
            url: Target URL

        Returns:
            Dictionary of parameter names and their values
        """
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        return params

    def identify_injection_points(self, url: str, post_data: Dict = None) -> List[Dict]:
        """
        Identify potential injection points in URL and POST data

        Args:
            url: Target URL
            post_data: POST parameters (optional)

        Returns:
            List of injection point dictionaries
        """
        injection_points = []

        # Analyze GET parameters
        get_params = self.extract_parameters(url)
        for param_name, param_values in get_params.items():
            injection_points.append({
                'type': 'GET',
                'parameter': param_name,
                'original_value': param_values[0] if param_values else '',
                'url': url
            })

        # Analyze POST parameters
        if post_data:
            for param_name, param_value in post_data.items():
                injection_points.append({
                    'type': 'POST',
                    'parameter': param_name,
                    'original_value': param_value,
                    'url': url
                })

        return injection_points

    def check_for_unsafe_patterns(self, input_string: str) -> Tuple[bool, List[str]]:
        """
        Check if input contains suspicious SQL patterns

        Args:
            input_string: String to analyze

        Returns:
            Tuple of (is_suspicious, list of matched patterns)
        """
        matched_patterns = []

        for pattern in self.suspicious_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                matched_patterns.append(pattern)

        is_suspicious = len(matched_patterns) > 0
        return is_suspicious, matched_patterns

    def analyze_input_sanitization(self, input_string: str) -> Dict:
        """
        Analyze how well input is sanitized

        Args:
            input_string: Input to analyze

        Returns:
            Dictionary with sanitization analysis
        """
        analysis = {
            'has_quotes': bool(re.search(r"['\"]", input_string)),
            'has_semicolon': ';' in input_string,
            'has_comment': bool(re.search(r'--|\#|/\*', input_string)),
            'has_sql_keywords': bool(re.search(
                r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE|FROM)\b',
                input_string,
                re.IGNORECASE
            )),
            'has_tautology': bool(re.search(r'1\s*=\s*1|\'1\'\s*=\s*\'1\'', input_string)),
            'length': len(input_string),
            'is_numeric': input_string.isdigit() if input_string else False
        }

        # Calculate risk score
        risk_score = 0
        if analysis['has_quotes']:
            risk_score += 2
        if analysis['has_semicolon']:
            risk_score += 2
        if analysis['has_comment']:
            risk_score += 3
        if analysis['has_sql_keywords']:
            risk_score += 3
        if analysis['has_tautology']:
            risk_score += 4

        analysis['risk_score'] = risk_score
        analysis['risk_level'] = self._get_risk_level(risk_score)

        return analysis

    def _get_risk_level(self, score: int) -> str:
        """Convert risk score to risk level"""
        if score == 0:
            return 'LOW'
        elif score <= 4:
            return 'MEDIUM'
        elif score <= 8:
            return 'HIGH'
        else:
            return 'CRITICAL'

    def validate_parameter_type(self, param_name: str, param_value: str) -> Dict:
        """
        Validate if parameter type matches expected type

        Args:
            param_name: Parameter name
            param_value: Parameter value

        Returns:
            Dictionary with validation results
        """
        # Common parameter naming conventions
        numeric_params = ['id', 'user_id', 'product_id', 'page', 'limit', 'offset', 'count']
        email_params = ['email', 'user_email', 'contact_email']

        validation = {
            'param_name': param_name,
            'param_value': param_value,
            'expected_type': 'string',
            'actual_type': 'string',
            'is_valid': True,
            'issues': []
        }

        # Check if parameter should be numeric
        if any(param_name.lower().endswith(suffix) for suffix in numeric_params):
            validation['expected_type'] = 'numeric'
            if not param_value.isdigit():
                validation['is_valid'] = False
                validation['issues'].append('Expected numeric value')
                validation['actual_type'] = 'non-numeric'

        # Check if parameter should be email
        if any(keyword in param_name.lower() for keyword in email_params):
            validation['expected_type'] = 'email'
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, param_value):
                validation['is_valid'] = False
                validation['issues'].append('Invalid email format')

        return validation
