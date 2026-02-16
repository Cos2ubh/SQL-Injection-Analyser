"""
Response Parser Module
Analyzes HTTP responses to detect SQL injection vulnerabilities
"""

import re
from typing import Tuple, Dict, List


class ResponseParser:
    """Parses and analyzes HTTP responses for SQL injection indicators"""

    def __init__(self):
        # SQL error patterns for different databases
        self.error_patterns = {
            'MySQL': [
                r"You have an error in your SQL syntax",
                r"Warning.*mysql_.*",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"com\.mysql\.jdbc\.exceptions"
            ],
            'PostgreSQL': [
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_.*",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"org\.postgresql\.util\.PSQLException"
            ],
            'Microsoft SQL Server': [
                r"Driver.*SQL[\-\_\ ]*Server",
                r"OLE DB.*SQL Server",
                r"\bSQL Server.*Driver",
                r"Warning.*mssql_.*",
                r"Microsoft SQL Native Client error",
                r"SQLSTATE\]",
                r"com\.microsoft\.sqlserver\.jdbc\.SQLServerException"
            ],
            'Oracle': [
                r"\bORA-[0-9][0-9][0-9][0-9]",
                r"Oracle error",
                r"Oracle.*Driver",
                r"Warning.*\Woci_.*",
                r"Warning.*\Wora_.*"
            ],
            'SQLite': [
                r"SQLite/JDBCDriver",
                r"SQLite\.Exception",
                r"System\.Data\.SQLite\.SQLiteException",
                r"Warning.*sqlite_.*",
                r"Warning.*SQLite3::",
                r"\[SQLITE_ERROR\]"
            ],
            'Generic': [
                r"syntax error",
                r"unclosed quotation mark",
                r"quoted string not properly terminated",
                r"SQL command not properly ended",
                r"Incorrect syntax near"
            ]
        }

        # Success indicators (might indicate successful injection)
        self.success_indicators = [
            r"admin",
            r"root",
            r"administrator",
            r"logged in as",
            r"welcome back"
        ]

    def detect_sql_errors(self, response_text: str) -> Tuple[bool, str]:
        """
        Detect SQL error messages in response

        Args:
            response_text: HTTP response body

        Returns:
            Tuple of (has_error, database_type_or_error_message)
        """
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return True, f"{db_type}: {match.group(0)}"

        return False, ""

    def check_response_differences(self, baseline: str, injected: str) -> Dict:
        """
        Compare baseline and injected responses

        Args:
            baseline: Baseline response text
            injected: Response with injected payload

        Returns:
            Dictionary with difference analysis
        """
        analysis = {
            'length_diff': abs(len(injected) - len(baseline)),
            'length_diff_percentage': (abs(len(injected) - len(baseline)) / max(len(baseline), 1)) * 100,
            'content_changed': baseline != injected,
            'significant_change': False
        }

        # Consider change significant if length differs by more than 10%
        if analysis['length_diff_percentage'] > 10:
            analysis['significant_change'] = True

        # Check for new keywords in response
        baseline_lower = baseline.lower()
        injected_lower = injected.lower()

        # SQL-related keywords that might appear in successful injection
        sql_keywords = ['select', 'union', 'database', 'table', 'column', 'error', 'syntax']
        new_keywords = []

        for keyword in sql_keywords:
            if keyword in injected_lower and keyword not in baseline_lower:
                new_keywords.append(keyword)

        if new_keywords:
            analysis['new_sql_keywords'] = new_keywords
            analysis['significant_change'] = True

        return analysis

    def detect_data_leakage(self, response_text: str) -> Tuple[bool, List[str]]:
        """
        Detect potential data leakage in response

        Args:
            response_text: HTTP response body

        Returns:
            Tuple of (has_leakage, list of leaked data patterns)
        """
        leakage_patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email addresses'),
            (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN pattern'),
            (r'\b\d{16}\b', 'Credit card pattern'),
            (r'password["\']?\s*[:=]\s*["\']?([^"\']+)', 'Password'),
            (r'api[_-]?key["\']?\s*[:=]\s*["\']?([^"\']+)', 'API key'),
            (r'token["\']?\s*[:=]\s*["\']?([^"\']+)', 'Token'),
        ]

        leaked_data = []

        for pattern, data_type in leakage_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                leaked_data.append(f"{data_type}: {len(matches)} found")

        has_leakage = len(leaked_data) > 0
        return has_leakage, leaked_data

    def detect_boolean_injection(self, true_response: str, false_response: str) -> bool:
        """
        Detect boolean-based blind SQL injection

        Args:
            true_response: Response to true condition payload
            false_response: Response to false condition payload

        Returns:
            Boolean indicating if vulnerability exists
        """
        # If responses are significantly different, boolean injection might work
        diff_percentage = abs(len(true_response) - len(false_response)) / max(len(true_response), 1) * 100

        # Consider vulnerable if responses differ by more than 5%
        return diff_percentage > 5

    def detect_time_based_injection(self, normal_time: float, delayed_time: float, expected_delay: int) -> bool:
        """
        Detect time-based blind SQL injection

        Args:
            normal_time: Normal response time
            delayed_time: Response time with delay payload
            expected_delay: Expected delay in seconds

        Returns:
            Boolean indicating if vulnerability exists
        """
        # Check if delayed response is significantly slower
        time_difference = delayed_time - normal_time

        # Consider vulnerable if actual delay is close to expected delay (±1 second)
        return abs(time_difference - expected_delay) <= 1

    def detect_union_injection(self, response_text: str, num_columns: int = None) -> Tuple[bool, int]:
        """
        Detect successful UNION-based injection

        Args:
            response_text: HTTP response body
            num_columns: Number of columns tested (if known)

        Returns:
            Tuple of (is_vulnerable, detected_columns)
        """
        # Look for NULL values or column data in response
        null_pattern = r'NULL'
        column_pattern = r'\b(1|2|3|4|5|6|7|8|9|10)\b'

        null_matches = len(re.findall(null_pattern, response_text))
        column_matches = re.findall(column_pattern, response_text)

        # If we see multiple NULLs or sequential numbers, UNION might have worked
        is_vulnerable = null_matches >= 2 or len(set(column_matches)) >= 3

        detected_columns = max(null_matches, len(set(column_matches)))

        return is_vulnerable, detected_columns

    def analyze_vulnerability(self, injection_result: Dict, baseline: Dict = None) -> Dict:
        """
        Comprehensive vulnerability analysis of injection result

        Args:
            injection_result: Result from PayloadInjector
            baseline: Baseline response for comparison

        Returns:
            Dictionary with vulnerability analysis
        """
        analysis = {
            'is_vulnerable': False,
            'vulnerability_type': None,
            'confidence': 'LOW',
            'evidence': [],
            'severity': 'INFO'
        }

        if not injection_result.get('success'):
            if injection_result.get('error') == 'TIMEOUT':
                analysis['is_vulnerable'] = True
                analysis['vulnerability_type'] = 'Time-Based Blind SQLi'
                analysis['confidence'] = 'MEDIUM'
                analysis['evidence'].append('Request timed out - possible time-based injection')
                analysis['severity'] = 'HIGH'
            return analysis

        response_text = injection_result.get('response_text', '')

        # Check for SQL errors
        has_error, error_msg = self.detect_sql_errors(response_text)
        if has_error:
            analysis['is_vulnerable'] = True
            analysis['vulnerability_type'] = 'Error-Based SQLi'
            analysis['confidence'] = 'HIGH'
            analysis['evidence'].append(f'SQL Error: {error_msg}')
            analysis['severity'] = 'CRITICAL'

        # Check for data leakage
        has_leakage, leaked_data = self.detect_data_leakage(response_text)
        if has_leakage:
            analysis['is_vulnerable'] = True
            if not analysis['vulnerability_type']:
                analysis['vulnerability_type'] = 'Data Leakage via SQLi'
            analysis['confidence'] = 'HIGH'
            analysis['evidence'].extend(leaked_data)
            analysis['severity'] = 'CRITICAL'

        # Compare with baseline if available
        if baseline and baseline.get('response_text'):
            diff = self.check_response_differences(
                baseline['response_text'],
                response_text
            )
            if diff['significant_change']:
                if not analysis['is_vulnerable']:
                    analysis['is_vulnerable'] = True
                    analysis['vulnerability_type'] = 'Content-Based SQLi'
                    analysis['confidence'] = 'MEDIUM'
                    analysis['severity'] = 'HIGH'
                analysis['evidence'].append(
                    f"Response changed significantly ({diff['length_diff_percentage']:.1f}%)"
                )
                if diff.get('new_sql_keywords'):
                    analysis['evidence'].append(
                        f"New SQL keywords found: {', '.join(diff['new_sql_keywords'])}"
                    )

        return analysis
