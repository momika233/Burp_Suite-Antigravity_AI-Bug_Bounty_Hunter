# -*- coding: utf-8 -*-
# Burp Suite Legacy Python Extension: Antigravity AI Bug Bounty Hunter v2.0
# Enhanced with: Deduplication, Response Body Sampling, JS Endpoint Extraction for IDOR
# FIXED: Removed f-strings for Jython 2.7 compatibility
# Author: https://x.com/momika233
# Optimized by: Antigravity AI

from burp import IBurpExtender, IHttpListener, IScannerCheck, IScanIssue
from java.io import PrintWriter
import json
import threading
import urllib2
import time
import re
import hashlib

# ════════════════════════════════════════════════════════════════════════════════
# HIGH CONFIDENCE PATTERNS (deduplicated)
# ════════════════════════════════════════════════════════════════════════════════
HIGH_CONFIDENCE_PATTERNS = [
    # SQL syntax error leaks (classic error messages)
    (r"(?i)(you have an error in your sql syntax|"
     r"syntax error.*near|"
     r"sql syntax.*mysql|"
     r"ORA-009[0-9]{2}|"
     r"SQLSTATE|"
     r"Microsoft OLE DB Provider for SQL Server.*error)",
     "SQL Error Message Leak", "High", 98),

    # Stack trace / exception leak (Python/Java/PHP/Node etc.)
    (r"(?i)(Traceback \(most recent call last\):|"
     r"at .*?\(.*?\:\d+\)|"
     r"Caused by: |"
     r"java\.lang\.(NullPointerException|IllegalArgumentException|ExceptionInInitializerError)|"
     r"Unhandled Exception|"
     r"stack trace:|"
     r"PHP Fatal error|"
     r"Call to undefined function)",
     "Stack Trace / Debug Leak", "High", 95),

    # 200 OK but business clearly failed (common soft 500 alternative)
    (r'(?i)"success"\s*:\s*(false|null|0)|'
     r'"status"\s*:\s*["\']?(failed|error|fail|ko|not_ok|exception)["\']?|'
     r'"code"\s*:\s*["\']?(4\d{2}|5\d{2})["\']?|'
     r'"message"\s*:\s*["\']?.{0,60}(error|failed|invalid|unauthorized|forbidden).{0,60}["\']?',
     "Soft Failure in 200 Response", "Medium", 88),

    # Key / credential leak (AWS / JWT / PEM etc. classic prefixes)
    (r"(?i)(AKIA[0-9A-Z]{16}|"
     r"aws_access_key_id\s*=\s*['\"][A-Z0-9]{20}['\"]|"
     r"-----BEGIN (RSA |EC |DSA |)PRIVATE KEY-----|"
     r"BEGIN PRIVATE KEY|"
     r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{43}|"
     r"SG\.[\w-]{20,}|"
     r"SK-[\w]{20,})",
     "Sensitive Key / Credential Leak", "High", 99),

    # Debug/test/development/old/internal API path exposure
    (r"(?i)/api/(debug|test|dev|staging|beta|alpha|demo|internal|v[1-9]|v10)/",
     "Exposed Debug/Test/Dev/Old-Version API Path", "High", 92),

    # Cross-platform differential interfaces (mobile usually has weaker protection)
    (r"(?i)/api/(mobile|app|android|ios)/",
     "Mobile/App Platform API (potential weaker auth)", "Medium", 87),

    # Common admin/internal interface paths
    (r"(?i)/api/(admin|superadmin|backend|console|manage|operator|staff)/",
     "Admin/Backend/Operator API Exposure", "High", 90),

    # Response contains sensitive fields (IDOR/unauthorized data leak)
    (r"(?i)(password_hash|pwd_hash|credit_card|card_number|cvv|ssn|id_card|"
     r"all_users|user_list|users:\s*\[.{20,}|emails?:.{5,}@|phone|token:)",
     "Massive Sensitive Data Leak in Response (likely IDOR/Unauthorized)", "High", 96),

    # 200 OK but performed high-risk actions (no-auth takeover risk)
    (r"(?i)(200|201)\s+OK.*(\"password_reset\"|\"reset_success\"|\"password changed\"|"
     r"\"user created\"|\"admin created\"|\"role.*admin\"|\"privilege granted\")",
     "Unauthenticated Password Reset / Admin Creation", "Critical", 97),

    # Debug mode enabled or environment information leak
    (r"(?i)(debug_mode\s*:\s*true|environment\s*:\s*[\"']?(dev|test|staging)|"
     r"debug_info|test_environment|stacktrace|trace_id)",
     "Debug Mode / Environment Info Leak", "High", 93),

    # Weak JWT / alg:none or admin privilege in response
    (r"(?i)alg\s*:\s*[\"']?none|"
     r"(\"role\"|\"is_admin\"|\"privilege\")?\s*:\s*[\"']?(admin|super|root|god|true)",
     "Weak JWT (alg:none) or Admin Privilege in Response", "High", 91),

    # 403 Bypass indicators
    (r"(?i)(200|201|302).*HTTP.*(/admin/|/debug/|/internal/|/api/v1/admin|/manage|/console|/backend)",
     "Potential 403 Bypass - Admin/Internal Path Accessible", "High", 89),

    # Sensitive data on non-403 response
    (r"(?i)(200|201)\s+OK.*(password|hash|token|api_key|secret|admin|user_list|all_users|credit_card|email\s*:\s*.+@)",
     "Sensitive Data Exposed on Non-403 Response", "High", 92),

    # Explicit bypass / internal access granted
    (r"(?i)(bypass|localhost|127\.0\.0\.1|internal access granted|direct access|proxy bypass|forbidden bypassed)",
     "Explicit Bypass / Internal Access Granted in Response", "Critical", 97),

    # Debug/dev mode on 200 response
    (r"(?i)200.*(debug\s*:\s*true|dev mode|development environment|test flag enabled|staging access)",
     "Debug/Dev Mode Enabled on 200 Response", "High", 90),
]

# ════════════════════════════════════════════════════════════════════════════════
# JS ENDPOINT EXTRACTION PATTERNS (for IDOR testing)
# ════════════════════════════════════════════════════════════════════════════════
JS_ENDPOINT_PATTERNS = [
    # API endpoints in JS
    r'["\'](?P<endpoint>/api/[a-zA-Z0-9/_\-]+)["\']',
    r'["\'](?P<endpoint>/v[0-9]+/[a-zA-Z0-9/_\-]+)["\']',
    r'["\'](?P<endpoint>/rest/[a-zA-Z0-9/_\-]+)["\']',
    r'["\'](?P<endpoint>/graphql[a-zA-Z0-9/_\-]*)["\']',
    
    # Fetch/axios/XMLHttpRequest patterns
    r'fetch\s*\(\s*["\'](?P<endpoint>[^"\']+)["\']',
    r'axios\.[a-z]+\s*\(\s*["\'](?P<endpoint>[^"\']+)["\']',
    r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\'](?P<endpoint>[^"\']+)["\']',
    
    # URL construction patterns
    r'url\s*[:=]\s*["\'](?P<endpoint>/[a-zA-Z0-9/_\-]+)["\']',
    r'endpoint\s*[:=]\s*["\'](?P<endpoint>/[a-zA-Z0-9/_\-]+)["\']',
    r'path\s*[:=]\s*["\'](?P<endpoint>/[a-zA-Z0-9/_\-]+)["\']',
    r'baseUrl\s*\+\s*["\'](?P<endpoint>/[a-zA-Z0-9/_\-]+)["\']',
    
    # Template literals (common in modern JS)
    r'`[^`]*(?P<endpoint>/api/[a-zA-Z0-9/_\-\$\{\}]+)[^`]*`',
    r'`[^`]*(?P<endpoint>/v[0-9]+/[a-zA-Z0-9/_\-\$\{\}]+)[^`]*`',
    
    # Common IDOR-prone patterns with IDs
    r'["\'](?P<endpoint>/users?/\$?\{?[a-zA-Z_]*[iI]d\}?)["\']',
    r'["\'](?P<endpoint>/accounts?/\$?\{?[a-zA-Z_]*[iI]d\}?)["\']',
    r'["\'](?P<endpoint>/orders?/\$?\{?[a-zA-Z_]*[iI]d\}?)["\']',
    r'["\'](?P<endpoint>/profiles?/\$?\{?[a-zA-Z_]*[iI]d\}?)["\']',
    r'["\'](?P<endpoint>/documents?/\$?\{?[a-zA-Z_]*[iI]d\}?)["\']',
    r'["\'](?P<endpoint>/files?/\$?\{?[a-zA-Z_]*[iI]d\}?)["\']',
    r'["\'](?P<endpoint>/messages?/\$?\{?[a-zA-Z_]*[iI]d\}?)["\']',
    r'["\'](?P<endpoint>/invoices?/\$?\{?[a-zA-Z_]*[iI]d\}?)["\']',
    r'["\'](?P<endpoint>/payments?/\$?\{?[a-zA-Z_]*[iI]d\}?)["\']',
    r'["\'](?P<endpoint>/transactions?/\$?\{?[a-zA-Z_]*[iI]d\}?)["\']',
]

# IDOR test ID values (will replace placeholders)
IDOR_TEST_IDS = ["1", "2", "100", "999", "0", "-1", "admin", "test", "null", "undefined"]


class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("Antigravity AI Bug Bounty Hunter v2.0")
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)

        self.semaphore = threading.Semaphore(1)
        self.last_request_time = 0
        self.min_delay = 4.0

        # ════════════════════════════════════════════════════════════════════
        # DEDUPLICATION: Track reported issues to avoid duplicates
        # ════════════════════════════════════════════════════════════════════
        self.reported_issues = set()
        self.reported_issues_lock = threading.Lock()

        # ════════════════════════════════════════════════════════════════════
        # JS ENDPOINT EXTRACTION: Store discovered endpoints per host
        # ════════════════════════════════════════════════════════════════════
        self.discovered_endpoints = {}  # {host: set(endpoints)}
        self.discovered_endpoints_lock = threading.Lock()
        self.tested_idor_urls = set()
        self.tested_idor_lock = threading.Lock()

        self.stdout.println("[+] Extension loaded - Antigravity AI Bug Bounty Hunter v2.0")
        self.stdout.println("[+] Features: Deduplication, Response Body Sampling, JS Endpoint IDOR Testing")
        self.stdout.println("[+] Author: https://x.com/momika233")
        self.stdout.println("[+] Optimized by: Antigravity AI")

    # ════════════════════════════════════════════════════════════════════════════════
    # DEDUPLICATION HELPER
    # ════════════════════════════════════════════════════════════════════════════════
    def generate_issue_hash(self, url, issue_name, detail_snippet=""):
        """Generate a unique hash for an issue to prevent duplicates"""
        # Normalize URL (remove query params for dedup purposes)
        url_str = str(url)
        base_url = url_str.split("?")[0]
        
        # Create hash from url + issue name + first 100 chars of detail
        content = "%s|%s|%s" % (base_url, issue_name, detail_snippet[:100])
        return hashlib.md5(content.encode('utf-8')).hexdigest()

    def is_duplicate_issue(self, url, issue_name, detail=""):
        """Check if this issue has already been reported"""
        issue_hash = self.generate_issue_hash(url, issue_name, detail)
        with self.reported_issues_lock:
            if issue_hash in self.reported_issues:
                return True
            self.reported_issues.add(issue_hash)
            return False

    def add_issue_if_new(self, issue):
        """Add issue only if it's not a duplicate"""
        if not self.is_duplicate_issue(issue.getUrl(), issue.getIssueName(), issue.getIssueDetail()):
            self.callbacks.addScanIssue(issue)
            return True
        return False

    # ════════════════════════════════════════════════════════════════════════════════
    # RESPONSE BODY SAMPLING FOR LLM
    # ════════════════════════════════════════════════════════════════════════════════
    def extract_response_sample(self, resp_bytes, max_size=3072):
        """Extract a meaningful sample from response body for LLM analysis"""
        try:
            res_info = self.helpers.analyzeResponse(resp_bytes)
            body_offset = res_info.getBodyOffset()
            body_bytes = resp_bytes[body_offset:]
            body_str = self.helpers.bytesToString(body_bytes)
            
            if len(body_str) <= max_size:
                return body_str
            
            # Smart sampling: prioritize beginning and end (often contains important data)
            sample_parts = []
            
            # First 1500 chars (usually contains structure/headers/first data)
            sample_parts.append(body_str[:1500])
            
            # Try to find JSON structure indicators
            json_indicators = ['"error"', '"message"', '"data"', '"user"', '"admin"', 
                             '"token"', '"password"', '"email"', '"id"', '"status"']
            for indicator in json_indicators:
                idx = body_str.find(indicator)
                if idx > 1500 and idx < len(body_str) - 200:
                    # Extract context around the indicator
                    start = max(0, idx - 50)
                    end = min(len(body_str), idx + 200)
                    sample_parts.append("...[CONTEXT]..." + body_str[start:end])
                    break
            
            # Last 500 chars (often contains closing structure/summary)
            sample_parts.append("...[END]..." + body_str[-500:])
            
            return "\n".join(sample_parts)[:max_size]
            
        except Exception as e:
            self.stderr.println("[sample error] %s" % str(e))
            return ""

    def extract_headers_sample(self, resp_bytes):
        """Extract interesting response headers for LLM analysis"""
        try:
            res_info = self.helpers.analyzeResponse(resp_bytes)
            headers = res_info.getHeaders()
            
            interesting_headers = []
            interesting_patterns = ['x-', 'auth', 'token', 'cookie', 'session', 
                                   'server', 'powered', 'debug', 'admin', 'internal']
            
            for header in headers[1:]:  # Skip status line
                header_lower = header.lower()
                for pattern in interesting_patterns:
                    if pattern in header_lower:
                        interesting_headers.append(header)
                        break
            
            return interesting_headers[:10]  # Limit to 10 interesting headers
            
        except Exception as e:
            return []

    # ════════════════════════════════════════════════════════════════════════════════
    # JS ENDPOINT EXTRACTION FOR IDOR TESTING
    # ════════════════════════════════════════════════════════════════════════════════
    def extract_js_endpoints(self, js_content, host):
        """Extract API endpoints from JavaScript code"""
        endpoints = set()
        
        for pattern in JS_ENDPOINT_PATTERNS:
            try:
                matches = re.finditer(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    try:
                        endpoint = match.group('endpoint')
                        if endpoint and len(endpoint) > 3 and len(endpoint) < 200:
                            # Clean up the endpoint
                            endpoint = endpoint.strip()
                            # Skip static assets
                            if not any(ext in endpoint.lower() for ext in ['.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff']):
                                endpoints.add(endpoint)
                    except:
                        pass
            except Exception as e:
                pass
        
        # Store discovered endpoints for this host
        with self.discovered_endpoints_lock:
            if host not in self.discovered_endpoints:
                self.discovered_endpoints[host] = set()
            new_endpoints = endpoints - self.discovered_endpoints[host]
            self.discovered_endpoints[host].update(endpoints)
        
        return new_endpoints

    def generate_idor_test_urls(self, endpoint, base_url):
        """Generate IDOR test URLs by replacing ID placeholders"""
        test_urls = []
        
        # Pattern to find ID placeholders or numeric segments
        id_patterns = [
            (r'\$\{[^}]+\}', 'placeholder'),      # ${userId}, ${id}
            (r'\{[^}]+\}', 'placeholder'),         # {userId}, {id}
            (r'/\d+(?=/|$)', 'numeric'),           # /123/, /456
            (r'/[a-f0-9]{24}(?=/|$)', 'mongodb'),  # MongoDB ObjectId
            (r'/[a-f0-9-]{36}(?=/|$)', 'uuid'),    # UUID
        ]
        
        for pattern, pattern_type in id_patterns:
            if re.search(pattern, endpoint):
                for test_id in IDOR_TEST_IDS:
                    test_endpoint = re.sub(pattern, '/' + test_id, endpoint)
                    test_urls.append(test_endpoint)
                break
        
        # If no ID pattern found, try appending common ID params
        if not test_urls:
            for test_id in IDOR_TEST_IDS[:5]:  # Limit to first 5
                test_urls.append(endpoint + "?id=" + test_id)
                test_urls.append(endpoint + "?user_id=" + test_id)
        
        return test_urls[:20]  # Limit total test URLs

    def test_idor_endpoint(self, messageInfo, endpoint):
        """Test a discovered endpoint for IDOR vulnerabilities"""
        try:
            http_service = messageInfo.getHttpService()
            host = http_service.getHost()
            port = http_service.getPort()
            protocol = http_service.getProtocol()
            
            base_url = "%s://%s:%d" % (protocol, host, port)
            test_urls = self.generate_idor_test_urls(endpoint, base_url)
            
            for test_url in test_urls:
                # Check if already tested
                url_key = "%s%s" % (base_url, test_url)
                with self.tested_idor_lock:
                    if url_key in self.tested_idor_urls:
                        continue
                    self.tested_idor_urls.add(url_key)
                
                # Build and send request
                try:
                    # Copy headers from original request
                    orig_req = messageInfo.getRequest()
                    orig_info = self.helpers.analyzeRequest(messageInfo)
                    headers = list(orig_info.getHeaders())
                    
                    # Update the first line with new path
                    method = orig_info.getMethod()
                    headers[0] = "%s %s HTTP/1.1" % (method, test_url)
                    
                    # Build new request
                    new_req = self.helpers.buildHttpMessage(headers, None)
                    
                    # Send request
                    response = self.callbacks.makeHttpRequest(http_service, new_req)
                    
                    if response:
                        resp_bytes = response.getResponse()
                        if resp_bytes:
                            res_info = self.helpers.analyzeResponse(resp_bytes)
                            status = res_info.getStatusCode()
                            
                            # Check for potential IDOR indicators
                            if status == 200:
                                body = self.helpers.bytesToString(resp_bytes[res_info.getBodyOffset():])
                                
                                # Check for data leakage indicators
                                idor_indicators = [
                                    (r'"(user|account|profile|email|phone|address)"', "User Data"),
                                    (r'"(order|invoice|payment|transaction)"', "Financial Data"),
                                    (r'"(message|chat|conversation)"', "Private Messages"),
                                    (r'"(document|file|attachment)"', "Private Files"),
                                    (r'"(password|secret|token|api_key)"', "Credentials"),
                                ]
                                
                                for pattern, data_type in idor_indicators:
                                    if re.search(pattern, body, re.IGNORECASE):
                                        detail = (
                                            "Potential IDOR vulnerability discovered via JS endpoint extraction.\n\n"
                                            "Discovered Endpoint: %s\n"
                                            "Test URL: %s\n"
                                            "Status: 200 OK\n"
                                            "Data Type Found: %s\n\n"
                                            "The endpoint was found in JavaScript code and returned data when accessed "
                                            "with a test ID. Manual verification required to confirm unauthorized access."
                                        ) % (endpoint, test_url, data_type)
                                        
                                        issue = CustomScanIssue(
                                            http_service,
                                            self.helpers.analyzeRequest(response).getUrl(),
                                            [response],
                                            "Potential IDOR - %s Exposure via JS Endpoint" % data_type,
                                            detail,
                                            "High"
                                        )
                                        
                                        if self.add_issue_if_new(issue):
                                            self.stdout.println("[IDOR] Found: %s -> %s" % (endpoint, data_type))
                                        break
                    
                    # Rate limit between IDOR tests
                    time.sleep(0.5)
                    
                except Exception as e:
                    pass
                    
        except Exception as e:
            self.stderr.println("[IDOR test error] %s" % str(e))

    # ════════════════════════════════════════════════════════════════════════════════
    # MAIN HTTP LISTENER
    # ════════════════════════════════════════════════════════════════════════════════
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        resp_bytes = messageInfo.getResponse()
        if not resp_bytes or len(resp_bytes) > 96 * 1024:
            return

        res_info = self.helpers.analyzeResponse(resp_bytes)
        mime = res_info.getStatedMimeType().lower()
        
        # ════════════════════════════════════════════════════════════════════
        # JS ENDPOINT EXTRACTION: Analyze JavaScript responses
        # ════════════════════════════════════════════════════════════════════
        if mime in ["script", "javascript"] or "javascript" in mime:
            try:
                http_service = messageInfo.getHttpService()
                host = http_service.getHost()
                body_offset = res_info.getBodyOffset()
                js_content = self.helpers.bytesToString(resp_bytes[body_offset:])
                
                new_endpoints = self.extract_js_endpoints(js_content, host)
                
                if new_endpoints:
                    self.stdout.println("[JS] Found %d new endpoints in %s" % (len(new_endpoints), host))
                    
                    # Test discovered endpoints for IDOR in background
                    for endpoint in list(new_endpoints)[:10]:  # Limit to 10 per JS file
                        t = threading.Thread(target=self.test_idor_endpoint, args=(messageInfo, endpoint))
                        t.setDaemon(True)
                        t.start()
                        
            except Exception as e:
                self.stderr.println("[JS extraction error] %s" % str(e))

        # Skip non-text responses for main analysis
        if mime not in ["html", "json", "javascript", "xml", "text", "unknown"]:
            return

        now = time.time()
        if now - self.last_request_time < self.min_delay:
            return

        self.last_request_time = now

        t = threading.Thread(target=self.analyze_message, args=(messageInfo,))
        t.setDaemon(True)
        t.start()

    def doPassiveScan(self, messageInfo):
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 0

    # ════════════════════════════════════════════════════════════════════════════════
    # QUICK HIGH CONFIDENCE CHECK (with deduplication)
    # ════════════════════════════════════════════════════════════════════════════════
    def quick_high_confidence_check(self, messageInfo, resp_bytes):
        """Fast regex matching for high-confidence leaks/errors/403 bypass"""
        try:
            body_str = self.helpers.bytesToString(resp_bytes)
            preview = body_str[:65536]

            req_bytes = messageInfo.getRequest()
            req_str = self.helpers.bytesToString(req_bytes).lower()
            res_info = self.helpers.analyzeResponse(resp_bytes)
            status_code = res_info.getStatusCode()

            found = []

            for pattern, title, severity, conf in HIGH_CONFIDENCE_PATTERNS:
                if re.search(pattern, preview, re.DOTALL | re.IGNORECASE):
                    detail = (
                        "High-confidence pattern match:\n"
                        "Rule: %s\n"
                        "Confidence: %d%%\n"
                        "(regex based - manual verification recommended)"
                    ) % (title, conf)

                    issue = CustomScanIssue(
                        messageInfo.getHttpService(),
                        self.helpers.analyzeRequest(messageInfo).getUrl(),
                        [messageInfo],
                        title,
                        detail,
                        severity
                    )
                    found.append((issue, conf))

            # IP spoofing header detection
            SPOOF_HEADERS_PATTERN = (
                r"(?i)("
                r"x-forwarded-for|x-real-ip|true-client-ip|x-client-ip|client-ip|"
                r"forwarded|via|x-original-ip|x-proxyuser-ip|x-custom-ip-authorization|"
                r"x-forwarded-host|x-originally-forwarded-for|x-originating-ip|"
                r"x-orig-remote-addr|x-remote-addr|x-true-client-ip"
                r")\s*:\s*.*("
                r"127\.0\.0\.1|localhost|::1|0\.0\.0\.0|"
                r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|"
                r"192\.168\.\d{1,3}\.\d{1,3}"
                r")"
            )

            if re.search(SPOOF_HEADERS_PATTERN, req_str):
                is_success_status = status_code in [200, 201, 204, 301, 302, 307, 308]

                if is_success_status:
                    detail = (
                        "Detected internal/private IP spoofing header in request\n"
                        "Response status: %d (non-forbidden)\n"
                        "High probability of 403 bypass via header manipulation"
                    ) % status_code

                    issue = CustomScanIssue(
                        messageInfo.getHttpService(),
                        self.helpers.analyzeRequest(messageInfo).getUrl(),
                        [messageInfo],
                        "Potential 403 Bypass via IP Spoofing Header",
                        detail,
                        "High"
                    )
                    found.append((issue, 94))

                elif status_code in [403, 401]:
                    detail = (
                        "Request contains known IP spoofing headers\n"
                        "Response status: %d\n"
                        "May indicate misconfigured access control"
                    ) % status_code

                    issue = CustomScanIssue(
                        messageInfo.getHttpService(),
                        self.helpers.analyzeRequest(messageInfo).getUrl(),
                        [messageInfo],
                        "Suspicious IP Spoofing Headers on Protected Endpoint",
                        detail,
                        "Medium"
                    )
                    found.append((issue, 85))

            if found:
                found.sort(key=lambda x: x[1], reverse=True)
                return [item[0] for item in found]

        except Exception as e:
            self.stderr.println("[quick-check error] %s" % str(e))

        return []

    # ════════════════════════════════════════════════════════════════════════════════
    # MAIN ANALYSIS (with response body sampling)
    # ════════════════════════════════════════════════════════════════════════════════
    def analyze_message(self, messageInfo):
        with self.semaphore:
            try:
                req_info = self.helpers.analyzeRequest(messageInfo)
                res_info = self.helpers.analyzeResponse(messageInfo.getResponse())
                resp_bytes = messageInfo.getResponse()

                # Phase 1: Fast regex check (with deduplication)
                quick_issues = self.quick_high_confidence_check(messageInfo, resp_bytes)
                for issue in quick_issues:
                    if self.add_issue_if_new(issue):
                        self.stdout.println("[QUICK-HIT] %s | %s" % (issue.getIssueName(), issue.getSeverity()))

                # Phase 2: LLM deep analysis with response body sampling
                params = []
                for p in req_info.getParameters():
                    val = p.getValue()[:180] + "..." if len(p.getValue()) > 180 else p.getValue()
                    params.append({"name": p.getName(), "value": val, "type": str(p.getType())})

                # ════════════════════════════════════════════════════════════════════
                # RESPONSE BODY SAMPLING: Include response sample for LLM
                # ════════════════════════════════════════════════════════════════════
                response_sample = self.extract_response_sample(resp_bytes, max_size=3072)
                interesting_headers = self.extract_headers_sample(resp_bytes)

                data = {
                    "url": str(req_info.getUrl()),
                    "method": req_info.getMethod(),
                    "status": res_info.getStatusCode(),
                    "mime_type": res_info.getStatedMimeType(),
                    "params_count": len(params),
                    "params_sample": params[:5],
                    "response_headers_sample": interesting_headers,
                    "response_body_sample": response_sample
                }

                prompt = self.build_prompt(data)
                ai_text = self.ask_ai(prompt)

                if ai_text:
                    self.handle_ai_result(ai_text, messageInfo)

            except Exception as e:
                self.stderr.println("[analyze error] %s" % str(e))

            finally:
                time.sleep(4.0)

    # ════════════════════════════════════════════════════════════════════════════════
    # LLM PROMPT (enhanced with response body analysis)
    # ════════════════════════════════════════════════════════════════════════════════
    def build_prompt(self, data):
        return u"""
You are a senior bug bounty hunter with 10+ years experience.

You are analyzing HTTP traffic for security vulnerabilities.
You have access to request metadata AND a sample of the response body.

ANALYZE THE RESPONSE BODY FOR:
1. Sensitive data exposure (PII, credentials, tokens, API keys)
2. IDOR indicators (other users' data, sequential IDs with data)
3. Error messages leaking internal info (stack traces, SQL errors, paths)
4. Debug/development mode indicators
5. Authentication/authorization bypasses (admin data on non-admin endpoints)
6. Business logic flaws (price manipulation, status changes)

Key focus:
- If status 200/201/302 but path contains admin/debug/internal → likely 403 bypass
- If X-Forwarded-For/X-Real-IP with 127.0.0.1/localhost in request → header spoofing bypass
- If response contains sensitive fields (password, token, users, admin) and status not 403/401 → data leak
- If response shows other user's data or sequential data patterns → IDOR

OUTPUT RULES - STRICT:
- ONLY raw JSON array: [ ... ] or []
- First char '['   Last char ']'
- NO markdown, NO explanation, NO comments
- confidence MUST >= 85 or output []

Each item:
- title (string, <=80 chars)
- severity ("Critical","High","Medium","Low","Information")
- detail (string, <=300 chars, include specific evidence from response)
- confidence (int 0-100)

Metadata + Response Sample:

%s
""" % json.dumps(data, ensure_ascii=False, indent=2)

    def ask_ai(self, prompt):
        try:
            payload = json.dumps({
                "model": "claude-opus-4-5-thinking",
                "max_tokens": 1024,
                "temperature": 0.2,
                "messages": [{"role": "user", "content": prompt}]
            }).encode('utf-8')

            req = urllib2.Request(
                "http://127.0.0.1:8045/v1/messages",
                data=payload,
                headers={
                    "Content-Type": "application/json; charset=utf-8",
                    "Authorization": "Bearer sk-xxxxxxx",
                    "Accept": "application/json"
                }
            )

            resp = urllib2.urlopen(req, timeout=60)
            raw = resp.read().decode('utf-8', errors='ignore')

            parsed = json.loads(raw)
            if "content" in parsed and parsed["content"]:
                return parsed["content"][0].get("text", "").strip()

            return None

        except urllib2.HTTPError as he:
            if he.code == 429:
                self.stderr.println("[429] Rate limited")
                self.min_delay = min(self.min_delay + 2, 12)
            else:
                self.stderr.println("[HTTP %d] %s" % (he.code, he.reason))
            return None
        except Exception as e:
            self.stderr.println("[urllib2 error] %s" % str(e))
            return None

    def clean_ai_text(self, text):
        if not text:
            return ""
        text = text.strip()
        text = re.sub(r'^json\s*|\s*$', '', text, flags=re.I | re.M)
        match = re.search(r'\[.*\]', text, re.DOTALL)
        return match.group(0) if match else text

    def handle_ai_result(self, ai_text, messageInfo):
        cleaned = self.clean_ai_text(ai_text)
        try:
            issues = json.loads(cleaned)
            if not isinstance(issues, list) or not issues:
                return
        except Exception as e:
            self.stderr.println("[!] Invalid JSON: %s" % str(e))
            self.stderr.println("Raw: %s" % ai_text[:400])
            return

        for item in issues:
            if item.get("confidence", 0) < 85:
                continue

            title = item.get("title", "AI Flagged Issue").strip()[:120]
            raw_sev = item.get("severity", "Information").strip().lower()

            severity_map = {
                "critical": "High",  # Burp doesn't have Critical, map to High
                "high": "High", "medium": "Medium", "low": "Low",
                "informational": "Information", "information": "Information", "info": "Information"
            }
            severity = severity_map.get(raw_sev, "Information")

            detail = item.get("detail", "No detail").strip()

            issue = CustomScanIssue(
                messageInfo.getHttpService(),
                self.helpers.analyzeRequest(messageInfo).getUrl(),
                [messageInfo],
                title,
                detail + "\n\n(AI generated - please verify manually)",
                severity
            )

            # Use deduplication
            if self.add_issue_if_new(issue):
                self.stdout.println("[AI] %s | %s" % (title, severity))


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x80000003

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
