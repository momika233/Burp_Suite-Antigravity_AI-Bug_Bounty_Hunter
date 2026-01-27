# -*- coding: utf-8 -*-
# Burp Suite Legacy Python Extension: Antigravity AI Bug Bounty Hunter
# With high-confidence regex pre-filter + fixed severity + rate limit
# FIXED: Removed f-strings for Jython 2.7 compatibility

from burp import IBurpExtender, IHttpListener, IScannerCheck, IScanIssue
from java.io import PrintWriter
import json
import threading
import urllib2
import time
import re

# High-confidence fast matching rules (highest priority, report immediately on match)
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
    (r"(?i)(AKIA[0-9A-Z]{16}|"              # AWS Access Key
     r"aws_access_key_id\s*=\s*['\"][A-Z0-9]{20}['\"]|"
     r"-----BEGIN (RSA |EC |DSA |)PRIVATE KEY-----|"
     r"BEGIN PRIVATE KEY|"
     r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{43}|"  # JWT
     r"SG\.[\w-]{20,}|"                     # some other signed keys
     r"SK-[\w]{20,})",                      # OpenAI / Anthropic etc. sk- prefix
     "Sensitive Key / Credential Leak", "High", 99),

    (r"(?i)(you have an error in your sql syntax|"
     r"syntax error.*near|"
     r"sql syntax.*mysql|"
     r"ORA-009[0-9]{2}|"
     r"SQLSTATE|"
     r"Microsoft OLE DB Provider for SQL Server.*error)",
     "SQL Error Message Leak", "High", 98),

    (r"(?i)(Traceback \(most recent call last\):|"
     r"at .*?\(.*?\:\d+\)|"
     r"Caused by: |"
     r"java\.lang\.(NullPointerException|IllegalArgumentException|ExceptionInInitializerError)|"
     r"Unhandled Exception|"
     r"stack trace:|"
     r"PHP Fatal error|"
     r"Call to undefined function)",
     "Stack Trace / Debug Leak", "High", 95),

    (r'(?i)"success"\s*:\s*(false|null|0)|'
     r'"status"\s*:\s*["\']?(failed|error|fail|ko|not_ok|exception)["\']?|'
     r'"code"\s*:\s*["\']?(4\d{2}|5\d{2})["\']?|'
     r'"message"\s*:\s*["\']?.{0,60}(error|failed|invalid|unauthorized|forbidden).{0,60}["\']?',
     "Soft Failure in 200 Response", "Medium", 88),

    (r"(?i)(AKIA[0-9A-Z]{16}|"
     r"aws_access_key_id\s*=\s*['\"][A-Z0-9]{20}['\"]|"
     r"-----BEGIN (RSA |EC |DSA |)PRIVATE KEY-----|"
     r"BEGIN PRIVATE KEY|"
     r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{43}|"
     r"SG\.[\w-]{20,}|"
     r"SK-[\w]{20,})",
     "Sensitive Key / Credential Leak", "High", 99),

    # ────────────────────────────────────────────────
    # Added: API hidden endpoint related rules from https://gugesay.com/archives/5213
    # ────────────────────────────────────────────────

    # Debug/test/development/old/internal API path exposure (appears in request path)
    (r"(?i)/api/(debug|test|dev|staging|beta|alpha|demo|internal|v[1-9]|v10)/",
     "Exposed Debug/Test/Dev/Old-Version API Path", "High", 92),

    # Cross-platform differential interfaces (mobile usually has weaker protection)
    (r"(?i)/api/(mobile|app|android|ios)/",
     "Mobile/App Platform API (potential weaker auth)", "Medium", 87),

    # Common admin/internal interface paths
    (r"(?i)/api/(admin|superadmin|backend|console|manage|operator|staff)/",
     "Admin/Backend/Operator API Exposure", "High", 90),

    # Response contains a large amount of user-related sensitive fields (very likely unauthorized user list/full data leak)
    (r"(?i)(password_hash|pwd_hash|credit_card|card_number|cvv|ssn|id_card|"
     r"all_users|user_list|users:\s*\[.{20,}|emails?:.{5,}@|phone|token:)",
     "Massive Sensitive Data Leak in Response (likely IDOR/Unauthorized)", "High", 96),

    # 200 OK but performed high-risk actions like password reset/change/create admin (no-auth takeover risk)
    (r"(?i)(200|201)\s+OK.*(\"password_reset\"|\"reset_success\"|\"password changed\"|"
     r"\"user created\"|\"admin created\"|\"role.*admin\"|\"privilege granted\")",
     "Unauthenticated Password Reset / Admin Creation", "Critical", 97),

    # Response shows debug mode enabled or environment information leak
    (r"(?i)(debug_mode\s*:\s*true|environment\s*:\s*[\"']?(dev|test|staging)|"
     r"debug_info|test_environment|stacktrace|trace_id)",
     "Debug Mode / Environment Info Leak", "High", 93),

    # Possible weak JWT / alg:none or sensitive fields exposed in response
    (r"(?i)alg\s*:\s*[\"']?none|"
     r"(\"role\"|\"is_admin\"|\"privilege\")?\s*:\s*[\"']?(admin|super|root|god|true)",
     "Weak JWT (alg:none) or Admin Privilege in Response", "High", 91),

    (r"(?i)(200|201|302).*HTTP.*(/admin/|/debug/|/internal/|/api/v1/admin|/manage|/console|/backend)",
     "Potential 403 Bypass - Admin/Internal Path Accessible (check headers)", "High", 89),

    # Response contains sensitive data + status code not 403/401/500 (implies bypass of auth/access control)
    (r"(?i)(200|201)\s+OK.*(password|hash|token|api_key|secret|admin|user_list|all_users|credit_card|email\s*:\s*.+@)",
     "Sensitive Data Exposed on Non-403 Response - Possible Header Bypass", "High", 92),

    # Response explicitly mentions bypass / localhost / 127.0.0.1 / internal access (rare but critical)
    (r"(?i)(bypass|localhost|127\.0\.0\.1|internal access granted|direct access|proxy bypass|forbidden bypassed)",
     "Explicit Bypass / Internal Access Granted in Response", "Critical", 97),

    # 200 OK + debug/environment/development mode enabled (often appears with Header spoof)
    (r"(?i)200.*(debug\s*:\s*true|dev mode|development environment|test flag enabled|staging access)",
     "Debug/Dev Mode Enabled on 200 Response - Likely IP Spoof Bypass", "High", 90),
]

class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("Antigravity AI Bug Bounty (2026 edition)")
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)

        self.semaphore = threading.Semaphore(1)
        self.last_request_time = 0
        self.min_delay = 4.0

        self.stdout.println("[+] Extension loaded - regex fast-path + fixed severity + 4s rate limit")
        self.stdout.println("[+] Author: https://x.com/momika233")
        self.stdout.println("[+] Article: https://x.com/momika233/status/2014354189082898652")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        resp_bytes = messageInfo.getResponse()
        if not resp_bytes or len(resp_bytes) > 96 * 1024:
            return

        res_info = self.helpers.analyzeResponse(resp_bytes)
        mime = res_info.getStatedMimeType().lower()
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

    def quick_high_confidence_check(self, messageInfo, resp_bytes):
        """Fast regex matching for high-confidence leaks/errors/403 bypass, directly generate issue"""
        try:
            body_str = self.helpers.bytesToString(resp_bytes)
            preview = body_str[:65536]  # Only look at first 64KB to avoid performance issues

            # Get request info for checking request headers
            req_bytes = messageInfo.getRequest()
            req_str = self.helpers.bytesToString(req_bytes).lower()  # lowercase for easy matching
            res_info = self.helpers.analyzeResponse(resp_bytes)
            status_code = res_info.getStatusCode()

            found = []

            # ────────────────────────────────────────────────
            # All high-confidence regex rules (including newly added hidden API, sensitive data, debug etc.)
            # ────────────────────────────────────────────────
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

            # ────────────────────────────────────────────────
            # Added: Detect common internal IP spoofing / proxy header bypass 403 patterns in request headers
            # ────────────────────────────────────────────────
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
                        "Detected internal/private IP spoofing header in request (e.g. 127.0.0.1 / localhost / 10.x / 192.168.x)\n"
                        "Response status: %d (non-forbidden)\n"
                        "High probability of 403 / access control bypass via header manipulation\n"
                        "Please verify manually which header triggered the bypass."
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

                # Even on 403, worth flagging if these headers are present (possible misconfig or partial bypass)
                elif status_code in [403, 401]:
                    detail = (
                        "Request contains known IP spoofing / proxy headers (127.0.0.1 / private range)\n"
                        "Response status: %d\n"
                        "This may indicate a misconfigured access control that trusts these headers - worth testing further."
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

            # ────────────────────────────────────────────────
            # Sort: highest confidence first, return all matched issues
            # ────────────────────────────────────────────────
            if found:
                found.sort(key=lambda x: x[1], reverse=True)
                return [item[0] for item in found]

        except Exception as e:
            self.stderr.println("[quick-check error] %s" % str(e))

        return []

    def analyze_message(self, messageInfo):
        with self.semaphore:
            try:
                req_info = self.helpers.analyzeRequest(messageInfo)
                res_info = self.helpers.analyzeResponse(messageInfo.getResponse())
                resp_bytes = messageInfo.getResponse()

                # Phase 1: Fast strong-signal check
                quick_issues = self.quick_high_confidence_check(messageInfo, resp_bytes)
                for issue in quick_issues:
                    self.callbacks.addScanIssue(issue)
                    self.stdout.println("[QUICK-HIT] %s | %s" % (issue.getIssueName(), issue.getSeverity()))

                # Phase 2: LLM deep analysis (can be commented out after quick hit if not needed)
                params = []
                for p in req_info.getParameters():
                    val = p.getValue()[:180] + "..." if len(p.getValue()) > 180 else p.getValue()
                    params.append({"name": p.getName(), "value": val, "type": str(p.getType())})

                data = {
                    "url": str(req_info.getUrl()),
                    "method": req_info.getMethod(),
                    "status": res_info.getStatusCode(),
                    "mime_type": res_info.getStatedMimeType(),
                    "params_count": len(params),
                    "params_sample": params[:5]
                }

                prompt = self.build_prompt(data)
                ai_text = self.ask_ai(prompt)

                if ai_text:
                    self.handle_ai_result(ai_text, messageInfo)

            except Exception as e:
                self.stderr.println("[analyze error] %s" % str(e))

            finally:
                time.sleep(4.0)

    def build_prompt(self, data):
        return u"""
You are a senior bug bounty hunter with 10+ years experience.

You ONLY report issues with VERY STRONG evidence from metadata alone.
No assumptions about logic, auth, cookies, JS behavior, etc.

Key focus:
-If the status code is 200/201/302, but the path contains admin/debug/internal/app/v1/admin, etc. → It is highly likely that 403 has been bypassed
-If X-Forwarded-For/X-Real IP/True Client IP with equivalent values of 127.0.0.1/localhost appear in the request header, it is almost certain that it is header spoofing bypassing
-If the response contains sensitive fields (password, token, users, admin) and the status code is not 403/401, report as successful bypass

OUTPUT RULES - STRICT:
- ONLY raw JSON array: [ ... ] or []
- First char '['   Last char ']'
- NO markdown, NO explanation, NO comments
- confidence MUST >= 85 or output []

Each item:
- title (string, <=80 chars)
- severity ("High","Medium","Low","Information")
- detail (string, <=200 chars)
- confidence (int 0-100)

Metadata:

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

            try:
                self.callbacks.addScanIssue(issue)
                self.stdout.println("[AI] %s | %s" % (title, severity))
            except Exception as e:
                self.stderr.println("[addScanIssue failed] %s" % str(e))


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
