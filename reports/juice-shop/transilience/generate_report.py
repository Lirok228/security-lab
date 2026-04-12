"""
Transilience AI — Penetration Test Report Generator
OWASP Juice Shop | 2026-04-12 | Agent: transilience
"""
import os, math, json
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
pt = 1  # 1 pt = 1 unit in ReportLab
from reportlab.lib import colors
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer,
    Table, TableStyle, PageBreak, CondPageBreak, Flowable, HRFlowable
)
from reportlab.platypus.flowables import KeepTogether
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics.shapes import Drawing, Rect, Circle, Line, String
from reportlab.graphics import renderPDF

# ── Fonts ────────────────────────────────────────────────────────────────────
FONT_DIR = "/tmp/fonts"
pdfmetrics.registerFont(TTFont("FH",   f"{FONT_DIR}/Poppins-Bold.ttf"))
pdfmetrics.registerFont(TTFont("FM",   f"{FONT_DIR}/Poppins-Medium.ttf"))
pdfmetrics.registerFont(TTFont("FR",   f"{FONT_DIR}/Poppins-Regular.ttf"))
pdfmetrics.registerFont(TTFont("FL",   f"{FONT_DIR}/Poppins-Light.ttf"))
pdfmetrics.registerFont(TTFont("FI",   f"{FONT_DIR}/Poppins-Italic.ttf"))
pdfmetrics.registerFont(TTFont("FB",   f"{FONT_DIR}/Carlito-Regular.ttf"))
pdfmetrics.registerFont(TTFont("FBB",  f"{FONT_DIR}/Carlito-Bold.ttf"))
pdfmetrics.registerFont(TTFont("FBI",  f"{FONT_DIR}/Carlito-Italic.ttf"))
pdfmetrics.registerFont(TTFont("FBBI", f"{FONT_DIR}/Carlito-BoldItalic.ttf"))
from reportlab.pdfbase.pdfmetrics import registerFontFamily
registerFontFamily("Carlito", normal="FB", bold="FBB", italic="FBI", boldItalic="FBBI")

# ── Palette ───────────────────────────────────────────────────────────────────
BG   = colors.HexColor("#07040B")
BGC  = colors.HexColor("#13101C")
BGCA = colors.HexColor("#1A1625")
GL   = colors.HexColor("#1E1A2E")
BS   = colors.HexColor("#2A2535")
BP   = colors.HexColor("#6941C6")
BPL  = colors.HexColor("#8B5CF6")
BM   = colors.HexColor("#C9317C")
T1   = colors.HexColor("#FFFFFF")
T2   = colors.HexColor("#F0F2F5")
T3   = colors.HexColor("#E0E3E8")
SC   = colors.HexColor("#EF4444")
SH   = colors.HexColor("#FB923C")
SM   = colors.HexColor("#EAB308")
SL   = colors.HexColor("#22C55E")
AB   = colors.HexColor("#3B82F6")
AE   = colors.HexColor("#10B981")
AA   = colors.HexColor("#F59E0B")

SEV_COLOR = {"CRITICAL": SC, "HIGH": SH, "MEDIUM": SM, "LOW": SL}

W, H = A4
MARGIN = 20 * mm
CW = W - 2 * MARGIN

# ── Styles ────────────────────────────────────────────────────────────────────
def S(name, font, size, leading, color, align=0, space_before=0, space_after=0, left_indent=0, bullet_indent=0):
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
    al = [TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY][align]
    return ParagraphStyle(name, fontName=font, fontSize=size, leading=leading,
                          textColor=color, alignment=al, spaceBefore=space_before,
                          spaceAfter=space_after, leftIndent=left_indent,
                          bulletIndent=bullet_indent, backColor=None)

st_ct    = S("ct",    "FH", 36, 44, T1)
st_cc    = S("cc",    "FM", 18, 24, BPL)
st_h1    = S("h1",    "FH", 20, 26, T1,  space_after=8)
st_h2    = S("h2",    "FM", 16, 21, T1,  space_after=6)
st_h3    = S("h3",    "FM", 13, 17, BPL, space_after=4)
st_body  = S("body",  "FB", 12, 17, T2,  align=3)
st_bs    = S("bs",    "FB", 11, 15, T2)
st_label = S("label", "FR", 10, 13, T3)
st_sl    = S("sl",    "FM", 10, 13, BPL)
st_tt    = S("tt",    "FM", 13, 18, T1)
st_ts    = S("ts",    "FB", 11, 15, T2,  align=3)
st_bullet= S("bullet","FB", 12, 17, T2,  left_indent=14)
st_notice= S("notice","FBI",10, 14, T3)
st_card_serial = S("cs", "FH", 14, 20, SC)
st_meta  = S("meta",  "FB", 10, 13, T2)

# ── Gradient line helper ──────────────────────────────────────────────────────
class GradientLine(Flowable):
    def __init__(self, width=None, height=2):
        super().__init__()
        self.line_width = width or CW
        self.line_height = height
        self.width = self.line_width
        self.height = self.line_height

    def draw(self):
        steps = 80
        sw = self.line_width / steps
        r0, g0, b0 = 0.412, 0.255, 0.776
        r1, g1, b1 = 0.788, 0.192, 0.486
        for i in range(steps):
            t = i / (steps - 1)
            c = colors.Color(r0 + t*(r1-r0), g0 + t*(g1-g0), b0 + t*(b1-b0))
            self.canv.setFillColor(c)
            self.canv.rect(i*sw, 0, sw+0.5, self.line_height, fill=1, stroke=0)


class GradientBar(Flowable):
    def __init__(self, fraction, max_width=160, height=8):
        super().__init__()
        self.fraction = max(fraction, 0.06)
        self.max_width = max_width
        self.bar_height = height
        self.width = max_width
        self.height = height + 4

    def draw(self):
        c = self.canv
        # Track
        c.setFillColor(BGCA)
        c.roundRect(0, 2, self.max_width, self.bar_height, 3, fill=1, stroke=0)
        # Fill
        fill_w = self.fraction * self.max_width
        steps = 60
        sw = fill_w / steps
        r0, g0, b0 = 0.412, 0.255, 0.776
        r1, g1, b1 = 0.788, 0.192, 0.486
        c.saveState()
        c.clipPath(c.beginPath(), stroke=0, fill=0)
        for i in range(steps):
            t = i / (steps - 1)
            col = colors.Color(r0 + t*(r1-r0), g0 + t*(g1-g0), b0 + t*(b1-b0))
            c.setFillColor(col)
            c.rect(i*sw, 2, sw+0.5, self.bar_height, fill=1, stroke=0)
        c.restoreState()


class AccentBar(Flowable):
    def __init__(self, sev="CRITICAL", width=None):
        super().__init__()
        self.sev = sev
        self.width = width or CW
        self.height = 4

    def draw(self):
        c = self.canv
        col = SEV_COLOR.get(self.sev, SC)
        c.setFillColor(col)
        c.roundRect(0, 0, self.width, 4, 2, fill=1, stroke=0)


class MetricBox(Flowable):
    """Single KPI box"""
    def __init__(self, value, label, color=SC):
        super().__init__()
        self.value = value
        self.label = label
        self.color = color
        bw = (CW - 30) / 5
        self.width = bw
        self.height = 58

    def draw(self):
        c = self.canv
        bw = self.width
        # Background
        c.setFillColor(BGC)
        c.setStrokeColor(BS)
        c.setLineWidth(0.4)
        c.roundRect(0, 0, bw, 58, 6, fill=1, stroke=1)
        # Top accent
        c.setFillColor(self.color)
        c.roundRect(0, 55, bw, 3, 1, fill=1, stroke=0)
        # Value
        c.setFont("FH", 22)
        c.setFillColor(self.color)
        c.drawCentredString(bw/2, 28, str(self.value))
        # Label
        c.setFont("FR", 9)
        c.setFillColor(T2)
        c.drawCentredString(bw/2, 10, self.label)


class MetricRow(Flowable):
    """Row of 5 KPI boxes"""
    def __init__(self, metrics):
        super().__init__()
        self.metrics = metrics  # list of (value, label, color)
        self.width = CW
        self.height = 70

    def draw(self):
        c = self.canv
        bw = (CW - 30) / 5
        for i, (val, label, col) in enumerate(self.metrics):
            x = i * (bw + 7.5)
            c.setFillColor(BGC)
            c.setStrokeColor(BS)
            c.setLineWidth(0.4)
            c.roundRect(x, 10, bw, 58, 6, fill=1, stroke=1)
            c.setFillColor(col)
            c.roundRect(x, 65, bw, 3, 1, fill=1, stroke=0)
            c.setFont("FH", 22)
            c.setFillColor(col)
            c.drawCentredString(x + bw/2, 38, str(val))
            c.setFont("FR", 9)
            c.setFillColor(T2)
            c.drawCentredString(x + bw/2, 18, label)


class SectionNumber(Flowable):
    def __init__(self, num):
        super().__init__()
        self.num = str(num).zfill(2)
        self.width = CW
        self.height = 38

    def draw(self):
        c = self.canv
        c.setFont("FH", 42)
        c.setFillColor(colors.Color(0.412, 0.255, 0.776, 0.7))
        c.drawString(0, 0, self.num)
        c.setFillColor(colors.Color(0.549, 0.361, 0.902, 0.5))
        c.drawString(1, -1, self.num)


# ── Page template ─────────────────────────────────────────────────────────────
def make_page(canvas, doc):
    canvas.saveState()
    # Background
    canvas.setFillColor(BG)
    canvas.rect(0, 0, W, H, fill=1, stroke=0)
    # Top gradient rule
    steps = 80
    sw = W / steps
    r0, g0, b0 = 0.412, 0.255, 0.776
    r1, g1, b1 = 0.788, 0.192, 0.486
    for i in range(steps):
        t = i / (steps - 1)
        col = colors.Color(r0 + t*(r1-r0), g0 + t*(g1-g0), b0 + t*(b1-b0))
        canvas.setFillColor(col)
        canvas.rect(i*sw, H - 3.5, sw+0.5, 3.5, fill=1, stroke=0)
    # Left accent strip
    canvas.setFillColor(colors.Color(0.412, 0.255, 0.776, 0.12))
    canvas.rect(0, 26, 2.5, H - 26, fill=1, stroke=0)
    # Footer
    canvas.setFillColor(GL)
    canvas.rect(0, 0, W, 26, fill=1, stroke=0)
    canvas.setFont("FR", 7)
    canvas.setFillColor(T3)
    canvas.drawString(MARGIN, 9, "TRANSILIENCE AI   ·   Penetration Test Report   ·   CONFIDENTIAL")
    canvas.setFont("FH", 9)
    canvas.setFillColor(BP)
    canvas.drawRightString(W - MARGIN, 9, str(doc.page))
    canvas.setFont("FR", 8)
    canvas.setFillColor(T2)
    canvas.drawRightString(W - MARGIN - 14, 9, "Page ")
    canvas.restoreState()


# ── Advisory card builder ─────────────────────────────────────────────────────
def advisory_card(serial, title, sev, cvss, cwe, owasp, endpoint, summary,
                  impact_bullets, remediation_bullets, poc_snippet=""):
    col = SEV_COLOR.get(sev, SC)
    items = []

    # Accent bar
    items.append(AccentBar(sev))
    items.append(Spacer(1, 8))

    # Title row
    SEV_HEX = {"CRITICAL": "EF4444", "HIGH": "FB923C", "MEDIUM": "EAB308", "LOW": "22C55E"}
    hex_col = SEV_HEX.get(sev, "EF4444")
    sev_tag = f'<font name="FH" size="14" color="#{hex_col}">#{serial}  [{sev}]  </font>'
    title_p = Paragraph(f'{sev_tag}<font name="FH" size="14" color="#FFFFFF">{title}</font>', st_body)
    items.append(title_p)
    items.append(Spacer(1, 4))

    # Metadata row
    meta_txt = (f'<font color="#8B5CF6">Endpoint: </font>{endpoint}   '
                f'<font color="#8B5CF6"> │  CVSS: </font>{cvss}   '
                f'<font color="#8B5CF6"> │  CWE: </font>{cwe}   '
                f'<font color="#8B5CF6"> │  OWASP: </font>{owasp}')
    items.append(Paragraph(meta_txt, st_meta))
    items.append(Spacer(1, 10))

    # Score row (visual bars)
    score_norm = float(cvss) / 10.0
    items.append(_score_row(score_norm, col))
    items.append(Spacer(1, 12))

    # Summary
    items.append(Paragraph('<font name="FM" size="10" color="#8B5CF6">ОПИСАНИЕ</font>', st_body))
    items.append(Spacer(1, 4))
    items.append(Paragraph(summary, st_ts))
    items.append(Spacer(1, 8))

    # Impact
    items.append(Paragraph('<font name="FM" size="10" color="#8B5CF6">IMPACT</font>', st_body))
    items.append(Spacer(1, 4))
    for b in impact_bullets:
        items.append(Paragraph(f"• {b}", st_bullet))
    items.append(Spacer(1, 8))

    # Remediation
    items.append(Paragraph('<font name="FM" size="10" color="#10B981">REMEDIATION</font>', st_body))
    items.append(Spacer(1, 4))
    for b in remediation_bullets:
        items.append(Paragraph(f"• {b}", st_bullet))
    items.append(Spacer(1, 8))

    if poc_snippet:
        items.append(Paragraph('<font name="FM" size="10" color="#8B5CF6">PoC</font>', st_body))
        items.append(Spacer(1, 4))
        items.append(Paragraph(f'<font name="Courier" size="9" color="#F0F2F5">{poc_snippet}</font>', st_body))
        items.append(Spacer(1, 8))

    # Bottom divider
    items.append(GradientLine(CW * 0.5, 1))
    items.append(Spacer(1, 16))

    return items


def _score_row(norm, col):
    """Three bars: Severity / Reproducibility / Priority"""
    class ScoreRowFlowable(Flowable):
        def __init__(self, n, c):
            super().__init__()
            self.n = n; self.c = c
            self.width = CW; self.height = 60

        def draw(self):
            cv = self.canv
            labels = ["SEVERITY", "REPRODUCIBILITY", "PRIORITY"]
            vals   = [self.n, 1.0, self.n]
            bar_max = CW * 0.48
            for i, (lbl, v) in enumerate(zip(labels, vals)):
                y = 44 - i * 20
                cv.setFont("FM", 10); cv.setFillColor(T2)
                cv.drawString(0, y, lbl)
                vx = CW * 0.22
                # Track
                cv.setFillColor(BGCA)
                cv.roundRect(vx, y, bar_max, 8, 3, fill=1, stroke=0)
                # Fill
                fw = max(v * bar_max, 4)
                steps = 40; sw2 = fw / steps
                r0,g0,b0 = 0.412,0.255,0.776; r1,g1,b1 = 0.788,0.192,0.486
                for j in range(steps):
                    t = j/(steps-1)
                    c2 = colors.Color(r0+t*(r1-r0),g0+t*(g1-g0),b0+t*(b1-b0))
                    cv.setFillColor(c2)
                    cv.rect(vx+j*sw2, y, sw2+0.3, 8, fill=1, stroke=0)
                # Glow dot
                cv.setFillColor(colors.Color(self.c.red, self.c.green, self.c.blue, 0.3))
                cv.circle(vx+fw, y+4, 5, fill=1, stroke=0)
                # Value text
                cv.setFont("FH", 11); cv.setFillColor(self.c)
                cv.drawString(CW*0.72+10, y, f"{v:.2f}")
    return ScoreRowFlowable(norm, col)


# ── Section header helper ─────────────────────────────────────────────────────
def section_header(num, title):
    return [
        SectionNumber(num),
        Paragraph(title, st_h1),
        GradientLine(CW, 2),
        Spacer(1, 4*mm),
    ]


# ── Cover page ────────────────────────────────────────────────────────────────
def cover_page():
    items = []
    items.append(Spacer(1, 26*mm))
    items.append(GradientLine(CW, 3))
    items.append(Spacer(1, 12*mm))
    items.append(Paragraph("PENETRATION TEST", st_ct))
    items.append(Paragraph("REPORT", st_ct))
    items.append(Spacer(1, 6*mm))
    items.append(Paragraph("OWASP Juice Shop", st_cc))
    items.append(Spacer(1, 4*mm))
    items.append(GradientLine(CW * 0.35, 2))
    items.append(Spacer(1, 8*mm))

    meta = [
        ("REPORT DATE",     "2026-04-12"),
        ("CLASSIFICATION",  "CONFIDENTIAL"),
        ("TARGET",          "http://localhost:3000"),
        ("METHODOLOGY",     "PTES + OWASP WSTG"),
        ("GENERATED BY",    "Transilience AI Agent"),
        ("REPORT ID",       "PT-JUICESHOP-20260412"),
    ]
    for lbl, val in meta:
        row = Table(
            [[Paragraph(lbl, st_label), Paragraph(val, st_bs)]],
            colWidths=[CW*0.3, CW*0.7]
        )
        row.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), colors.transparent)]))
        items.append(row)
        items.append(Spacer(1, 3*mm))

    items.append(Spacer(1, 15*mm))
    items.append(Paragraph(
        "This report is confidential and intended solely for the authorised recipient. "
        "Unauthorised disclosure, copying or distribution is prohibited.",
        st_notice
    ))
    return items


# ── Executive Summary ─────────────────────────────────────────────────────────
def executive_summary():
    items = [PageBreak()]
    items += section_header("01", "Executive Summary")

    items.append(MetricRow([
        ("3",   "VALIDATED FINDINGS", SC),
        ("2",   "CRITICAL",           SC),
        ("1",   "HIGH",               SH),
        ("1",   "REJECTED",           SM),
        ("4",   "EXECUTORS",          BP),
    ]))
    items.append(Spacer(1, 8*mm))

    items.append(Paragraph(
        "В ходе тестирования OWASP Juice Shop (http://localhost:3000) методом black-box пентеста "
        "с применением multi-agent Transilience framework было выявлено <b>3 подтверждённых уязвимости</b> "
        "(2 Critical, 1 High) и <b>1 finding отклонён</b> валидатором из-за несоответствия в данных. "
        "Тестирование охватывало 4 категории атак: SQL Injection, XSS, JWT, Broken Access Control. "
        "Все критические уязвимости подтверждены рабочими PoC с полным пакетом доказательств.",
        st_body
    ))
    items.append(Spacer(1, 4*mm))

    items.append(Paragraph("Ключевые findings:", st_h3))
    key_findings = [
        "F-001 [CRITICAL 9.8] — UNION-based SQLi в /rest/products/search: полный дамп БД (22 аккаунта + MD5 хэши)",
        "F-004 [CRITICAL 9.1] — 4 Broken Access Control: /rest/memories отдаёт хэши паролей без auth",
        "F-002 [HIGH 7.4] — Stored XSS в reviews: 9 payload'ов в 5 продуктах, выполнение JS у всех посетителей",
        "F-003 [REJECTED] — JWT alg:none: правдоподобная уязвимость, но не прошла валидацию (timestamp fabrication + count mismatch)",
    ]
    for f in key_findings:
        items.append(Paragraph(f"&bull; {f}", st_bullet))
    items.append(Spacer(1, 4*mm))

    items.append(Paragraph("Exploit chains:", st_h3))
    chains = [
        "SQLi (F-001) → /rest/memories hash leak (F-004-B) → MD5 crack → Account Takeover",
        "SQLi auth bypass → Stored XSS inject (F-002) → persistent JS worm на всех посетителях",
    ]
    for ch in chains:
        items.append(Paragraph(f"&bull; {ch}", st_bullet))

    return items


# ── Findings sections ─────────────────────────────────────────────────────────
def findings_critical():
    items = [PageBreak()]
    items += section_header("02", "Critical Severity Findings")

    # F-001
    items += advisory_card(
        serial=1, title="UNION-based SQL Injection — Product Search",
        sev="CRITICAL", cvss="9.8", cwe="CWE-89", owasp="A03:2021 Injection",
        endpoint="GET /rest/products/search?q=",
        summary=(
            "Параметр <font name='Courier' size='10'>q</font> в эндпоинте поиска продуктов передаётся "
            "напрямую в SQLite-запрос без параметризации. Инъекция требует выхода из вложенного подзапроса "
            "через <font name='Courier' size='10'>\\'\\'))</font>, после чего UNION SELECT позволяет извлечь "
            "произвольные данные. Аутентификация не требуется. Воспроизведено 3/3 раза."
        ),
        impact_bullets=[
            "Полный дамп таблицы Users: 22 аккаунта, email + MD5-хэши паролей",
            "Enumeration схемы БД: 21 таблица (Users, Orders, Challenges, Wallets...)",
            "SQLite version disclosure: 3.44.2",
            "В связке с /rest/memories (F-004-B): полная компрометация всех аккаунтов",
        ],
        remediation_bullets=[
            "Использовать parameterized queries / Sequelize Op.like вместо string interpolation",
            "Убрать raw DB errors из HTTP-ответов (сейчас SQLITE_ERROR виден в 500)",
            "Заменить MD5 на bcrypt/Argon2 для хранения паролей",
            "Ввести WAF-правило на детектирование UNION SELECT паттернов",
        ],
        poc_snippet="GET /rest/products/search?q=\\')) UNION SELECT email||':'||password,2,3,4,5,6,7,8,9 FROM Users--"
    )

    # F-004
    items += advisory_card(
        serial=4, title="Broken Access Control — 4 sub-findings",
        sev="CRITICAL", cvss="9.1", cwe="CWE-284", owasp="A01:2021 Broken Access Control",
        endpoint="GET /rest/memories, /api/Users/{id}, /rest/user/authentication-details/",
        summary=(
            "Кластер из 4 уязвимостей контроля доступа. Наиболее критичная (F-004-B): "
            "<font name='Courier' size='10'>GET /rest/memories</font> без какой-либо аутентификации "
            "возвращает User-объекты с MD5-хэшами паролей, включая admin-аккаунты. "
            "Дополнительно: IDOR на профилях пользователей, vertical privilege escalation через "
            "<font name='Courier' size='10'>/rest/user/authentication-details/</font>."
        ),
        impact_bullets=[
            "F-004-B [CRITICAL 9.1]: /rest/memories без auth → MD5 хэши паролей всех пользователей",
            "F-004-C [HIGH 8.1]: любой auth пользователь читает список всех 21 аккаунтов",
            "F-004-A [HIGH 7.5]: IDOR — customer читает профили admin-аккаунтов по ID",
            "F-004-D [MEDIUM 5.3]: /api/Challenges/ раскрывает все 111 уязвимостей с описаниями",
        ],
        remediation_bullets=[
            "Убрать поле password из User-объектов во всех API-ответах немедленно",
            "Добавить проверку роли на /rest/user/authentication-details/ (только admin)",
            "Реализовать ownership check в /api/Users/{id}: пользователь видит только свой профиль",
            "Перейти с MD5 на bcrypt с work factor ≥ 12",
        ],
        poc_snippet="curl -s http://localhost:3000/rest/memories | python3 -c \"import sys,json; [print(m.get('User',{}).get('email',''),m.get('User',{}).get('password','')) for m in json.loads(sys.stdin.read())['data']]\""
    )
    return items


def findings_high():
    items = [PageBreak()]
    items += section_header("03", "High Severity Findings")

    items += advisory_card(
        serial=2, title="Stored XSS — Product Reviews (9 confirmed payloads)",
        sev="HIGH", cvss="7.4", cwe="CWE-79", owasp="A03:2021 Injection",
        endpoint="PUT /rest/products/{id}/reviews",
        summary=(
            "Поле <font name='Courier' size='10'>message</font> в отзывах к продуктам сохраняется "
            "в NeDB без HTML-санитизации и возвращается без экранирования. Angular рендерит "
            "содержимое как HTML, что приводит к выполнению произвольного JavaScript в контексте "
            "всех пользователей, просматривающих страницу продукта. 9 payload'ов подтверждены "
            "в 5 продуктах. Требуется auth для записи, но не для чтения (уязвимость персистентна)."
        ),
        impact_bullets=[
            "Session hijacking: кража document.cookie у всех посетителей заражённых продуктов",
            "CSRF: автоматические действия от имени жертвы (заказы, смена email)",
            "Фишинг: подмена контента страницы через DOM-манипуляции",
            "В связке с SQLi (F-001): inject XSS → worm распространяется через все продукты",
        ],
        remediation_bullets=[
            "Серверная санитизация: библиотека he (Node.js) перед сохранением в NeDB",
            "Клиентская санитизация: DOMPurify.sanitize() перед innerHTML",
            "Заменить Angular innerHTML bindings на [textContent] / {{ }} interpolation",
            "Добавить Content-Security-Policy: script-src 'self' — блокирует inline scripts",
        ],
        poc_snippet="curl -X PUT http://localhost:3000/rest/products/1/reviews -H 'Authorization: Bearer $TOKEN' -d '{\"message\":\"<script>alert(document.cookie)</script>\",\"language\":\"en\"}'"
    )
    return items


def rejected_section():
    items = [PageBreak()]
    items += section_header("04", "Rejected Findings (False Positives)")

    items.append(Paragraph(
        "Следующий finding был отклонён валидатором Phase 4.5 и <b>не включён в итоговые метрики</b>. "
        "Уязвимость может быть реальной, но finding не соответствует стандартам доказательной базы.",
        st_body
    ))
    items.append(Spacer(1, 4*mm))

    data = [
        [Paragraph("ID", st_sl), Paragraph("Title", st_sl), Paragraph("Failed Checks", st_sl), Paragraph("Причина", st_sl)],
        [
            Paragraph("F-003", st_bs),
            Paragraph("JWT alg:none Algorithm Confusion", st_bs),
            Paragraph("claims_vs_raw, log_corroboration", st_bs),
            Paragraph("(1) описание: '22 аккаунта' vs raw evidence: 21;\n(2) 3 verify-entries — одинаковый timestamp 09:48:32Z", st_bs),
        ],
    ]
    t = Table(data, colWidths=[CW*0.08, CW*0.28, CW*0.24, CW*0.4])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), BGC),
        ("BACKGROUND", (0,1), (-1,1), BGCA),
        ("TEXTCOLOR", (0,0), (-1,-1), T2),
        ("GRID", (0,0), (-1,-1), 0.5, GL),
        ("FONTNAME", (0,0), (-1,0), "FM"),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
    ]))
    items.append(t)
    items.append(Spacer(1, 4*mm))
    items.append(Paragraph(
        "Рекомендация: повторить тест E-03 (JWT) с новым executor'ом и корректным логированием фазы verify.",
        st_bs
    ))
    return items


def methodology_section():
    items = [PageBreak()]
    items += section_header("05", "Methodology & Validation")

    phases = [
        ("Phase 1 — Initialization",  "Определение scope, создание output-структуры, загрузка reconnaissance данных"),
        ("Phase 2 — Reconnaissance",  "Использованы данные предыдущей сессии /reconnaissance: 24 API эндпоинта, 111 challenges, tech stack"),
        ("Phase 3 — Test Plan",       "4 executor-агента: Injection, XSS, JWT/Auth, Access Control"),
        ("Phase 4 — Testing",         "Параллельный запуск 4 Pentester Executor агентов (run_in_background=True)"),
        ("Phase 4.5 — Validation",    "4 Pentester Validator агента (параллельно): 5 gate checks per finding"),
        ("Phase 5 — Aggregation",     "3/4 findings validated; 1 rejected; 2 exploit chains идентифицированы"),
        ("Phase 6 — Reporting",       "Transilience PDF report + SUMMARY.md update"),
    ]
    data = [[Paragraph("Phase", st_sl), Paragraph("Описание", st_sl)]]
    for phase, desc in phases:
        data.append([Paragraph(phase, st_bs), Paragraph(desc, st_bs)])

    t = Table(data, colWidths=[CW*0.3, CW*0.7])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), BGC),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [BGC, BGCA]),
        ("GRID", (0,0), (-1,-1), 0.5, GL),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
    ]))
    items.append(t)
    items.append(Spacer(1, 4*mm))

    items.append(Paragraph("Validation Gate (5 checks per finding):", st_h3))
    checks = [
        "CVSS Consistency — severity label matches score range",
        "Evidence Exists — description.md + poc.py + poc_output.txt + evidence/raw-source.txt",
        "PoC Validation — valid Python syntax + target reference + live execution",
        "Claims vs Raw Evidence — all factual claims corroborated in raw scan files",
        "Log Corroboration — 4 phases (recon/experiment/test/verify) + distinct timestamps",
    ]
    for ch in checks:
        items.append(Paragraph(f"&bull; {ch}", st_bullet))

    return items


# ── Build document ────────────────────────────────────────────────────────────
def build():
    out_path = "/Users/timderbak/security-lab/reports/juice-shop/transilience/reports/report-2026-04-12.pdf"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    frame = Frame(MARGIN, 30, CW, H - 30 - 28*mm, id="main")
    template = PageTemplate(id="dark_bg", frames=[frame], onPage=make_page)
    doc = BaseDocTemplate(
        out_path, pagesize=A4,
        pageTemplates=[template],
        title="Juice Shop Pentest Report — Transilience",
        author="Transilience AI",
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=28*mm, bottomMargin=30,
    )

    story = []
    story += cover_page()
    story += executive_summary()
    story += findings_critical()
    story += findings_high()
    story += rejected_section()
    story += methodology_section()

    doc.build(story)
    print(f"PDF generated: {out_path}")
    return out_path


if __name__ == "__main__":
    build()
