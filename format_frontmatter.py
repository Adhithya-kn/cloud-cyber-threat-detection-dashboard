import docx
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
import os

TEMPLATE_PATH = '/Users/ak/.gemini/antigravity/brain/f070d679-5e82-456f-80af-3f78f20eba37/.user_uploaded/media_1791376098499.docx'
OUTPUT_PATH = '/Users/ak/Documents/Cp-01/cloud-cyber-threat-detection-dashboard/MICROPROJECT_REPORT_CLOUD_CYBER_THREAT_DETECTION.docx'
SCREENSHOTS_DIR = '/Users/ak/Documents/Cp-01/cloud-cyber-threat-detection-dashboard/screenshots'

doc = docx.Document(TEMPLATE_PATH)

# Helper function to set run font
def format_run(run, font_name="Times New Roman", size_pt=12, bold=False, italic=False, color=None):
    run.font.name = font_name
    run.font.size = Pt(size_pt)
    run.bold = bold
    run.italic = italic
    if color:
        run.font.color.rgb = color

# Helper to set paragraph format
def format_para(para, align=WD_ALIGN_PARAGRAPH.LEFT, line_spacing=1.15, space_after=6, space_before=0):
    para.alignment = align
    para.paragraph_format.line_spacing = line_spacing
    para.paragraph_format.space_after = Pt(space_after)
    para.paragraph_format.space_before = Pt(space_before)

# Set cell borders
def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def set_cell_shading(cell, color_hex):
    shading_xml = f'<w:shd {nsdecls("w")} w:fill="{color_hex}"/>'
    cell._tc.get_or_add_tcPr().append(parse_xml(shading_xml))

print(f"Total paragraphs in template: {len(doc.paragraphs)}")

# 1. Update Title Page
# P0 is Title
for r in doc.paragraphs[0].runs:
    r.text = ""
r0 = doc.paragraphs[0].add_run("CLOUD-BASED CYBER THREAT DETECTION DASHBOARD")
format_run(r0, font_name="Times New Roman", size_pt=16, bold=True)
doc.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

# P8, P9, P10, P11 are Student Names on Title Page
students_info = [
    ("Rohan H", "2411021060715"),
    ("Tharun Reddy", "2411021060740"),
    ("Adhithya K N", "2411021060714")
]

doc.paragraphs[8].text = ""
r8 = doc.paragraphs[8].add_run(f"{students_info[0][0]} — {students_info[0][1]}")
format_run(r8, font_name="Times New Roman", size_pt=12, bold=True)
doc.paragraphs[8].alignment = WD_ALIGN_PARAGRAPH.CENTER

doc.paragraphs[9].text = ""
r9 = doc.paragraphs[9].add_run(f"{students_info[1][0]} — {students_info[1][1]}")
format_run(r9, font_name="Times New Roman", size_pt=12, bold=True)
doc.paragraphs[9].alignment = WD_ALIGN_PARAGRAPH.CENTER

doc.paragraphs[10].text = ""
r10 = doc.paragraphs[10].add_run(f"{students_info[2][0]} — {students_info[2][1]}")
format_run(r10, font_name="Times New Roman", size_pt=12, bold=True)
doc.paragraphs[10].alignment = WD_ALIGN_PARAGRAPH.CENTER

doc.paragraphs[11].text = "" # remove 4th student placeholder

# 2. Update Certificate Paragraph (P40)
doc.paragraphs[40].text = ""
r40_1 = doc.paragraphs[40].add_run("This is to certify that the microproject entitled ")
format_run(r40_1, font_name="Times New Roman", size_pt=12, bold=False)
r40_2 = doc.paragraphs[40].add_run("“CLOUD-BASED CYBER THREAT DETECTION DASHBOARD” ")
format_run(r40_2, font_name="Times New Roman", size_pt=12, bold=True)
r40_3 = doc.paragraphs[40].add_run("is a bona fide work carried out by ")
format_run(r40_3, font_name="Times New Roman", size_pt=12, bold=False)
r40_4 = doc.paragraphs[40].add_run("Rohan H (2411021060715), Tharun Reddy (2411021060740), and Adhithya K N (2411021060714) ")
format_run(r40_4, font_name="Times New Roman", size_pt=12, bold=True)
r40_5 = doc.paragraphs[40].add_run("as part of the requirements for the course ")
format_run(r40_5, font_name="Times New Roman", size_pt=12, bold=False)
r40_6 = doc.paragraphs[40].add_run("Cloud Applications Development and Deployment (E1CSA372) ")
format_run(r40_6, font_name="Times New Roman", size_pt=12, bold=True)
r40_7 = doc.paragraphs[40].add_run("during the academic year ")
format_run(r40_7, font_name="Times New Roman", size_pt=12, bold=False)
r40_8 = doc.paragraphs[40].add_run("2026–2027")
format_run(r40_8, font_name="Times New Roman", size_pt=12, bold=True)
r40_9 = doc.paragraphs[40].add_run(", under my guidance.")
format_run(r40_9, font_name="Times New Roman", size_pt=12, bold=False)
doc.paragraphs[40].alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

# 3. Update Declaration Paragraph (P66)
doc.paragraphs[66].text = ""
r66_1 = doc.paragraphs[66].add_run("We hereby declare that the microproject report entitled ")
format_run(r66_1, font_name="Times New Roman", size_pt=12, bold=False)
r66_2 = doc.paragraphs[66].add_run("“CLOUD-BASED CYBER THREAT DETECTION DASHBOARD” ")
format_run(r66_2, font_name="Times New Roman", size_pt=12, bold=True)
r66_3 = doc.paragraphs[66].add_run("is an original work carried out by us as part of the course ")
format_run(r66_3, font_name="Times New Roman", size_pt=12, bold=False)
r66_4 = doc.paragraphs[66].add_run("Cloud Applications Development and Deployment (E1CSA372) ")
format_run(r66_4, font_name="Times New Roman", size_pt=12, bold=True)
r66_5 = doc.paragraphs[66].add_run("during the academic year 2026–2027, under the guidance of ")
format_run(r66_5, font_name="Times New Roman", size_pt=12, bold=False)
r66_6 = doc.paragraphs[66].add_run("Dr. C VIJI, Associate Professor, ")
format_run(r66_6, font_name="Times New Roman", size_pt=12, bold=True)
r66_7 = doc.paragraphs[66].add_run("Alliance School of Advanced Computing, Alliance University.")
format_run(r66_7, font_name="Times New Roman", size_pt=12, bold=False)
doc.paragraphs[66].alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

# Student signatories in Declaration (P75, P76, P77, P78)
doc.paragraphs[75].text = ""
r75 = doc.paragraphs[75].add_run(f"1. {students_info[0][0]} — {students_info[0][1]}\t\t____________________")
format_run(r75, font_name="Times New Roman", size_pt=12)

doc.paragraphs[76].text = ""
r76 = doc.paragraphs[76].add_run(f"2. {students_info[1][0]} — {students_info[1][1]}\t\t____________________")
format_run(r76, font_name="Times New Roman", size_pt=12)

doc.paragraphs[77].text = ""
r77 = doc.paragraphs[77].add_run(f"3. {students_info[2][0]} — {students_info[2][1]}\t\t____________________")
format_run(r77, font_name="Times New Roman", size_pt=12)

doc.paragraphs[78].text = ""

# Date and place
doc.paragraphs[94].text = ""
r94 = doc.paragraphs[94].add_run("Date: 07-10-2026")
format_run(r94, font_name="Times New Roman", size_pt=12, bold=True)

doc.paragraphs[96].text = ""
r96 = doc.paragraphs[96].add_run("Place: Bengaluru")
format_run(r96, font_name="Times New Roman", size_pt=12, bold=True)

# 4. Fill Abstract (P98 is Heading 3: ABSTRACT, P99 is empty)
doc.paragraphs[99].text = ""
abstract_text = (
    "In modern enterprise cloud environments, organizations face a rapid surge in sophisticated cyber threats, "
    "ranging from distributed brute-force attacks and stealthy port scans to high-volume unauthorized data exfiltration. "
    "Traditional security monitoring platforms and enterprise SIEM solutions frequently impose prohibitive licensing overheads, "
    "excessive configuration complexity, and opaque machine learning black-box workflows that impede immediate human comprehension. "
    "This microproject presents CyberShield, a cloud-native Cyber Threat Detection and Security Operations Center (SOC) dashboard "
    "designed to provide real-time telemetry ingestion, deterministic rule detection, explainable machine learning anomaly identification, "
    "risk scoring (0–100 scale), and structured incident triage. "
    "The application is engineered using Python, Pandas, Scikit-learn (Isolation Forest), and Plotly, and is packaged as a high-performance "
    "interactive Streamlit web dashboard. The system incorporates an end-to-end processing pipeline that normalizes heterogeneous CSV and JSON "
    "security events into an RFC-aligned schema, evaluates time-window thresholds for brute-force attacks (>5 failed attempts in 5 minutes), "
    "port scanning (>15 destination ports in 60 seconds), and abnormal bandwidth spikes (>10 MB in 60 seconds), fuses rule outcomes with "
    "unsupervised ML anomaly indicators, and persists deduplicated alert records with actionable mitigation playbooks. "
    "A production-grade web deployment was demonstrated and verified via cloud tunneling and automated browser testing across multiple devices. "
    "The prototype exhibits high detection accuracy, zero false alarms on normal enterprise baselines, transparent scoring mechanisms, "
    "and interactive case investigation capabilities essential for SOC analysts."
)
r_abs = doc.paragraphs[99].add_run(abstract_text)
format_run(r_abs, font_name="Times New Roman", size_pt=12)
doc.paragraphs[99].alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

# 5. Fill Abbreviations
# P103 is header, P105, P106, P107 are placeholders
abbrevs = [
    ("SOC", "Security Operations Center"),
    ("SIEM", "Security Information and Event Management"),
    ("ML", "Machine Learning"),
    ("CADD", "Cloud Applications Development and Deployment"),
    ("API", "Application Programming Interface"),
    ("MFA", "Multi-Factor Authentication"),
    ("IDS", "Intrusion Detection System"),
    ("IPS", "Intrusion Prevention System"),
    ("CSV", "Comma-Separated Values"),
    ("JSON", "JavaScript Object Notation"),
    ("RFC", "Request for Comments"),
    ("KPI", "Key Performance Indicator"),
    ("DLP", "Data Loss Prevention"),
    ("TCP", "Transmission Control Protocol"),
    ("UDP", "User Datagram Protocol"),
    ("SSH", "Secure Shell"),
    ("HTTP", "Hypertext Transfer Protocol"),
    ("HTTPS", "Hypertext Transfer Protocol Secure"),
    ("DNS", "Domain Name System")
]

doc.paragraphs[105].text = ""
doc.paragraphs[106].text = ""
doc.paragraphs[107].text = ""

# Delete placeholders from 105 to 107 and insert a proper table
p_target = doc.paragraphs[104] # insert after P103
table_abbr = doc.add_table(rows=len(abbrevs) + 1, cols=2)
table_abbr.alignment = WD_TABLE_ALIGNMENT.CENTER
table_abbr.rows[0].cells[0].text = "Abbreviations"
table_abbr.rows[0].cells[1].text = "Full Form"
format_run(table_abbr.rows[0].cells[0].paragraphs[0].runs[0], font_name="Times New Roman", size_pt=12, bold=True)
format_run(table_abbr.rows[0].cells[1].paragraphs[0].runs[0], font_name="Times New Roman", size_pt=12, bold=True)
set_cell_shading(table_abbr.rows[0].cells[0], "1F2937")
table_abbr.rows[0].cells[0].paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)
set_cell_shading(table_abbr.rows[0].cells[1], "1F2937")
table_abbr.rows[0].cells[1].paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)

for idx, (abbr, full) in enumerate(abbrevs):
    row_cells = table_abbr.rows[idx + 1].cells
    row_cells[0].text = abbr
    row_cells[1].text = full
    format_run(row_cells[0].paragraphs[0].runs[0], font_name="Times New Roman", size_pt=11, bold=True)
    format_run(row_cells[1].paragraphs[0].runs[0], font_name="Times New Roman", size_pt=11)
    set_cell_margins(row_cells[0], 80, 80, 120, 120)
    set_cell_margins(row_cells[1], 80, 80, 120, 120)
    if idx % 2 == 1:
        set_cell_shading(row_cells[0], "F3F4F6")
        set_cell_shading(row_cells[1], "F3F4F6")

# Move the abbreviation table right after P103
p103 = doc.paragraphs[103]
p103._p.addnext(table_abbr._tbl)

# 6. Update Table of Contents
toc_entries = [
    ("1", "Introduction", "1"),
    ("1.1", "Background", "1"),
    ("1.2", "Problem Statement", "2"),
    ("1.3", "Objectives", "2"),
    ("1.4", "Scope of the Microproject", "3"),
    ("2", "System Design and Methodology", "4"),
    ("2.1", "Proposed Approach", "4"),
    ("2.2", "System Architecture", "5"),
    ("2.3", "Modules and Components", "6"),
    ("2.4", "Algorithm and Working Procedure", "8"),
    ("3", "Implementation", "10"),
    ("3.1", "Software and Hardware Requirements", "10"),
    ("3.2", "Tools and Technologies Used", "11"),
    ("3.3", "Dataset and Input Data Specification", "12"),
    ("3.4", "Implementation Details & Code Architecture", "14"),
    ("4", "Results and Discussion", "18"),
    ("4.1", "Results and Analytical Observations", "18"),
    ("4.2", "Performance Analysis", "20"),
    ("4.3", "Security Analysis and Triage", "21"),
    ("4.4", "Screenshots and System Outputs", "22"),
    ("5", "Conclusion and Future Scope", "27"),
    ("6", "References", "28"),
    ("7", "Appendix", "29")
]

# Clean out old TOC placeholder text
for i in range(114, 146):
    if i < len(doc.paragraphs):
        doc.paragraphs[i].text = ""

# Build clean TOC table
toc_table = doc.add_table(rows=len(toc_entries) + 1, cols=3)
toc_table.alignment = WD_TABLE_ALIGNMENT.CENTER
toc_table.rows[0].cells[0].text = "S.No"
toc_table.rows[0].cells[1].text = "Contents / Chapter Title"
toc_table.rows[0].cells[2].text = "Page No"
for c_i in range(3):
    format_run(toc_table.rows[0].cells[c_i].paragraphs[0].runs[0], font_name="Times New Roman", size_pt=12, bold=True)
    set_cell_shading(toc_table.rows[0].cells[c_i], "1F2937")
    toc_table.rows[0].cells[c_i].paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)

for idx, (sno, title, page_no) in enumerate(toc_entries):
    row_c = toc_table.rows[idx + 1].cells
    row_c[0].text = sno
    row_c[1].text = title
    row_c[2].text = page_no
    is_main = "." not in sno
    format_run(row_c[0].paragraphs[0].runs[0], font_name="Times New Roman", size_pt=11, bold=is_main)
    format_run(row_c[1].paragraphs[0].runs[0], font_name="Times New Roman", size_pt=11, bold=is_main)
    format_run(row_c[2].paragraphs[0].runs[0], font_name="Times New Roman", size_pt=11, bold=is_main)
    set_cell_margins(row_c[0], 60, 60, 100, 100)
    set_cell_margins(row_c[1], 60, 60, 100, 100)
    set_cell_margins(row_c[2], 60, 60, 100, 100)
    row_c[2].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.RIGHT

# Move TOC table after P109 (CONTENTS heading)
doc.paragraphs[109]._p.addnext(toc_table._tbl)

print("Front matter formatted and updated.")
doc.save(OUTPUT_PATH)
print(f"Saved checkpoint to {OUTPUT_PATH}")
