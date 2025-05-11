import re
import fitz  # PyMuPDF
import pandas as pd
from fpdf import FPDF
from io import BytesIO
import streamlit as st
import base64


def detect_emails(text):
    return re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text)

def detect_credit_cards(text):
    return re.findall(r"\b(?:\d[ -]*?){13,16}\b", text)

def detect_national_ids(text):
    return re.findall(r"\b(1|2)\d{9}\b", text)

def detect_passwords(text):
    common_patterns = ["password", "123456", "qwerty", "letmein", "admin"]
    return [pw for pw in common_patterns if pw in text.lower()]

def analyze_text(text):
    result = {
        "Emails": detect_emails(text),
        "Credit Cards": detect_credit_cards(text),
        "National IDs": detect_national_ids(text),
        "Weak Passwords": detect_passwords(text)
    }
    severity = "Low"
    if result["Credit Cards"] or result["National IDs"]:
        severity = "High"
    elif result["Emails"] or result["Weak Passwords"]:
        severity = "Medium"
    result["Severity"] = severity
    return result

def extract_text_from_pdf(file):
    doc = fitz.open(stream=file.read(), filetype="pdf")
    text = ""
    for page in doc:
        text += page.get_text()
    return text

def extract_text_from_excel(file):
    df = pd.read_excel(file, engine='openpyxl')
    return df.astype(str).to_string(index=False)

def generate_pdf_report(result_dict):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Data Leak Report", ln=True, align="C")
    pdf.ln(10)

    for key, values in result_dict.items():
        if isinstance(values, list):
            pdf.set_font("Arial", 'B', size=12)
            pdf.cell(200, 10, txt=f"{key}:", ln=True)
            pdf.set_font("Arial", size=12)
            if values:
                for v in values:
                    pdf.multi_cell(0, 10, f"- {v}")
            else:
                pdf.cell(200, 10, txt="- None", ln=True)
            pdf.ln(5)
        else:
            pdf.set_font("Arial", 'B', size=12)
            pdf.cell(200, 10, txt=f"{key}: {values}", ln=True)

    return pdf.output(dest='S').encode('latin-1', errors='ignore')


def generate_excel_report(result_dict):
    df = pd.DataFrame([(k, v if isinstance(v, list) else [v]) for k, v in result_dict.items()],
                      columns=["نوع التسريب", "القيم"])
    expanded_rows = []
    for _, row in df.iterrows():
        for value in row["القيم"]:
            expanded_rows.append({"نوع التسريب": row["نوع التسريب"], "القيمة": value})
    result_df = pd.DataFrame(expanded_rows)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        result_df.to_excel(writer, index=False, sheet_name="التقرير")
    output.seek(0)
    return output

# ============ Streamlit ============
st.set_page_config(page_title="Leak Detector  M7MAD", layout="centered")
st.markdown("""
    <style>
    .reportview-container {
        background: #f4f4f4;
    }
    .stButton > button {
        background-color: #ff4b4b;
        color: white;
        font-weight: bold;
        border-radius: 8px;
        padding: 10px 20px;
    }
    .stTextInput > div > input {
        font-size: 16px;
    }
    .stMarkdown h4 {
        font-weight: bold;
    }
    </style>
""", unsafe_allow_html=True)

st.image("https://cdn-icons-png.flaticon.com/512/4712/4712035.png", width=120)
st.title("Leak Detector 🔐 - M7MAD ")
st.caption("Cybersecurity made smarter. Scan text, PDF, or Excel for leaks.")

option = st.radio("Choose input type:", ["Upload File", "Direct Text"])
text = ""
uploaded_file = None

if option == "Upload File":
    uploaded_file = st.file_uploader("Upload a TXT, PDF, or XLSX file", type=["txt", "pdf", "xlsx"])
    if uploaded_file:
        file_type = uploaded_file.name.split(".")[-1].lower()
        if file_type == "txt":
            text = uploaded_file.read().decode("utf-8")
        elif file_type == "pdf":
            text = extract_text_from_pdf(uploaded_file)
        elif file_type == "xlsx":
            text = extract_text_from_excel(uploaded_file)
elif option == "Direct Text":
    text = st.text_area("Paste text here:", height=200)

if text:
    result = analyze_text(text)
    severity_color = {
        "High": "#ff4b4b",
        "Medium": "#ffa534",
        "Low": "#3adb76"
    }
    st.markdown(f"<h4 style='color:{severity_color[result['Severity']]};'>Severity Level: {result['Severity']}</h4>", unsafe_allow_html=True)

    st.subheader("Leak Results:")
    for key, value in result.items():
        if key != "Severity":
            st.write(f"**{key}**: {value if value else 'None'}")

    pdf_bytes = generate_pdf_report(result)
    b64_pdf = base64.b64encode(pdf_bytes).decode()
    href_pdf = f'<a href="data:application/octet-stream;base64,{b64_pdf}" download="leak_report.pdf">⬇️ Download PDF Report</a>'
    st.markdown(href_pdf, unsafe_allow_html=True)

    excel_bytes = generate_excel_report(result)
    b64_excel = base64.b64encode(excel_bytes.read()).decode()
    href_excel = f'<a href="data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,{b64_excel}" download="leak_report.xlsx">⬇️ Download Excel Report</a>'
    st.markdown(href_excel, unsafe_allow_html=True)
else:
    st.info("Please provide text or upload a file to start scanning.")


# Footer
st.markdown("---")
st.markdown("<p style='text-align: center; color: grey;'>Developed by محمد 🚀 </p>", unsafe_allow_html=True)

