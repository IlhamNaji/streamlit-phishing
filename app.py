import streamlit as st
import pickle
import pandas as pd
import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import socket
import matplotlib.pyplot as plt

# =========================
# LOAD MODEL
# =========================
model = pickle.load(open("model.pkl", "rb"))
columns = pickle.load(open("columns.pkl", "rb"))

# =========================
# CONFIG PAGE
# =========================
st.set_page_config(
    page_title="Phishing Detection System",
    page_icon="🔍",
    layout="wide"
)

# =========================
# HEADER
# =========================
st.title("🔍 Sistem Deteksi Website Phishing")
st.markdown("""
Aplikasi ini menggunakan algoritma **LightGBM** untuk mendeteksi apakah sebuah URL tergolong phishing atau tidak berdasarkan analisis fitur URL, domain, dan konten website.
""")

# =========================
# INPUT
# =========================
url = st.text_input("Masukkan URL Website")

# =========================
# FEATURE EXTRACTION
# =========================
def extract_features(url):
    data = {col: 0 for col in columns}
    parsed = urlparse(url)

    data["URLURL_Length"] = len(url)
    data["having_At_Symbol"] = 1 if "@" in url else 0
    data["HTTPS_token"] = 1 if "https" in url else 0
    data["having_IPv4_address"] = 1 if re.match(r"\d+\.\d+\.\d+\.\d+", parsed.netloc) else 0
    data["having_Sub_Domain"] = 1 if parsed.netloc.count('.') > 2 else 0
    data["Prefix_Suffix"] = 1 if '-' in parsed.netloc else 0

    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        data["Request_URL"] = len(soup.find_all('img'))
        data["URL_of_Anchor"] = len(soup.find_all('a'))
        data["Links_in_tags"] = len(soup.find_all(['link','script']))
        data["Favicon"] = 1 if soup.find("link", rel="icon") else 0
    except:
        pass

    try:
        socket.gethostbyname(parsed.netloc)
        data["DNSRecord"] = 1
    except:
        data["DNSRecord"] = 0

    return pd.DataFrame([data])

# =========================
# ANALISIS
# =========================
if st.button("🔍 Analisis Sekarang"):
    if url:
        df_input = extract_features(url)
        df_input = df_input[columns]

        pred = model.predict(df_input)[0]
        proba = model.predict_proba(df_input)[0]

        phishing_prob = round(proba[1] * 100, 2)
        safe_prob = round(proba[0] * 100, 2)

        # =========================
        # STATUS LEVEL
        # =========================
        if phishing_prob < 30:
            status = "AMAN"
            warna = "green"
        elif phishing_prob < 70:
            status = "WASPADA"
            warna = "orange"
        else:
            status = "PHISHING"
            warna = "red"

        # =========================
        # HASIL UTAMA
        # =========================
        st.subheader("📊 Hasil Analisis")

        col1, col2 = st.columns(2)

        with col1:
            st.metric("Risiko Phishing", f"{phishing_prob}%")
            st.progress(int(phishing_prob))

        with col2:
            st.metric("Status Website", status)

        # =========================
        # CHART
        # =========================
        st.subheader("📈 Probabilitas")
        chart_data = pd.DataFrame({
            "Kategori": ["Aman", "Phishing"],
            "Persentase": [safe_prob, phishing_prob]
        })
        st.bar_chart(chart_data.set_index("Kategori"))

        # =========================
        # DETAIL FITUR
        # =========================
        st.subheader("🧾 Detail Analisis")

        features = df_input.iloc[0]

        if features["having_At_Symbol"] == 1:
            st.warning("URL mengandung simbol @")

        if features["URLURL_Length"] > 75:
            st.warning("URL terlalu panjang")

        if features["Prefix_Suffix"] == 1:
            st.warning("Domain mengandung '-'")

        if features["HTTPS_token"] == 0:
            st.warning("Tidak menggunakan HTTPS")

        # =========================
        # FEATURE IMPORTANCE
        # =========================
        st.subheader("🧠 Feature Importance")

        importances = model.feature_importances_

        feat_df = pd.DataFrame({
            "Fitur": columns,
            "Nilai": importances
        }).sort_values(by="Nilai", ascending=False).head(10)

        fig, ax = plt.subplots()
        ax.barh(feat_df["Fitur"], feat_df["Nilai"])
        ax.invert_yaxis()

        st.pyplot(fig)

    else:
        st.warning("Masukkan URL terlebih dahulu!")