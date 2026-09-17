import pandas as pd
import re
from urllib.parse import urlparse

df = pd.read_csv("data/processed/combined_dataset.csv")

def get_hostname(url):
    try:
        u = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "http://" + url
        return urlparse(u).hostname or ""
    except Exception:
        return ""

df["hostname"] = df["url"].astype(str).apply(get_hostname)
no_dot = df[~df["hostname"].str.contains(r"\.", regex=True, na=False)]

print(len(no_dot))
print(no_dot[["url", "label", "source"]].sample(min(10, len(no_dot)), random_state=1).to_string())