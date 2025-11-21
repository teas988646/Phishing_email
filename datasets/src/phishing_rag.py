# email_rag_local.py
import os
import csv
import json
import logging
import schedule
import time
import threading
import gradio as gr
import re
from typing import List, Any

# ---- Logging Setup ----
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S"
)

# ---- CSV + Email Patterns Index ----
CSV_FILE = "phishing_examples.csv"
email_index = {}

def ensure_csv_exists():
    if not os.path.exists(CSV_FILE):
        logging.warning("CSV not found — creating a sample phishing CSV.")
        with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["id", "subject", "body", "indicator"])
            writer.writerow(["E001", "Your account has been suspended", 
                             "Click this link to restore your account: http://malicious.example/login", 
                             "Suspicious link"])
            writer.writerow(["E002", "Urgent: Verify your payment info", 
                             "Provide your bank details now or we'll close your account", 
                             "Sensitive info request"])
            writer.writerow(["E003", "Congratulations! You won a gift card", 
                             "Claim your prize by clicking here", 
                             "Unsolicited reward"])

def load_csv():
    ensure_csv_exists()
    global email_index
    try:
        with open(CSV_FILE, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            parsed = {}
            for r in reader:
                if not r:
                    continue
                eid = r.get("id")
                subject = r.get("subject") or ""
                body = r.get("body") or ""
                indicator = r.get("indicator") or ""
                if eid:
                    parsed[eid.strip()] = {
                        "subject": subject.strip(),
                        "body": body.strip(),
                        "indicator": indicator.strip()
                    }
            email_index = parsed
            logging.info("📄 Loaded %d phishing email rows from CSV.", len(email_index))
    except Exception as e:
        logging.error("❌ Failed to load CSV: %s", e)
        email_index = {}

def update_index():
    logging.info("🔄 Rebuilding local CSV index...")
    load_csv()
    logging.info("✅ Index ready. Entries: %d", len(email_index))

# ---- Persistent Chat History ----
HISTORY_FILE = "email_chat_history.json"

def normalize_history(raw: Any) -> List[List[str]]:
    if not raw:
        return []
    out = []
    if isinstance(raw, list):
        if all(isinstance(x, dict) and 'role' in x and 'content' in x for x in raw):
            pair = []
            for msg in raw:
                role = msg.get("role")
                text = str(msg.get("content", ""))
                if role == "user":
                    pair = [text, ""]
                elif role in ("assistant", "system"):
                    if pair:
                        pair[1] = text
                        out.append(pair)
                        pair = []
            return out
        for item in raw:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                out.append([str(item[0]), str(item[1])])
            elif isinstance(item, dict):
                if 'user' in item and 'assistant' in item:
                    out.append([str(item['user']), str(item['assistant'])])
                elif 'question' in item and 'answer' in item:
                    out.append([str(item['question']), str(item['answer'])])
    return out

def load_history() -> List[List[str]]:
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        norm = normalize_history(raw)
        logging.info("📚 Loaded %d history entries", len(norm))
        return norm
    except Exception as e:
        logging.warning("⚠️ Failed to load history: %s. Starting fresh.", e)
        return []

def save_history(history: List[List[str]]):
    try:
        out = [{"user": h[0], "assistant": h[1] if len(h) > 1 else ""} for h in history]
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error("❌ Failed to save history: %s", e)

# ---- Local LLM Simulator ----
def simple_similarity(a: str, b: str) -> float:
    wa = set(re.findall(r"\w+", a.lower()))
    wb = set(re.findall(r"\w+", b.lower()))
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / max(1, len(wa | wb))

def analyze_email_local(email_text: str, top_k_context: int = 5) -> str:
    # same logic as your original function
    text = email_text or ""
    text_lower = text.lower()
    indicators = []
    score = 0

    # Suspicious patterns
    patterns = {
        "link": r"https?://|www\.",
        "suspicious_words": r"\b(verify|confirm|urgent|suspend|suspended|password|bank|account|billing|verify your|click here|update|login|wire transfer)\b",
        "amounts": r"\b\d{3,}\b|\$\d+",
        "attachment": r"\b(attachment|attached|pdf|docx|invoice)\b",
        "greeting_generic": r"\b(dear user|dear customer|valued customer)\b"
    }

    if re.search(patterns["link"], text_lower): indicators.append("Contains external link(s)"); score += 3
    if re.search(patterns["suspicious_words"], text_lower): indicators.append("Contains suspicious action words"); score += 2
    if re.search(patterns["amounts"], text_lower): indicators.append("Mentions amounts or unusual numbers"); score += 1
    if re.search(patterns["attachment"], text_lower): indicators.append("Mentions an attachment"); score += 1
    if re.search(patterns["greeting_generic"], text_lower): indicators.append("Generic greeting"); score += 1

    # similarity check
    sims = []
    for eid, v in email_index.items():
        combined = f"{v.get('subject','')} {v.get('body','')}"
        sim = simple_similarity(text, combined)
        sims.append((eid, sim, v))
    sims_sorted = sorted(sims, key=lambda x: x[1], reverse=True)[:top_k_context]
    similar_msgs = []
    for eid, sim, v in sims_sorted:
        if sim > 0.15:
            similar_msgs.append(f"{eid} (sim={sim:.2f}): {v.get('indicator','')}")
            score += int(sim * 3)

    # risk
    if score >= 6: risk = "HIGH"
    elif score >= 3: risk = "MEDIUM"
    else: risk = "LOW"

    # actions
    actions = []
    if "Contains external link(s)" in indicators: actions.append("Do not click links. Inspect carefully.")
    if "Contains suspicious action words" in indicators: actions.append("Do not provide sensitive info. Verify sender.")
    if "Mentions an attachment" in indicators: actions.append("Do not open attachments. Scan safely.")
    if "Generic greeting" in indicators: actions.append("Generic greeting may indicate phishing.")
    if not actions: actions.append("No immediate danger detected; stay cautious.")

    # summary
    summary_lines = ["📌 Phishing Analysis (Local Simulator)", f"Risk level: **{risk}** (score={score})"]
    if indicators: summary_lines.append("\nDetected indicators:"); summary_lines += [f"  {i+1}. {ind}" for i, ind in enumerate(indicators)]
    else: summary_lines.append("\nDetected indicators: None obvious (heuristic scan)")
    if similar_msgs: summary_lines.append("\nSimilar known examples from CSV:"); summary_lines += [f"  - {s}" for s in similar_msgs]
    summary_lines.append("\nRecommended actions:"); summary_lines += [f"  {i+1}. {a}" for i, a in enumerate(actions)]

    if risk=="HIGH": verdict="\nVERDICT: Likely phishing. Do not interact."
    elif risk=="MEDIUM": verdict="\nVERDICT: Possibly phishing. Verify before interacting."
    else: verdict="\nVERDICT: Low immediate signs; stay cautious."
    summary_lines.append(verdict)

    return "\n".join(summary_lines)

# ---- Gradio streaming generator ----
def query_generator(user_input: str, chat_history: List[List[str]]):
    history = normalize_history(chat_history or [])
    history.append([user_input, ""])
    yield history, history, ""

    answer = analyze_email_local(user_input)
    typed = ""
    for ch in answer:
        typed += ch
        history[-1][1] = typed
        yield history, history, ""
        time.sleep(0.005)  # streaming effect

    save_history(history)
    yield history, history, ""

# ---- Scheduler (optional) ----
def scheduler_thread():
    try:
        import schedule
        schedule.every().day.at("02:00").do(update_index)
    except Exception as e:
        logging.warning("Scheduler setup failed: %s", e)
    while True:
        try:
            schedule.run_pending()
        except Exception as e:
            logging.warning("Scheduler run_pending error: %s", e)
        time.sleep(60)

# ---- Gradio UI ----
def launch_ui():
    update_index()
    initial_history = load_history()

    with gr.Blocks(title="Email Phishing RAG Bot (Local Simulator)") as demo:
        gr.Markdown("## 📧 Email Phishing Detection Bot (Local)")
        chatbot = gr.Chatbot(value=initial_history)
        inp = gr.Textbox(placeholder="Paste email content here...")
        ask_btn = gr.Button("Analyze")
        clear_btn = gr.Button("Clear Chat")

        ask_btn.click(fn=query_generator, inputs=[inp, chatbot], outputs=[chatbot, chatbot, inp])
        inp.submit(fn=query_generator, inputs=[inp, chatbot], outputs=[chatbot, chatbot, inp])

        def clear_history():
            save_history([])
            return []

        clear_btn.click(fn=clear_history, outputs=chatbot)

    demo.queue()
    demo.launch(server_name="0.0.0.0", share=True)

# ---- Main ----
if __name__ == "__main__":
    logging.info("🚀 Starting Email Phishing Bot (Local Simulator)...")
    t = threading.Thread(target=scheduler_thread, daemon=True)
    t.start()
    launch_ui()
