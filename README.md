 Phishing Email Detection using RAG + OpenAI

This project is a Phishing Email Detection System built using  
Retrieval-Augmented Generation (RAG), OpenAI Embeddings, and Gradio UI.

It analyzes email text and detects whether the message is:
-  Safe  
-  Suspicious  
-  Phishing Attempt  

The system also provides:
-  Reasoning about why the email is suspicious
-  Evidence from similar phishing examples (via vector search)
-  A chat-style interface to ask questions about emails

 Features

1. RAG-powered detection
The system uses a dataset of sample phishing emails and embeds them using the OpenAI API.  
When a new email is submitted, similar examples are retrieved for context.

2. Gradio Web Interface
A clean and simple interface:

- Input email content
- Receive classification + explanation
- See similar phishing emails
- Chat-based interaction

3. Email history
You can store analysis results in a JSON file (`email_chat_history.json`).

4. Custom dataset support
You can add more phishing or legitimate emails to improve accuracy.

Project Structure

