# 📦 fastapi-redaction

> **Automatic secret & sensitive-data redaction for FastAPI (logs, headers, responses)**  
> Prevent AWS keys, Okta tokens, DB passwords, SFTP credentials, SharePoint secrets, JWT secrets, and any sensitive values from leaking into logs or API responses — without modifying your FastAPI endpoint code.

---
<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-Compatible-brightgreen?logo=fastapi" />
  <img src="https://img.shields.io/badge/Security-Focused-red?logo=security" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?logo=open-source-initiative" />
  <img src="https://img.shields.io/pypi/v/fastapi-redaction.svg?logo=pypi" />
  <img src="https://img.shields.io/github/stars/yourusername/fastapi-redaction?style=social" />
</p>

<p align="center">
  <img src="https://media.giphy.com/media/l0Exk8EUzSLsrErEQ/giphy.gif" width="400" alt="Data Security Animation"/>
</p>
---

## 🚨 Why this package exists

FastAPI applications often log or return sensitive information during:

- 🐞 Debugging  
- ⚠️ Exception handling  
- 🔄 Background tasks  
- 📜 Request logging  
- 🛡 Middleware traces  
- 📤 API responses  

This can unintentionally expose:

- 🔑 AWS access keys  
- 🔐 Okta API tokens  
- 🔑 SFTP / SSH passwords  
- 📂 SharePoint / MS Graph secrets  
- 🗄 Database passwords  
- 🔒 JWT secrets & signing keys  
- 🌍 Third-party API keys  

👉 This library **fully prevents such leaks** by automatically redacting secrets at multiple layers.

---

## ✨ Features

- 🔥 **Full-stack secret masking**  
  Redacts secrets from JSON responses, headers, logs, and any string containing sensitive substrings.

- 🔍 **Automatic secret discovery**  
  Detects environment variables like `*_SECRET`, `*_KEY`, `*_TOKEN`, `*_PASSWORD`, `CREDENTIAL`, `PRIVATE_KEY`.

- 🧠 **Substring-based masking**  
  Any secret value is replaced with: `REDACTED`.

- 🛡 **Configurable JSON key masking**  
  Force-hide fields such as: `password`, `token`, `secret`, `api_key`, `session`.

- 💨 **Zero changes to your API endpoints**  
  Just one line:  
  ```python
  redaction.init_app(app)
  ```

## 📥 Installation
  ```python
   pip install fastapi-redaction
  ```

## 🚀 Quick Start Example

  ```python
   python -m build   
  ```

  ```python
   pip install dist/fastapi_redaction-0.1.0-py3-none-any.whl    
  ```

  ```python
   python .\example_app.py   
  ```


## ⚙️ Advanced Usage

🔧 Explicit environment variables

  ```python
    config = RedactionConfig(
        explicit_env_keys=[
            "SFTP_PASSWORD",
            "SHAREPOINT_CLIENT_SECRET",
            "MY_SERVICE_TOKEN",
        ]
    )
  ```

## 🔐 Security Notes

This package prevents secret leakage to:

- 🌐 API clients  
- 🖥 Browser DevTools  
- ☁️ Cloud logs  
- 🔄 Reverse proxies  
- 🤖 AI tools in IDEs (Copilot, Cursor, Windsurf)  
- 💻 Local console output  

⚠️ It does **not** modify your internal logic — handlers still receive the real values.
