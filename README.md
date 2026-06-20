# 🛡️ Phishing Website Detector

A machine learning web app that detects whether a website URL is phishing or legitimate.

## 🔗 Live Demo
[Coming soon - Render deployment]

## 🛠️ Tech Stack
- Python
- Flask
- Scikit-learn (Random Forest + Decision Tree)
- Pandas
- BeautifulSoup

## 🧠 How it works
- Extracts 56 features from any URL instantly
- Features include URL length, special characters, domain structure, phishing keywords
- Random Forest model achieves 90.99% accuracy
- Decision Tree model achieves 87.62% accuracy

## 📊 Models Compared
| Model | Accuracy |
|---|---|
| Random Forest | 90.99% |
| Decision Tree | 87.62% |

## ▶️ Run Locally
pip install -r requirements.txt
python app.py
