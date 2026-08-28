🚀 How the Software Works
1. User submits data

The user can submit:

📧 Email

The system accepts email content and analyzes it for phishing indicators.

🔗 URL

The system analyzes a URL and extracts security-related characteristics.

2. Email Processing

The email processing module analyzes the submitted email.

It performs operations such as:

Text preprocessing
Feature extraction
Suspicious keyword analysis
Phishing classification
Model prediction

The processed email is passed to the Machine Learning model.

3. URL Feature Extraction

For URL-based detection, the system extracts different characteristics from the URL.

Examples include:

URL length
Number of special characters
Number of dots
Number of subdomains
Presence of suspicious patterns
Domain characteristics
HTTPS-related information
IP address usage
Lookalike domain indicators

These features are used to determine whether a URL appears legitimate or suspicious.

🤖 Machine Learning Models

One of the major parts of this project is the implementation and comparison of multiple Machine Learning algorithms.

The project includes four ML models:

1. Logistic Regression

Logistic Regression is used as a classification model for determining whether the input belongs to the phishing or legitimate category.

It provides a strong baseline for binary classification.

2. Naive Bayes

Naive Bayes is a probabilistic classification algorithm.

It is particularly useful for text-based classification problems such as phishing email detection.

The model estimates the probability of an email belonging to a phishing or legitimate class based on the extracted features.

3. Random Forest

Random Forest is an ensemble Machine Learning algorithm consisting of multiple decision trees.

It helps identify complex relationships between phishing-related features and provides robust classification performance.

4. Support Vector Machine (SVM)

Support Vector Machine is a supervised learning algorithm that attempts to find an optimal decision boundary between different classes.

It is used in this project for phishing classification and model comparison.

📊 Model Comparison

The project does not depend on a single Machine Learning model.

Multiple models are trained and evaluated to compare their performance.

The models evaluated are:

Model	Purpose
Logistic Regression	Phishing classification
Naive Bayes	Text-based classification
Random Forest	Ensemble classification
SVM	Classification and boundary detection

The project contains evaluation results including:

Accuracy
Classification reports
Confusion matrices
ROC curves
Model comparison
Performance visualization
📈 Model Evaluation

The project includes an evaluation module to understand how well the trained models perform.

Evaluation outputs include:

Confusion Matrix

A confusion matrix is used to analyze:

True Positives
True Negatives
False Positives
False Negatives

This helps understand how accurately the model identifies phishing and legitimate samples.

ROC Curve

ROC curves are generated to evaluate the classification capability of the models.

The project also contains ROC-related evaluation data.

Classification Report

Classification reports are generated for the individual models.

They provide metrics such as:

Precision
Recall
F1-score
Support
Model Performance Comparison

The project generates comparison results between:

Logistic Regression
Naive Bayes
Random Forest
SVM

This allows the performance of different approaches to be studied instead of relying on only one model.

🧠 Risk Fusion

The project also contains a Risk Fusion Engine.

Instead of relying only on one prediction, different security signals can be combined to determine the overall risk.

The system considers multiple analysis components such as:

ML Prediction
      +
URL Analysis
      +
Threat Intelligence
      +
Domain Analysis
      +
Lookalike Detection
      ↓
Risk Fusion
      ↓
Final Risk Score
      ↓
Threat Level

The final result can contain:

Prediction
Risk Score
Threat Level
⚠️ Threat Levels

The system categorizes detected threats into different levels.

🟢 LOW

The input appears to have a relatively low level of suspicious activity.

🟡 MEDIUM

The input contains suspicious characteristics that require attention.

🔴 HIGH

The input contains strong phishing or malicious indicators.

🌐 Threat Intelligence

The project also contains a Threat Intelligence component.

The purpose of this module is to support the detection process using security-related intelligence and indicators.

This provides an additional layer beyond the Machine Learning prediction.

🔍 Domain Analysis

The system contains domain analysis functionality for examining domain-related characteristics.

This helps identify suspicious domains and contributes to the overall security analysis.

🎭 Lookalike Domain Detection

Attackers often create domains that look similar to legitimate websites.

For example:

legitimate-site.com
leg1timate-site.com
legitimate-site-security.com

The project includes a lookalike detection component to identify suspicious domain similarities.

📊 Dashboard

The React frontend provides an interactive cybersecurity dashboard.

The dashboard includes components for:

📧 Email Analysis
🔗 URL Analysis
📜 Scan History
📊 Threat Charts
📈 Threat Trend Analysis
🤖 Model Performance
📋 Model Evaluation
🔬 Model Analysis
⚠️ Risk Information
📜 Scan History

Every scan can be recorded and displayed in the Recent Threat Activity section.

The history contains information such as:

Field	Description
ID	Unique scan identifier
Scan Type	Email or URL
Prediction	Phishing or Safe
Threat Level	LOW / MEDIUM / HIGH
Risk Score	Calculated percentage
Timestamp	Time of scan

The dashboard also provides:

Export Scan History
Clear Scan History
📥 Export Reports

The system provides an option to export scan history as a CSV report.

The exported report contains information such as:

Scan ID
Scan type
Original content
Prediction
Threat level
Risk score
Scan time
🛠️ Technologies Used
Frontend
React.js
JavaScript
HTML
CSS
Vite
Axios
Socket.IO Client
React Icons
Backend
Python
Flask
Flask-SocketIO
Machine Learning
Scikit-learn
Logistic Regression
Naive Bayes
Random Forest
Support Vector Machine
Data Processing
Python
Pandas
NumPy
Database
SQLite / configured project database
Development Tools
VS Code
Git
GitHub
Postman
Browser Developer Tools
