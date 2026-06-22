import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

print("Loading dataset...")

df = pd.read_csv("phishing_email.csv")

print("Dataset loaded successfully")
print("Total Rows:", len(df))

# Features and Labels
X = df["text_combined"]
y = df["label"]

print("Creating TF-IDF features...")

vectorizer = TfidfVectorizer(
    max_features=5000,
    stop_words="english"
)

X_vectorized = vectorizer.fit_transform(X)

print("TF-IDF completed")

# Train/Test Split
print("Splitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X_vectorized,
    y,
    test_size=0.2,
    random_state=42
)

print("Dataset split completed")

# Random Forest Model
print("Training Random Forest Model...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("Model training completed")

# Prediction
print("Testing model...")

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print(f"\nModel Accuracy: {accuracy * 100:.2f}%")

# Save Model
print("Saving model...")

joblib.dump(model, "saved_models/phishing_model.pkl")
joblib.dump(vectorizer, "saved_models/vectorizer.pkl")

print("Model Saved Successfully!")