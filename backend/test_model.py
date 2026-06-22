import joblib

model = joblib.load("saved_models/phishing_model.pkl")

print(type(model))
print(model)