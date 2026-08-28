import os
import pandas as pd
import joblib
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.naive_bayes import MultinomialNB

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_curve,
    roc_auc_score
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_PATH = os.path.join(
    BASE_DIR,
    "phishing_email.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "saved_models"
)

EVALUATION_DIR = os.path.join(
    BASE_DIR,
    "evaluation",
    "results"
)

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(EVALUATION_DIR, exist_ok=True)


# ============================================================
# 1. LOAD DATASET
# ============================================================

print("=" * 70)
print("LOADING DATASET")
print("=" * 70)

if not os.path.exists(DATASET_PATH):
    raise FileNotFoundError(
        f"Dataset not found: {DATASET_PATH}"
    )

df = pd.read_csv(DATASET_PATH)

print("Dataset loaded successfully")
print("Total emails:", len(df))

print("\nClass distribution:")
print(df["label"].value_counts())


# ============================================================
# 2. FEATURES AND LABELS
# ============================================================

X = df["text_combined"].fillna("").astype(str)
y = df["label"].astype(int)


# ============================================================
# 3. TRAIN / TEST SPLIT
# ============================================================

print("\n" + "=" * 70)
print("SPLITTING DATASET")
print("=" * 70)

X_train_text, X_test_text, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("Training emails:", len(X_train_text))
print("Testing emails :", len(X_test_text))


# ============================================================
# 4. TF-IDF
# ============================================================

print("\n" + "=" * 70)
print("CREATING TF-IDF FEATURES")
print("=" * 70)

vectorizer = TfidfVectorizer(
    max_features=5000,
    stop_words="english",
    ngram_range=(1, 2)
)

X_train = vectorizer.fit_transform(X_train_text)
X_test = vectorizer.transform(X_test_text)

print("TF-IDF completed")
print("Training feature shape:", X_train.shape)
print("Testing feature shape :", X_test.shape)


# ============================================================
# 5. SAVE VECTORIZER
# ============================================================

vectorizer_path = os.path.join(
    MODEL_DIR,
    "vectorizer.pkl"
)

joblib.dump(
    vectorizer,
    vectorizer_path
)

print("\nVectorizer saved:")
print(vectorizer_path)

print(
    "Vectorizer size:",
    os.path.getsize(vectorizer_path),
    "bytes"
)


# ============================================================
# 6. DEFINE MODELS
# ============================================================

models = {

    "Logistic Regression": LogisticRegression(
        max_iter=1000,
        class_weight="balanced"
    ),

    "Random Forest": RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    ),

    "SVM": LinearSVC(
        class_weight="balanced",
        random_state=42
    ),

    "Naive Bayes": MultinomialNB()

}


# ============================================================
# 7. TRAIN MODELS
# ============================================================

results = {}
trained_models = {}
roc_scores = {}

best_model = None
best_model_name = None
best_f1 = -1


for name, model in models.items():

    print("\n")
    print("=" * 70)
    print("TRAINING:", name)
    print("=" * 70)

    # --------------------------------------------------------
    # TRAIN
    # --------------------------------------------------------

    model.fit(
        X_train,
        y_train
    )

    print("Training completed")

    # --------------------------------------------------------
    # PREDICTION
    # --------------------------------------------------------

    y_pred = model.predict(
        X_test
    )

    # --------------------------------------------------------
    # METRICS
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    # --------------------------------------------------------
    # CONFUSION MATRIX
    # --------------------------------------------------------

    cm = confusion_matrix(
        y_test,
        y_pred
    )

    print("\nConfusion Matrix:")
    print(cm)

    # --------------------------------------------------------
    # CLASSIFICATION REPORT
    # --------------------------------------------------------

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            y_pred,
            target_names=[
                "Legitimate",
                "Phishing"
            ],
            zero_division=0
        )
    )

    # ========================================================
    # SAVE INDIVIDUAL MODEL
    # ========================================================

    MODEL_FILENAMES = {

        "Logistic Regression":
            "logistic_regression.pkl",

        "Random Forest":
            "random_forest.pkl",

        "SVM":
            "svm.pkl",

        "Naive Bayes":
            "naive_bayes.pkl"

    }

    model_filename = MODEL_FILENAMES[name]

    model_path = os.path.join(
        MODEL_DIR,
        model_filename
    )

    print("\nSaving model:")
    print("Model:", name)
    print("Path :", model_path)

    # Remove old file if it exists
    if os.path.exists(model_path):
        try:
            os.remove(model_path)
            print("Old model removed")
        except Exception as e:
            print(
                "Could not remove old model:",
                e
            )

    # Save trained model
    joblib.dump(
        model,
        model_path
    )

    # Verify file
    if not os.path.exists(model_path):
        raise RuntimeError(
            f"Model file was not created: {model_path}"
        )

    model_size = os.path.getsize(
        model_path
    )

    if model_size == 0:
        raise RuntimeError(
            f"Model file is EMPTY: {model_path}"
        )

    print(
        "MODEL SAVED SUCCESSFULLY:",
        model_filename
    )

    print(
        "MODEL SIZE:",
        model_size,
        "bytes"
    )

    # --------------------------------------------------------
    # SAVE RESULTS
    # --------------------------------------------------------

    results[name] = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1
    }

    trained_models[name] = model

    # --------------------------------------------------------
    # SELECT BEST MODEL
    # --------------------------------------------------------

    if f1 > best_f1:

        best_f1 = f1
        best_model = model
        best_model_name = name


# ============================================================
# 8. ROC / AUC
# ============================================================

print("\n")
print("=" * 70)
print("ROC / AUC CALCULATION")
print("=" * 70)

roc_scores = {}

plt.figure(
    figsize=(10, 7)
)

for name, model in trained_models.items():

    # --------------------------------------------------------
    # MODELS WITH PROBABILITY
    # --------------------------------------------------------

    if hasattr(
        model,
        "predict_proba"
    ):

        y_score = model.predict_proba(
            X_test
        )[:, 1]

    # --------------------------------------------------------
    # SVM
    # --------------------------------------------------------

    else:

        y_score = model.decision_function(
            X_test
        )

    fpr, tpr, _ = roc_curve(
        y_test,
        y_score
    )

    auc_score = roc_auc_score(
        y_test,
        y_score
    )

    roc_scores[name] = auc_score

    print(
        f"{name}: AUC = {auc_score:.4f}"
    )

    plt.plot(
        fpr,
        tpr,
        label=f"{name} (AUC = {auc_score:.3f})"
    )


# ------------------------------------------------------------
# RANDOM CLASSIFIER
# ------------------------------------------------------------

plt.plot(
    [0, 1],
    [0, 1],
    linestyle="--",
    label="Random Classifier"
)

plt.xlabel(
    "False Positive Rate"
)

plt.ylabel(
    "True Positive Rate"
)

plt.title(
    "ROC Curve - Phishing Email Detection"
)

plt.legend()

plt.grid(True)

roc_path = os.path.join(
    EVALUATION_DIR,
    "roc_curve.png"
)

plt.savefig(
    roc_path,
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print("\nROC graph saved:")
print(roc_path)


# ============================================================
# 9. SAVE CONFUSION MATRICES
# ============================================================

print("\n")
print("=" * 70)
print("GENERATING CONFUSION MATRICES")
print("=" * 70)


for name, model in trained_models.items():

    y_pred = model.predict(
        X_test
    )

    cm = confusion_matrix(
        y_test,
        y_pred
    )

    plt.figure(
        figsize=(6, 5)
    )

    plt.imshow(
        cm,
        interpolation="nearest"
    )

    plt.title(
        f"Confusion Matrix - {name}"
    )

    plt.colorbar()

    plt.xticks(
        [0, 1],
        [
            "Legitimate",
            "Phishing"
        ]
    )

    plt.yticks(
        [0, 1],
        [
            "Legitimate",
            "Phishing"
        ]
    )

    plt.xlabel(
        "Predicted Label"
    )

    plt.ylabel(
        "Actual Label"
    )

    for i in range(2):

        for j in range(2):

            plt.text(
                j,
                i,
                str(cm[i, j]),
                ha="center",
                va="center"
            )

    plt.tight_layout()

    filename = (
        name.lower()
        .replace(" ", "_")
        .replace("-", "_")
        + "_confusion_matrix.png"
    )

    path = os.path.join(
        EVALUATION_DIR,
        filename
    )

    plt.savefig(
        path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        f"{name} confusion matrix saved"
    )


# ============================================================
# 10. MODEL COMPARISON TABLE
# ============================================================

comparison_data = []

for name in results:

    comparison_data.append({

        "Model": name,

        "Accuracy":
            results[name]["accuracy"],

        "Precision":
            results[name]["precision"],

        "Recall":
            results[name]["recall"],

        "F1":
            results[name]["f1"],

        "ROC_AUC":
            roc_scores[name]

    })


comparison_df = pd.DataFrame(
    comparison_data
)


# ============================================================
# 11. SAVE MODEL COMPARISON CSV
# ============================================================

comparison_csv = os.path.join(
    EVALUATION_DIR,
    "model_comparison.csv"
)

comparison_df.to_csv(
    comparison_csv,
    index=False
)

print("\nModel comparison saved:")
print(comparison_csv)


# ============================================================
# 12. MODEL COMPARISON GRAPH
# ============================================================

plt.figure(
    figsize=(12, 7)
)

x = range(
    len(comparison_df)
)

width = 0.18

plt.bar(
    [i - 1.5 * width for i in x],
    comparison_df["Accuracy"],
    width,
    label="Accuracy"
)

plt.bar(
    [i - 0.5 * width for i in x],
    comparison_df["Precision"],
    width,
    label="Precision"
)

plt.bar(
    [i + 0.5 * width for i in x],
    comparison_df["Recall"],
    width,
    label="Recall"
)

plt.bar(
    [i + 1.5 * width for i in x],
    comparison_df["F1"],
    width,
    label="F1 Score"
)

plt.xticks(
    list(x),
    comparison_df["Model"],
    rotation=20
)

plt.ylabel(
    "Score"
)

plt.xlabel(
    "Machine Learning Model"
)

plt.title(
    "Machine Learning Model Performance Comparison"
)

plt.ylim(
    0,
    1.05
)

plt.legend()

plt.grid(
    axis="y",
    alpha=0.3
)

plt.tight_layout()

comparison_graph = os.path.join(
    EVALUATION_DIR,
    "model_comparison.png"
)

plt.savefig(
    comparison_graph,
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print(
    "Comparison graph saved:"
)

print(
    comparison_graph
)


# ============================================================
# 13. SAVE BEST MODEL
# ============================================================

best_model_path = os.path.join(
    MODEL_DIR,
    "phishing_model.pkl"
)

joblib.dump(
    best_model,
    best_model_path
)

print(
    "\nBest model saved:"
)

print(
    best_model_path
)

print(
    "Best model size:",
    os.path.getsize(best_model_path),
    "bytes"
)


# ============================================================
# 14. VERIFY ALL MODEL FILES
# ============================================================

print("\n")
print("=" * 75)
print("VERIFYING ALL MODEL FILES")
print("=" * 75)

required_models = [
    "logistic_regression.pkl",
    "naive_bayes.pkl",
    "random_forest.pkl",
    "svm.pkl",
    "phishing_model.pkl",
    "vectorizer.pkl"
]

all_models_valid = True

for filename in required_models:

    path = os.path.join(
        MODEL_DIR,
        filename
    )

    if os.path.exists(path):

        size = os.path.getsize(path)

        if size > 0:

            print(
                f"OK   {filename:<30} {size:,} bytes"
            )

        else:

            print(
                f"FAIL {filename:<30} EMPTY"
            )

            all_models_valid = False

    else:

        print(
            f"FAIL {filename:<30} NOT FOUND"
        )

        all_models_valid = False


if not all_models_valid:

    raise RuntimeError(
        "One or more model files are missing or empty."
    )


# ============================================================
# 15. FINAL OUTPUT
# ============================================================

print("\n")
print("=" * 75)
print("FINAL MODEL COMPARISON")
print("=" * 75)

print(
    comparison_df.to_string(
        index=False
    )
)


print("\n")
print("=" * 75)
print("BEST MODEL")
print("=" * 75)

print(
    "Best Model:",
    best_model_name
)

print(
    f"Best F1 Score: {best_f1 * 100:.2f}%"
)

print(
    f"Best ROC-AUC: "
    f"{roc_scores[best_model_name]:.4f}"
)

print("\nBest model saved as:")
print(best_model_path)

print("\n")
print("=" * 75)
print("ALL 4 INDIVIDUAL MODELS SAVED SUCCESSFULLY")
print("=" * 75)

print(
    "Logistic Regression : saved"
)

print(
    "Random Forest       : saved"
)

print(
    "SVM                 : saved"
)

print(
    "Naive Bayes         : saved"
)

print("\n")
print("=" * 75)
print("TRAINING + EVALUATION COMPLETED")
print("=" * 75)