import React, { useState } from "react";
import "./ModelEvaluation.css";

const BACKEND_URL = "http://localhost:5000";

const models = [
  {
    name: "Logistic Regression",
    key: "logistic_regression",
    accuracy: 97.98,
    precision: 97.91,
    recall: 98.22,
    f1: 98.06,
    auc: 0.9977,
    confusionMatrix:
      "/saved_models/evaluation/logistic_regression_confusion_matrix.png",
  },
  {
    name: "Naive Bayes",
    key: "naive_bayes",
    accuracy: 95.41,
    precision: 98.33,
    recall: 92.75,
    f1: 95.46,
    auc: 0.9943,
    confusionMatrix:
      "/saved_models/evaluation/naive_bayes_confusion_matrix.png",
  },
  {
    name: "SVM",
    key: "svm",
    accuracy: 98.38,
    precision: 98.37,
    recall: 98.51,
    f1: 98.44,
    auc: 0.9985,
    confusionMatrix:
      "/saved_models/evaluation/svm_confusion_matrix.png",
  },
  {
    name: "Random Forest",
    key: "random_forest",
    accuracy: 98.55,
    precision: 98.52,
    recall: 98.69,
    f1: 98.61,
    auc: 0.9985,
    confusionMatrix:
      "/saved_models/evaluation/random_forest_confusion_matrix.png",
  },
];

function ModelEvaluation() {
  const [selectedModel, setSelectedModel] = useState(null);

  return (
    <div className="model-evaluation-container">

      {/* HEADER */}
      <div className="evaluation-header">
        <div>
          <h2>ML Model Analysis</h2>
          <p>
            Compare the performance of all trained phishing detection models.
          </p>
        </div>

        <div className="best-model-badge">
          🏆 Best Model: Random Forest
        </div>
      </div>

      {/* MODEL CARDS */}
      <div className="model-cards">

        {models.map((model) => (
          <div
            key={model.key}
            className={`model-card ${
              selectedModel?.key === model.key ? "selected" : ""
            }`}
            onClick={() => setSelectedModel(model)}
          >

            <div className="model-card-top">
              <div className="model-icon">
                {model.key === "random_forest"
                  ? "🌲"
                  : model.key === "svm"
                  ? "⚡"
                  : model.key === "naive_bayes"
                  ? "🧠"
                  : "📊"}
              </div>

              {model.key === "random_forest" && (
                <span className="best-tag">BEST</span>
              )}
            </div>

            <h3>{model.name}</h3>

            <div className="main-score">
              <span>{model.accuracy}%</span>
              <small>Accuracy</small>
            </div>

            <div className="mini-metrics">

              <div>
                <span>Precision</span>
                <strong>{model.precision}%</strong>
              </div>

              <div>
                <span>Recall</span>
                <strong>{model.recall}%</strong>
              </div>

              <div>
                <span>F1 Score</span>
                <strong>{model.f1}%</strong>
              </div>

              <div>
                <span>ROC-AUC</span>
                <strong>{model.auc}</strong>
              </div>

            </div>

            <button className="view-analysis-btn">
              View Full Analysis →
            </button>

          </div>
        ))}

      </div>

      {/* SELECTED MODEL */}
      {selectedModel && (
        <div className="model-details">

          <div className="details-header">

            <div>
              <span className="details-label">
                SELECTED MODEL
              </span>

              <h2>{selectedModel.name}</h2>

              <p>
                Detailed evaluation results for the selected phishing
                detection model.
              </p>
            </div>

            <button
              className="close-details"
              onClick={() => setSelectedModel(null)}
            >
              ✕
            </button>

          </div>

          {/* METRIC CARDS */}
          <div className="metric-cards">

            <div className="metric-card">
              <span>Accuracy</span>
              <strong>{selectedModel.accuracy}%</strong>
            </div>

            <div className="metric-card">
              <span>Precision</span>
              <strong>{selectedModel.precision}%</strong>
            </div>

            <div className="metric-card">
              <span>Recall</span>
              <strong>{selectedModel.recall}%</strong>
            </div>

            <div className="metric-card">
              <span>F1 Score</span>
              <strong>{selectedModel.f1}%</strong>
            </div>

            <div className="metric-card">
              <span>ROC-AUC</span>
              <strong>{selectedModel.auc}</strong>
            </div>

          </div>

          {/* CONFUSION MATRIX */}
          <div className="chart-card">

            <div className="chart-title">
              <h3>Confusion Matrix</h3>
              <p>
                Actual vs predicted phishing email classification
              </p>
            </div>

            <div className="image-container">
              <img
                src={`${BACKEND_URL}${selectedModel.confusionMatrix}`}
                alt={`${selectedModel.name} Confusion Matrix`}
              />
            </div>

          </div>

          {/* ROC CURVE */}
          <div className="chart-card">

            <div className="chart-title">
              <h3>ROC Curve</h3>
              <p>
                Receiver Operating Characteristic and AUC performance
              </p>
            </div>

            <div className="image-container">
              <img
                src={`${BACKEND_URL}/saved_models/evaluation/roc_curve_all_models.png`}
                alt="ROC Curve - All Models"
              />
            </div>

          </div>

          {/* MODEL PERFORMANCE */}
          <div className="chart-card">

            <div className="chart-title">
              <h3>Model Performance Comparison</h3>
              <p>
                Accuracy, precision, recall and F1-score comparison
              </p>
            </div>

            <div className="image-container">
              <img
                src={`${BACKEND_URL}/saved_models/evaluation/model_performance_comparison.png`}
                alt="Model Performance Comparison"
              />
            </div>

          </div>

          {/* EXPLANATION */}
          <div className="analysis-summary">

            <h3>Model Interpretation</h3>

            {selectedModel.key === "random_forest" && (
              <p>
                Random Forest is the best performing model in this evaluation.
                It achieved 98.55% accuracy, 98.69% recall, 98.61% F1-score
                and 0.9985 ROC-AUC. It is currently selected as the production
                phishing detection model.
              </p>
            )}

            {selectedModel.key === "svm" && (
              <p>
                SVM achieved excellent phishing detection performance with
                98.38% accuracy, 98.51% recall and 98.44% F1-score.
                Its ROC-AUC is 0.9985.
              </p>
            )}

            {selectedModel.key === "logistic_regression" && (
              <p>
                Logistic Regression achieved 97.98% accuracy and 98.06%
                F1-score. It provides strong baseline performance for
                phishing email classification.
              </p>
            )}

            {selectedModel.key === "naive_bayes" && (
              <p>
                Naive Bayes achieved 95.41% accuracy and 95.46% F1-score.
                Its precision is high at 98.33%, although its recall is
                lower than the other models.
              </p>
            )}

          </div>

        </div>
      )}

    </div>
  );
}

export default ModelEvaluation;