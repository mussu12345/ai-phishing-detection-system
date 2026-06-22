from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


def generate_report(data, filename):

    pdf = SimpleDocTemplate(filename)

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "AI Phishing Detection Report",
            styles["Title"]
        )
    )

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            f"Prediction: {data.get('prediction', 'N/A')}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"Threat Level: {data.get('threat_level', 'N/A')}",
            styles["BodyText"]
        )
    )

    content.append(
        Paragraph(
            f"Risk Score: {data.get('risk_score', 0)}%",
            styles["BodyText"]
        )
    )

    content.append(Spacer(1, 15))

    content.append(
        Paragraph(
            "Reasons:",
            styles["Heading2"]
        )
    )

    reasons = data.get(
        "reasons",
        ["No reasons available"]
    )

    for reason in reasons:
        content.append(
            Paragraph(
                f"• {reason}",
                styles["BodyText"]
            )
        )

    content.append(Spacer(1, 15))

    content.append(
        Paragraph(
            "Prevention:",
            styles["Heading2"]
        )
    )

    prevention = data.get(
        "prevention",
        ["No prevention tips available"]
    )

    for item in prevention:
        content.append(
            Paragraph(
                f"• {item}",
                styles["BodyText"]
            )
        )

    pdf.build(content)