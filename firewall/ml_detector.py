
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# Pretrained Hugging Face model
MODEL_NAME = "protectai/deberta-v3-base-prompt-injection-v2"

# Model objects are loaded only once
tokenizer = None
model = None


def load_model():
    """
    Load the pretrained classifier on CPU.
    """

    global tokenizer, model

    if model is not None:
        return

    print("Loading prompt injection detection model...")

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME
    )

    # We are explicitly using CPU.
    model.to(torch.device("cpu"))
    model.eval()

    print("Model loaded successfully on CPU.")

    
def ml_detect(text: str) -> dict:
    """
    Predict whether the input prompt is safe or an injection.

    Returns the predicted label and class probabilities.
    """

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    if not text.strip():
        raise ValueError("Input prompt cannot be empty.")

    load_model()

    # Convert text into model-compatible tokens.
    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=512
    )

    # Run prediction without calculating gradients.
    with torch.inference_mode():
        outputs = model(**inputs)

        probabilities = torch.softmax(
            outputs.logits,
            dim=-1
        )[0]

    # Read actual class names from the model configuration.
    id2label = model.config.id2label

    class_probabilities = {
        id2label[index]: round(probability.item(), 4)
        for index, probability in enumerate(probabilities)
    }

    predicted_index = int(torch.argmax(probabilities).item())
    predicted_label = id2label[predicted_index]

    # Find the injection probability using the model's labels.
    injection_index = next(
        (
            index
            for index, label in id2label.items()
            if "INJECTION" in label.upper()
        ),
        None
    )

    if injection_index is None:
        raise ValueError(
            f"Could not identify injection class. Model labels: {id2label}"
        )

    injection_probability = probabilities[injection_index].item()

    return {
        "label": predicted_label,
        "injection_probability": round(injection_probability, 4),
        "class_probabilities": class_probabilities
    }
