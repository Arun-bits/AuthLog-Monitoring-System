# src/evaluation.py

def evaluate_detection(expected, actual):
    tp = len(set(expected) & set(actual))
    fp = len(set(actual) - set(expected))
    fn = len(set(expected) - set(actual))

    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn
    }
