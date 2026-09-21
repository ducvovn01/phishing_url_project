# Autoencoder anomaly detector over the same numeric URL features as
# clustering_model.py.
#
# The autoencoder learns to compress and rebuild *legitimate* URLs only: it is
# trained on the legitimate rows of train and never sees a phishing URL while
# learning. A URL it rebuilds badly (high reconstruction error) looks unlike
# the legitimate ones, and that error is its phishing score.
#
# The error has no fixed scale, so to report the same metrics as the other
# models (evaluate(), per_class_table()) it is turned into a probability by a
# one-feature logistic regression on log(error) (Platt scaling), fitted on a
# domain-grouped validation split of train. That is the only step that sees
# phishing labels, and it keeps the order of the scores: ROC-AUC and PR-AUC
# are those of the raw error.
#
# Writes models/autoencoder.joblib and data/analysis/autoencoder_report.md.
import copy
import time

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupShuffleSplit
from torch import nn

from clustering_model import build_preprocess, numeric_feature_columns
from train_model import (
    ANALYSIS_DIR,
    MODELS_DIR,
    PROCESSED_DIR,
    RANDOM_STATE,
    THRESHOLD,
    evaluate,
    log,
    per_class_table,
    per_source_table,
    split_by_domain,
)

VAL_SIZE = 0.1  # share of train domains held out for early stopping and calibration
HIDDEN = [64, 32]
BOTTLENECK = 8  # 20 features squeezed through 8 numbers
BATCH_SIZE = 2048
LEARNING_RATE = 1e-3
MAX_EPOCHS = 60
PATIENCE = 5  # epochs without a better validation loss before stopping
EPS = 1e-12  # keeps log(error) finite for a perfectly rebuilt row


def build_autoencoder(n_features: int, hidden: list = HIDDEN,
                      bottleneck: int = BOTTLENECK) -> nn.Sequential:
    """Mirror-image encoder/decoder; linear output layer, since the inputs are
    standard-scaled and can be negative."""
    sizes = [n_features, *hidden, bottleneck]
    layers: list[nn.Module] = []
    for a, b in zip(sizes, sizes[1:]):
        layers += [nn.Linear(a, b), nn.ReLU()]
    back = sizes[::-1]
    for i, (a, b) in enumerate(zip(back, back[1:])):
        layers.append(nn.Linear(a, b))
        if i < len(back) - 2:
            layers.append(nn.ReLU())
    return nn.Sequential(*layers)


def reconstruction_error(model: nn.Module, X: np.ndarray, device: torch.device,
                         batch_size: int = 65536) -> np.ndarray:
    """Mean squared error per row between the input and its reconstruction."""
    model.eval()
    errors = []
    with torch.no_grad():
        for i in range(0, len(X), batch_size):
            batch = torch.as_tensor(X[i:i + batch_size], dtype=torch.float32, device=device)
            errors.append(((model(batch) - batch) ** 2).mean(dim=1).cpu().numpy())
    return np.concatenate(errors)


def error_feature(error: np.ndarray) -> np.ndarray:
    return np.log(error + EPS).reshape(-1, 1)


def train_autoencoder(X_fit: np.ndarray, X_val: np.ndarray, device: torch.device, start: float):
    """Fits on X_fit, stops early on the validation loss over X_val, and
    returns the best-epoch model and a per-epoch loss table."""
    torch.manual_seed(RANDOM_STATE)
    model = build_autoencoder(X_fit.shape[1]).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    X_fit_t = torch.as_tensor(X_fit, dtype=torch.float32, device=device)
    generator = torch.Generator(device=device).manual_seed(RANDOM_STATE)

    best_loss, best_state, stale, history = np.inf, None, 0, []
    for epoch in range(1, MAX_EPOCHS + 1):
        model.train()
        order = torch.randperm(len(X_fit_t), device=device, generator=generator)
        total = 0.0
        for i in range(0, len(order), BATCH_SIZE):
            batch = X_fit_t[order[i:i + BATCH_SIZE]]
            loss = ((model(batch) - batch) ** 2).mean()
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total += loss.item() * len(batch)
        val_loss = float(reconstruction_error(model, X_val, device).mean())
        history.append({"epoch": epoch, "train_loss": total / len(X_fit_t), "val_loss": val_loss})
        if val_loss < best_loss:
            best_loss, best_state, stale = val_loss, copy.deepcopy(model.state_dict()), 0
        else:
            stale += 1
        if epoch == 1 or epoch % 5 == 0 or stale >= PATIENCE:
            log(f"  epoch {epoch}: train loss {history[-1]['train_loss']:.4f}, "
                f"validation loss {val_loss:.4f}", start)
        if stale >= PATIENCE:
            break
    model.load_state_dict(best_state)
    return model, pd.DataFrame(history)


def bundle_proba(bundle: dict, rows: pd.DataFrame) -> np.ndarray:
    """Phishing probability for feature rows, from a models/autoencoder.joblib bundle."""
    model = build_autoencoder(len(bundle["feature_columns"]), bundle["hidden"],
                              bundle["bottleneck"])
    model.load_state_dict(bundle["state_dict"])
    X = bundle["preprocess"].transform(rows[bundle["feature_columns"]])
    error = reconstruction_error(model, X, torch.device("cpu"))
    return bundle["calibrator"].predict_proba(error_feature(error))[:, 1]


def main() -> None:
    start = time.perf_counter()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # Whole table, so split_by_domain() reproduces train_model.py's split.
    df = pd.read_parquet(PROCESSED_DIR / "features.parquet")
    feature_cols = numeric_feature_columns(df)
    train, test = split_by_domain(df)
    del df
    y_train, y_test = train["label"].to_numpy(), test["label"].to_numpy()
    log(f"Split: {len(train)} train rows / {len(test)} test rows, no shared domains", start)

    splitter = GroupShuffleSplit(n_splits=1, test_size=VAL_SIZE, random_state=RANDOM_STATE)
    fit_idx, val_idx = next(splitter.split(train, groups=train["domain"]))
    fit_legit = fit_idx[y_train[fit_idx] == 0]
    val_legit = val_idx[y_train[val_idx] == 0]

    # Scaling is fitted on legitimate rows only too: phishing rows must not
    # shape what "normal" looks like.
    preprocess = build_preprocess().fit(train[feature_cols].iloc[fit_legit])
    X_train = preprocess.transform(train[feature_cols])
    X_test = preprocess.transform(test[feature_cols])

    log(f"Training on {len(fit_legit)} legitimate rows ({device})", start)
    model, history = train_autoencoder(X_train[fit_legit], X_train[val_legit], device, start)
    best_epoch = int(history.loc[history["val_loss"].idxmin(), "epoch"])
    log(f"Best epoch {best_epoch} of {len(history)}", start)

    # Platt scaling on the whole validation split, both classes.
    val_error = reconstruction_error(model, X_train[val_idx], device)
    calibrator = LogisticRegression().fit(error_feature(val_error), y_train[val_idx])

    test_error = reconstruction_error(model, X_test, device)
    proba = calibrator.predict_proba(error_feature(test_error))[:, 1]
    # The error level where the calibrated probability crosses THRESHOLD.
    a, b = calibrator.coef_[0][0], calibrator.intercept_[0]
    error_cutoff = float(np.exp((np.log(THRESHOLD / (1 - THRESHOLD)) - b) / a))

    results = pd.DataFrame({"Autoencoder": evaluate(test["label"], proba)}).T
    by_class = per_class_table(test["label"], proba)
    by_source = per_source_table(test, proba)
    error_by_class = (pd.DataFrame({"error": test_error, "label": y_test})
                      .groupby("label")["error"].describe(percentiles=[0.25, 0.5, 0.75, 0.95])
                      .rename(index={0: "legitimate", 1: "phishing"}))
    print()
    print(results.to_string(float_format="{:.4f}".format))
    print()
    print(by_class.to_string(float_format="{:.4f}".format))
    print()
    print(error_by_class.to_string(float_format="{:.4f}".format))

    model_path = MODELS_DIR / "autoencoder.joblib"
    joblib.dump({
        "preprocess": preprocess,  # log1p + scaling, fitted on legitimate train rows
        "feature_columns": feature_cols,
        # Weights only, rebuilt with build_autoencoder() - see bundle_proba().
        "state_dict": {k: v.cpu() for k, v in model.state_dict().items()},
        "hidden": HIDDEN,
        "bottleneck": BOTTLENECK,
        "calibrator": calibrator,  # log(reconstruction error) -> phishing probability
        "threshold": THRESHOLD,
    }, model_path)
    print(f"saved {model_path}")

    ae = results.loc["Autoencoder"]
    ratio = error_by_class.loc["phishing", "50%"] / error_by_class.loc["legitimate", "50%"]
    report = [
        "# Autoencoder Report - Phishing URL Detector\n",
        "Source: `scripts/autoencoder_model.py`. Same test split as `model_report.md`.\n",
        "## Summary of findings\n",
        f"- Autoencoder (test): ROC-AUC {ae['roc_auc']:.4f}, PR-AUC {ae['pr_auc']:.4f}, F1 "
        f"{ae['f1']:.4f} (precision {ae['precision']:.4f}, recall {ae['recall']:.4f}), "
        f"accuracy {ae['accuracy']:.4f}, MCC {ae['mcc']:.4f}, RMSE {ae['rmse']:.4f}.",
        f"- The median reconstruction error of a phishing URL is {ratio:.1f}x that of a "
        "legitimate one: phishing URLs do look unusual to a model of legitimate URLs, but "
        "the two error distributions overlap (table below).",
        f"- At threshold {THRESHOLD}, a URL is flagged when its reconstruction error is above "
        f"{error_cutoff:.4f}.\n",
        "## Setup\n",
        f"- Features ({len(feature_cols)}): " + ", ".join(f"`{c}`" for c in feature_cols)
        + ". log1p then standard scaling, fitted on legitimate train rows.",
        f"- Network: {len(feature_cols)} -> " + " -> ".join(map(str, HIDDEN)) + f" -> "
        f"{BOTTLENECK} -> " + " -> ".join(map(str, HIDDEN[::-1])) + f" -> {len(feature_cols)}, "
        f"ReLU, mean squared error loss, Adam (learning rate {LEARNING_RATE}), batch "
        f"{BATCH_SIZE}.",
        f"- Trained on the {len(fit_legit)} legitimate rows of a domain-grouped fit split of "
        f"train; early stopping on the reconstruction loss of the {len(val_legit)} legitimate "
        f"validation rows (patience {PATIENCE}, best epoch {best_epoch} of {len(history)}).",
        f"- Probability: logistic regression on log(error), fitted on all {len(val_idx)} "
        "validation rows, both classes.\n",
        "## Training history\n",
        history.to_markdown(index=False, floatfmt=".4f"),
        "",
        "## Test results\n",
        f"Same metrics as `model_report.md`; threshold {THRESHOLD} on the calibrated "
        "probability.\n",
        results.to_markdown(floatfmt=".4f"),
        "",
        "## Precision, recall and F1 by class (test split)\n",
        by_class.to_markdown(floatfmt=".4f"),
        "",
        "## Results by source (test split)\n",
        by_source.to_markdown(floatfmt=".4f"),
        "",
        "## Reconstruction error by class (test split)\n",
        error_by_class.to_markdown(floatfmt=".4f"),
        "",
        "## Caveats\n",
        "- An anomaly detector flags whatever is unusual, not only phishing: legitimate URLs "
        "with long paths or query strings also rebuild badly and become false positives.",
        "- Phishing URLs that look like ordinary short URLs rebuild well and are missed; "
        "the supervised models can learn those patterns, this one cannot.",
        "- Same as `model_report.md`: the test split comes from the same four overlapping "
        "sources as train.",
        "",
    ]
    report_path = ANALYSIS_DIR / "autoencoder_report.md"
    report_path.write_text("\n".join(report), encoding="utf-8")
    print(f"saved {report_path}")
    log("Done", start)


if __name__ == "__main__":
    main()
