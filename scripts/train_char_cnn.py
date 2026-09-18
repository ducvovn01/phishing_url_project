# Character-level CNN baseline (URLNet-style) over the raw URL string.
#
# Unlike train_model.py it gets no hand-made features: it reads the URL as a
# sequence of characters and learns its own patterns. It uses the same
# domain-grouped train/test split and the same metrics as train_model.py, and
# scores the saved LightGBM model on that test split for a side-by-side table.
#
# URL preprocessing, to keep source formatting out of the input (same reason
# has_protocol/uses_https are dropped in train_model.py):
# - the scheme ("https://") is stripped - whether a row has one depends on
#   its source;
# - the URL is lowercased - phiusiil rows never contain uppercase letters,
#   while ~7-27% of rows in the other sources do.
#
# Writes models/char_cnn.pt and data/analysis/char_cnn_report.md.
import time

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import average_precision_score, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit
from torch import nn

from train_model import (
    ANALYSIS_DIR,
    MODELS_DIR,
    PROCESSED_DIR,
    RANDOM_STATE,
    TARGET_FPR,
    THRESHOLD,
    build_matrix,
    evaluate,
    log,
    per_source_table,
    positive_proba,
    split_by_domain,
)

MAX_LEN = 200  # covers 99% of URLs (scheme stripped); longer ones are cut
# Byte -> token id: 0 = padding, 1..95 = printable ASCII (space..~), 96 = any
# other byte (non-ASCII URLs are UTF-8 encoded first).
PAD_ID, UNK_ID = 0, 96
VOCAB_SIZE = 97
BYTE_TO_ID = np.full(256, UNK_ID, dtype=np.uint8)
BYTE_TO_ID[32:127] = np.arange(1, 96)

VAL_SIZE = 0.1  # share of train domains held out for early stopping
BATCH_SIZE = 1024
MAX_EPOCHS = 8
PATIENCE = 2  # epochs without validation PR-AUC gain before stopping
LEARNING_RATE = 1e-3
WEIGHT_DECAY = 1e-4

MODEL_CONFIG = {
    "vocab_size": VOCAB_SIZE,
    "embed_dim": 32,
    "kernel_sizes": [3, 4, 5, 6],
    "filters": 128,
    "hidden_dim": 256,
    "dropout": 0.3,
}


def preprocess(urls: pd.Series) -> pd.Series:
    return (
        urls.fillna("").astype(str).str.strip()
        .str.replace(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", regex=True)
        .str.lower()
    )


def encode(urls: pd.Series) -> np.ndarray:
    """(n, MAX_LEN) uint8 token ids, padded on the right with PAD_ID."""
    raw = b"".join(
        u.encode("utf-8")[:MAX_LEN].ljust(MAX_LEN, b"\0") for u in preprocess(urls)
    )
    ids = BYTE_TO_ID[np.frombuffer(raw, dtype=np.uint8)]
    # ljust's padding bytes are \0, which BYTE_TO_ID maps to UNK; fix them up.
    ids[np.frombuffer(raw, dtype=np.uint8) == 0] = PAD_ID
    return ids.reshape(-1, MAX_LEN)


class CharCNN(nn.Module):
    """Embedding -> parallel 1-D convolutions of several widths -> global max
    pool -> MLP -> one logit (phishing)."""

    def __init__(self, vocab_size, embed_dim, kernel_sizes, filters, hidden_dim, dropout):
        super().__init__()
        self.embed = nn.Embedding(vocab_size, embed_dim, padding_idx=PAD_ID)
        self.convs = nn.ModuleList(
            nn.Conv1d(embed_dim, filters, k, padding=k // 2) for k in kernel_sizes
        )
        self.head = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(filters * len(kernel_sizes), hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 1),
        )

    def forward(self, ids: torch.Tensor) -> torch.Tensor:
        x = self.embed(ids).transpose(1, 2)  # (batch, embed_dim, MAX_LEN)
        # Padding positions would otherwise win the max pool on short URLs.
        pad = (ids == PAD_ID).unsqueeze(1)
        pooled = []
        for conv in self.convs:
            h = torch.relu(conv(x))[..., :ids.shape[1]]
            pooled.append(h.masked_fill(pad, 0).amax(dim=2))
        return self.head(torch.cat(pooled, dim=1)).squeeze(1)


@torch.no_grad()
def predict_proba(model: CharCNN, ids: np.ndarray, device: torch.device) -> np.ndarray:
    model.eval()
    out = []
    for i in range(0, len(ids), BATCH_SIZE * 4):
        batch = torch.from_numpy(ids[i:i + BATCH_SIZE * 4]).to(device).long()
        with torch.autocast(device.type, enabled=device.type == "cuda"):
            out.append(torch.sigmoid(model(batch).float()).cpu().numpy())
    return np.concatenate(out)


def train(model, X, y, X_val, y_val, device, start):
    optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE, weight_decay=WEIGHT_DECAY)
    loss_fn = nn.BCEWithLogitsLoss()
    scaler = torch.amp.GradScaler(enabled=device.type == "cuda")
    generator = torch.Generator().manual_seed(RANDOM_STATE)
    X_t, y_t = torch.from_numpy(X), torch.from_numpy(y.astype(np.float32))

    history, best_score, best_state, stale = [], -1.0, None, 0
    for epoch in range(1, MAX_EPOCHS + 1):
        model.train()
        order = torch.randperm(len(X_t), generator=generator)
        total = 0.0
        for i in range(0, len(order), BATCH_SIZE):
            idx = order[i:i + BATCH_SIZE]
            ids = X_t[idx].to(device, non_blocking=True).long()
            target = y_t[idx].to(device, non_blocking=True)
            optimizer.zero_grad(set_to_none=True)
            with torch.autocast(device.type, enabled=device.type == "cuda"):
                loss = loss_fn(model(ids).float(), target)
            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()
            total += loss.item() * len(idx)

        val_score = average_precision_score(y_val, predict_proba(model, X_val, device))
        history.append({"epoch": epoch, "train_loss": total / len(order), "val_pr_auc": val_score})
        log(f"  epoch {epoch}: train loss {total / len(order):.4f}, val PR-AUC {val_score:.4f}", start)

        if val_score > best_score:
            best_score, stale = val_score, 0
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
        else:
            stale += 1
            if stale >= PATIENCE:
                break

    model.load_state_dict(best_state)
    return pd.DataFrame(history)


def main() -> None:
    start = time.perf_counter()
    torch.manual_seed(RANDOM_STATE)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    log(f"Device: {device}", start)

    # Whole table, so split_by_domain() reproduces train_model.py's split
    # exactly and the LightGBM comparison can be scored on the same rows.
    df = pd.read_parquet(PROCESSED_DIR / "features.parquet")
    train_df, test_df = split_by_domain(df)
    del df

    # Early-stopping split, also grouped by domain.
    splitter = GroupShuffleSplit(n_splits=1, test_size=VAL_SIZE, random_state=RANDOM_STATE)
    fit_idx, val_idx = next(splitter.split(train_df, groups=train_df["domain"]))
    fit_df, val_df = train_df.iloc[fit_idx], train_df.iloc[val_idx]
    log(f"Split: {len(fit_df)} fit / {len(val_df)} validation / {len(test_df)} test rows", start)

    X_fit, X_val, X_test = (encode(d["url"]) for d in (fit_df, val_df, test_df))
    y_fit, y_val, y_test = (d["label"].to_numpy() for d in (fit_df, val_df, test_df))
    log("Encoded URLs", start)

    model = CharCNN(**MODEL_CONFIG).to(device)
    n_params = sum(p.numel() for p in model.parameters())
    log(f"Training Char-CNN ({n_params:,} parameters)", start)
    history = train(model, X_fit, y_fit, X_val, y_val, device, start)
    cnn_proba = predict_proba(model, X_test, device)

    lgbm_bundle = joblib.load(MODELS_DIR / "lightgbm.joblib")
    X_test_lgbm = build_matrix(test_df, lgbm_bundle["feature_columns"], lgbm_bundle["tld_categories"])
    lgbm_proba = positive_proba(lgbm_bundle["model"], X_test_lgbm)

    results = pd.DataFrame({
        "Char-CNN": evaluate(test_df["label"], cnn_proba),
        "LightGBM (saved model)": evaluate(test_df["label"], lgbm_proba),
    }).T
    by_source = per_source_table(test_df, cnn_proba)
    cm = confusion_matrix(y_test, (cnn_proba >= THRESHOLD).astype(int))
    print()
    print(results.to_string(float_format="{:.4f}".format))
    print()
    print(by_source.to_string(float_format="{:.4f}".format))

    model_path = MODELS_DIR / "char_cnn.pt"
    torch.save({
        "state_dict": model.state_dict(),
        "model_config": MODEL_CONFIG,
        "max_len": MAX_LEN,  # URLs must go through encode() in this file
        "threshold": THRESHOLD,
    }, model_path)
    print(f"saved {model_path}")

    cnn, lg = results.iloc[0], results.iloc[1]
    best_epoch = history.loc[history["val_pr_auc"].idxmax()]
    tn, fp, fn, tp = cm.ravel()
    report = [
        "# Char-CNN Report - Phishing URL Detector\n",
        "Source: `scripts/train_char_cnn.py`. Compared with the LightGBM model from "
        "`scripts/train_model.py` on the same test split.\n",
        "## Summary of findings\n",
        f"- Char-CNN (test): ROC-AUC {cnn['roc_auc']:.4f}, PR-AUC {cnn['pr_auc']:.4f}, "
        f"F1 {cnn['f1']:.4f} (precision {cnn['precision']:.4f}, recall {cnn['recall']:.4f}) "
        f"at threshold {THRESHOLD}. At a {TARGET_FPR:.0%} false-positive rate it catches "
        f"{cnn['recall_at_1pct_fpr']:.2%} of phishing URLs.",
        f"- LightGBM on the same rows: ROC-AUC {lg['roc_auc']:.4f}, PR-AUC {lg['pr_auc']:.4f}, "
        f"F1 {lg['f1']:.4f}, recall at {TARGET_FPR:.0%} FPR {lg['recall_at_1pct_fpr']:.2%}.",
        f"- At threshold {THRESHOLD}, Char-CNN misses {fn} of {fn + tp} phishing URLs and "
        f"flags {fp} of {tn + fp} legitimate URLs ({fp / (tn + fp):.2%}).",
        f"- Best epoch: {int(best_epoch['epoch'])} of {len(history)} "
        f"(validation PR-AUC {best_epoch['val_pr_auc']:.4f}).\n",
        "## Setup\n",
        "- Test split: `split_by_domain()` from `train_model.py` (same rows as `model_report.md`).",
        f"- Early stopping: {VAL_SIZE:.0%} of train domains held out (`GroupShuffleSplit`, "
        f"random_state {RANDOM_STATE}); training stops after {PATIENCE} epochs without a "
        f"validation PR-AUC gain (max {MAX_EPOCHS}), and the best epoch is kept.",
        f"- Input: URL with the scheme stripped, lowercased, cut to {MAX_LEN} characters. "
        "Scheme and letter case mostly record how each source formatted its URLs "
        "(phiusiil has no uppercase at all), so they are removed.",
        f"- Tokens: printable ASCII characters, one id each; any other byte shares one id "
        f"({VOCAB_SIZE} ids with padding).",
        f"- Model: embedding {MODEL_CONFIG['embed_dim']} -> Conv1d with kernel sizes "
        f"{MODEL_CONFIG['kernel_sizes']} ({MODEL_CONFIG['filters']} filters each) -> global "
        f"max pool -> dense {MODEL_CONFIG['hidden_dim']} -> 1 logit; dropout "
        f"{MODEL_CONFIG['dropout']}. {n_params:,} parameters.",
        f"- Training: AdamW (lr {LEARNING_RATE}, weight decay {WEIGHT_DECAY}), batch "
        f"{BATCH_SIZE}, binary cross-entropy, mixed precision on GPU ({device}).\n",
        "## Training history\n",
        history.to_markdown(index=False, floatfmt=".4f"),
        "",
        "## Test results\n",
        f"Threshold-based metrics use threshold {THRESHOLD}. `recall_at_1pct_fpr` is the share "
        f"of phishing URLs caught when {TARGET_FPR:.0%} of legitimate URLs are flagged.\n",
        results.to_markdown(floatfmt=".4f"),
        "",
        "## Char-CNN results by source (test split)\n",
        by_source.to_markdown(floatfmt=".4f"),
        "",
        "## Char-CNN confusion matrix (test split)\n",
        pd.DataFrame(cm, index=["actual legitimate", "actual phishing"],
                     columns=["predicted legitimate", "predicted phishing"]).to_markdown(),
        "",
        "## Caveats\n",
        "- Same as `model_report.md`: the test split comes from the same four overlapping "
        "sources as train, so expect lower scores on URLs from a new source.",
        "- Lowercasing and stripping the scheme remove the source-formatting shortcuts we "
        "know about. The CNN can still pick up others (e.g. how a source encodes paths) "
        "that the hand-made features never saw.",
        "- One training run with one seed; small score differences between models may not "
        "hold across seeds.",
        "",
    ]
    report_path = ANALYSIS_DIR / "char_cnn_report.md"
    report_path.write_text("\n".join(report), encoding="utf-8")
    print(f"saved {report_path}")
    log("Done", start)


if __name__ == "__main__":
    main()
