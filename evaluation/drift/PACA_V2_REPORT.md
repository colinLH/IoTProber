# PACA v2 training report

Training date: 2026-09-25

## Data contract

- Source: `/mnt/zwj_ckpt/iotprober/platform_data/csv/rag/ipraw_*.csv`
- Raw rows: 362,937 across 11 production device types.
- Removed ambiguous data: 15,346 IPs appearing under multiple device types, covering 36,438 rows.
- Cleaned rows: 326,499.
- Deterministic IP-group split: train 70%, validation 10%, calibration 10%, test 10%.
- Unique IPs: train 228,836; validation 32,320; calibration 32,868; test 32,475.
- Cross-split IP overlap: verified zero.
- The source corpus has no temporal/real drift labels. Test FPR is measured on held-out static data; synthetic shifts are stress tests rather than real-world TPR estimates.

## Model and calibration

- Eight NVIDIA H800 GPUs via `torch.nn.DataParallel`; BF16 autocast.
- Perspective-hashed input: 128 dimensions per perspective, 1,408 total dimensions.
- Hidden dimensions: 256, 128; latent dimension: 32.
- Class-balanced anchor sampling; latent-space contrastive loss (`lambda=0.1`).
- Best checkpoint selected by macro validation reconstruction score and restored before calibration.
- Requested 100 epochs; early stopped after 16; best epoch: 1.
- Device-type thresholds: held-out calibration 99th percentile; global 99th percentile fallback for unknown types.
- Global threshold: 0.0085176184.

Perspective sensitivities are loaded from `config/perspective_info.json` and frozen into the artifact:

| Perspective | Weight |
|---|---:|
| as | 0.03 |
| whois | 0.03 |
| os | 0.10 |
| sw | 0.11 |
| hw | 0.13 |
| sd | 0.09 |
| body | 0.08 |
| htags | 0.08 |
| hfavicons | 0.15 |
| certificate | 0.16 |
| dns | 0.04 |

## Held-out clean test

- Rows: 32,475.
- Micro clean FPR: 1.016%.
- Macro clean FPR across 11 types: 0.767%.
- Large-class clean FPRs: CAMERA 0.998%, NAS 0.918%, ROUTER 1.030%, NVR 1.306%, PRINTER 1.380%, SCADA 1.085%.
- The legacy global-threshold model marked 16.8% of its reference/training data as drift and ranged from 8.4% to 95.6% by type; the v2 calibration removes that systematic type bias.

Full per-type results are in `drift_data/autoencoder_drift_v2/clean_test_metrics.csv`.

## Artifacts

- `drift_data/autoencoder_drift_v2/paca_model.pt`
- `drift_data/autoencoder_drift_v2/paca_artifacts.pkl`
- `drift_data/autoencoder_drift_v2/training_manifest.json`
- `drift_data/autoencoder_drift_v2/training_history.csv`
- `drift_data/autoencoder_drift_v2/class_thresholds.csv`
- `drift_data/autoencoder_drift_v2/test_results.csv`
- `drift_data/autoencoder_drift_v2/clean_test_metrics.csv`
- `drift_data/autoencoder_drift_v2/synthetic_drift_metrics.csv`
- `drift_data/autoencoder_drift_v2/synthetic_drift_results.csv`

The artifacts directory is intentionally ignored by Git, matching the repository's existing model/data policy. `path_config.DRIFT_OUTPUT_DIR` now selects this directory in production.
