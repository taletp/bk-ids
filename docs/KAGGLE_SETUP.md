# Kaggle Training Setup Guide

## Overview
This guide explains how to train your IDS model on Kaggle servers using the CIC-IDS2018 dataset.

## Why Kaggle?
- **Memory**: Kaggle provides 16GB RAM (vs local OOM errors)
- **Compute**: Free CPU/GPU resources for faster training
- **Dataset**: CIC-IDS2018 already available as Kaggle Dataset
- **Persistence**: Download trained models back to local system

## Step-by-Step Instructions

### 1. Upload the Notebook

1. Go to [kaggle.com/code](https://www.kaggle.com/code)
2. Click "New Notebook" → "Upload Notebook"
3. Upload `kaggle_train_ids.ipynb` from this directory
4. Notebook will open in Kaggle's editor

### 2. Add the Dataset

1. In the Kaggle notebook editor, click **"Add Data"** (right sidebar)
2. Search for: `CSE-CIC-IDS2018` or `solarmainframe/ids-intrusion-csv`
3. Click **"Add"** to attach the dataset to your notebook
4. The dataset will be available at `/kaggle/input/ids-intrusion-csv/`

**Alternative datasets on Kaggle:**
- `solarmainframe/ids-intrusion-csv` (recommended)
- `cicdataset/cicids2017`
- Search "CIC-IDS2018" for other versions

### 3. Configure the Training

Edit the `CONFIG` cell in the notebook:

```python
CONFIG = {
    'use_simplified': True,           # Use simplified 8-class taxonomy
    'balance_method': 'undersample',  # Options: undersample, oversample, smote
    'days_to_load': [                 # Which days to train on
        '02-14-2018.csv',
        '02-15-2018.csv'
    ],
    'model_type': 'random_forest',    # Options: random_forest, xgboost, lightgbm, mlp
}
```

**Model Types:**
- `random_forest`: Fast, good baseline (scikit-learn)
- `xgboost`: Better accuracy, slower (XGBoost)
- `lightgbm`: Fast gradient boosting (LightGBM)
- `mlp`: Neural network (TensorFlow/Keras)

**Days Available:**
```
02-14-2018.csv  - Wednesday, Benign + Brute Force
02-15-2018.csv  - Thursday, Benign + SQL Injection, Brute Force
02-16-2018.csv  - Friday, Benign + DoS
02-20-2018.csv  - Tuesday, Benign + DDoS
02-21-2018.csv  - Wednesday, Benign + DDoS, Brute Force
02-22-2018.csv  - Thursday, Benign + Web attacks, Brute Force
02-23-2018.csv  - Friday, Benign + Infiltration
03-01-2018.csv  - Wednesday, Benign + Bot
03-02-2018.csv  - Thursday, Benign + DDoS
```

### 4. Run the Notebook

1. Enable GPU (optional): Settings → Accelerator → GPU P100
2. Click "Run All" or execute cells sequentially
3. Monitor progress in cell outputs
4. Training takes **10-30 minutes** depending on configuration

### 5. Download Trained Artifacts

After training completes, download these files from `/kaggle/working/`:

```
ids_model_*.keras or *.joblib  # Trained model
scaler.joblib                  # Feature scaler
label_encoder.joblib           # Label encoder
model_metadata.json            # Model info
confusion_matrix.png           # Evaluation plot
```

**How to download:**
1. Click the folder icon (top-right of notebook)
2. Navigate to `/kaggle/working/`
3. Right-click each file → Download
4. Save to your local `bk-ids/models/` directory

### 6. Use the Model Locally

Copy downloaded files to your local system:

```bash
cd /path/to/bk-ids
mkdir -p models

# Copy downloaded files
mv ~/Downloads/ids_model_*.keras models/
mv ~/Downloads/scaler.joblib models/
mv ~/Downloads/label_encoder.joblib models/
mv ~/Downloads/model_metadata.json models/
```
or use Kaggle's API to download directly.
```bash
kaggle kernels output <your-username/your-project-name> -p models/
```

Update your local config:

```python
# config/config.py
MODEL_PATH = "models/ids_model_random_forest.joblib"  # or .keras
SCALER_PATH = "models/scaler.joblib"
```

Run the IDS:

```bash
sudo ./venv/bin/python main.py --mode live --interface eth0
```

## Troubleshooting

### "Dataset not found"
- Make sure you added the dataset in Step 2
- Check the dataset path matches your dataset name
- Try searching for alternative CIC-IDS2018 datasets

### "Out of Memory" in Kaggle
- Reduce `days_to_load` (train on 1-2 days first)
- Use `balance_method='undersample'` (reduces samples)
- Avoid `oversample` or `smote` with large datasets

### "Module not found"
- The notebook installs required packages in Cell 1
- If import fails, manually run: `!pip install imbalanced-learn`

### "Model accuracy too low"
- Try different `model_type` (xgboost usually best)
- Add more days to `days_to_load`
- Use `balance_method='smote'` for better minority class handling

### "Training takes too long"
- Enable GPU in Settings → Accelerator
- Use `random_forest` or `lightgbm` (faster than xgboost)
- Reduce dataset size (fewer days)

## Performance Tips

### For Quick Testing (5 min)
```python
CONFIG = {
    'days_to_load': ['02-14-2018.csv'],
    'model_type': 'random_forest',
    'balance_method': 'undersample'
}
```

### For Best Accuracy (30 min)
```python
CONFIG = {
    'days_to_load': [
        '02-14-2018.csv', '02-15-2018.csv', '02-16-2018.csv',
        '02-20-2018.csv', '02-21-2018.csv', '02-22-2018.csv'
    ],
    'model_type': 'xgboost',
    'balance_method': 'smote',
    'use_simplified': True
}
```

### For Production (60 min)
```python
CONFIG = {
    'days_to_load': [  # All 9 days
        '02-14-2018.csv', '02-15-2018.csv', '02-16-2018.csv',
        '02-20-2018.csv', '02-21-2018.csv', '02-22-2018.csv',
        '02-23-2018.csv', '03-01-2018.csv', '03-02-2018.csv'
    ],
    'model_type': 'xgboost',
    'balance_method': 'smote',
    'use_simplified': False  # Full 14-class taxonomy
}
```

## Next Steps

1. **Upload** `kaggle_train_ids.ipynb` to Kaggle
2. **Add** CIC-IDS2018 dataset
3. **Configure** training parameters
4. **Run** the notebook
5. **Download** trained artifacts
6. **Deploy** model locally

## Resources

- **Kaggle Notebook Editor**: https://www.kaggle.com/code
- **CIC-IDS2018 Dataset**: https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv
- **Documentation**: See `docs/CIC-IDS2018-GUIDE.md` for more details
- **Kaggle GPU Guide**: https://www.kaggle.com/docs/notebooks#gpu

## Questions?

Check `README.md` in the project root for system architecture details.
