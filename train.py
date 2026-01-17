#!/usr/bin/env python3
"""
Script huấn luyện mô hình Deep Learning
Sinh dữ liệu training giả lập và huấn luyện các mô hình
"""

import sys
import logging
import numpy as np
import argparse
from pathlib import Path
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib

# Setup path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "config"))

import config
from src.model_trainer import AttackDetectionModel
from src.preprocessor import DataPreprocessor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_synthetic_data(n_samples: int = 1000) -> tuple:
    """
    Sinh dữ liệu training giả lập
    
    Args:
        n_samples: Số mẫu dữ liệu
        
    Returns:
        Tuple (X, y) - features và labels
    """
    logger.info(f"Generating {n_samples} synthetic samples...")
    
    X_list = []
    y_list = []
    
    n_features = len(config.FEATURE_NAMES)
    
    # Class distribution
    n_per_class = n_samples // 5
    
    # 0: Normal
    for _ in range(n_per_class):
        sample = np.random.normal(loc=[256**2, 256**2, 500, 0, 0, 200, 64, 1024, 80, 0, 1, 0, 0, 65535, 0, 0, 10],
                                 scale=[1e8, 1e8, 200, 0, 0, 100, 5, 10000, 0, 0, 0, 0, 0, 10000, 0, 0, 5])
        X_list.append(np.clip(sample, 0, None))
        y_list.append(0)
    
    # 1: Teardrop (IP fragmentation)
    for _ in range(n_per_class):
        sample = np.random.normal(loc=[256**2, 256**2, 800, 100, 1, 300, 64, 1024, 80, 0, 1, 0, 0, 65535, 0, 0, 10],
                                 scale=[1e8, 1e8, 100, 50, 0.5, 100, 5, 10000, 0, 0, 0, 0, 0, 10000, 0, 0, 5])
        X_list.append(np.clip(sample, 0, None))
        y_list.append(1)
    
    # 2: Ping of Death (oversized ICMP)
    for _ in range(n_per_class):
        sample = np.random.normal(loc=[256**2, 256**2, 65000, 0, 0, 64500, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10],
                                 scale=[1e8, 1e8, 5000, 0, 0, 5000, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5])
        X_list.append(np.clip(sample, 0, None))
        y_list.append(2)
    
    # 3: SYN Flood
    for _ in range(n_per_class):
        sample = np.random.normal(loc=[256**2, 256**2, 60, 0, 0, 0, 64, 5000, 80, 1, 0, 0, 0, 65535, 100000, 0, 100],
                                 scale=[1e8, 1e8, 10, 0, 0, 0, 5, 10000, 0, 0, 0, 0, 0, 10000, 50000, 0, 50])
        X_list.append(np.clip(sample, 0, None))
        y_list.append(3)
    
    # 4: DNS Amplification
    for _ in range(n_per_class):
        sample = np.random.normal(loc=[256**2, 256**2, 512, 0, 0, 450, 64, 10000, 53, 0, 0, 0, 0, 0, 0, 512, 150],
                                 scale=[1e8, 1e8, 100, 0, 0, 100, 5, 10000, 0, 0, 0, 0, 0, 0, 0, 100, 100])
        X_list.append(np.clip(sample, 0, None))
        y_list.append(4)
    
    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list)
    
    logger.info(f"Generated X shape: {X.shape}, y shape: {y.shape}")
    logger.info(f"Class distribution: {np.bincount(y)}")
    
    return X, y


def prepare_data(X: np.ndarray, y: np.ndarray, test_size: float = 0.2) -> tuple:
    """
    Chuẩn bị dữ liệu: Split và scale
    
    Args:
        X: Features
        y: Labels
        test_size: Tỷ lệ test set
        
    Returns:
        Tuple (X_train, X_test, y_train, y_test, scaler)
    """
    logger.info("Preparing data...")
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )
    
    # Fit scaler on training data
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Convert labels to one-hot
    y_train_onehot = np.eye(5)[y_train]
    y_test_onehot = np.eye(5)[y_test]
    
    logger.info(f"Train set: {X_train_scaled.shape}, Test set: {X_test_scaled.shape}")
    
    return X_train_scaled, X_test_scaled, y_train_onehot, y_test_onehot, scaler


def train_model(architecture: str = 'mlp', epochs: int = 50) -> AttackDetectionModel:
    """
    Huấn luyện mô hình
    
    Args:
        architecture: 'mlp', 'cnn', hoặc 'lstm'
        epochs: Số epoch
        
    Returns:
        Trained model
    """
    logger.info(f"Training {architecture} model for {epochs} epochs...")
    
    # Generate data
    X, y = generate_synthetic_data(n_samples=2000)
    
    # Prepare data
    X_train, X_test, y_train, y_test, scaler = prepare_data(X, y)
    
    # Create model
    model = AttackDetectionModel(
        input_dim=len(config.FEATURE_NAMES),
        architecture=architecture
    )
    
    # Train
    history = model.train(
        X_train, y_train,
        X_val=X_test, y_val=y_test,
        epochs=epochs,
        batch_size=32
    )
    
    # Evaluate
    evaluation = model.evaluate(X_test, y_test)
    logger.info(f"Test Evaluation: {evaluation}")
    
    # Save model and scaler
    model_path = config.MODEL_DIR / f"ids_model_{architecture}.keras"
    scaler_path = config.MODEL_DIR / "scaler.joblib"
    
    model.save(str(model_path))
    joblib.dump(scaler, str(scaler_path))
    
    logger.info(f"Model saved to {model_path}")
    logger.info(f"Scaler saved to {scaler_path}")
    
    return model, scaler


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Train IDS/IPS Models')
    parser.add_argument('--architecture', choices=['mlp', 'cnn', 'lstm'], default='mlp',
                       help='Model architecture (default: mlp)')
    parser.add_argument('--epochs', type=int, default=50,
                       help='Number of training epochs (default: 50)')
    parser.add_argument('--all', action='store_true',
                       help='Train all architectures')
    
    args = parser.parse_args()
    
    architectures = ['mlp', 'cnn', 'lstm'] if args.all else [args.architecture]
    
    for arch in architectures:
        logger.info(f"\n{'='*60}")
        logger.info(f"Training {arch.upper()} Architecture")
        logger.info(f"{'='*60}")
        
        try:
            model, scaler = train_model(architecture=arch, epochs=args.epochs)
            logger.info(f"✓ {arch.upper()} training completed successfully")
        except Exception as e:
            logger.error(f"✗ Error training {arch}: {str(e)}")
    
    logger.info(f"\n{'='*60}")
    logger.info("Training Summary:")
    logger.info(f"Models saved to: {config.MODEL_DIR}")
    logger.info(f"Scaler saved to: {config.MODEL_DIR / 'scaler.joblib'}")
    logger.info("Ready for inference!")
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    main()
