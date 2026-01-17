"""
Module Model Trainer: Tạo, huấn luyện và lưu mô hình Deep Learning
Hỗ trợ CNN, LSTM, MLP architectures
"""

import logging
import numpy as np
from typing import Tuple, List, Optional
from datetime import datetime
import json

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, models, callbacks
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    logging.warning("TensorFlow not installed. Model training will be disabled.")

logger = logging.getLogger(__name__)


class AttackDetectionModel:
    """
    Mô hình phát hiện tấn công sử dụng Deep Learning
    
    Classes: 0=Normal, 1=Teardrop, 2=PingOfDeath, 3=SynFlood, 4=DNS_Amp
    """
    
    ATTACK_CLASSES = {
        0: 'Normal',
        1: 'Teardrop',
        2: 'PingOfDeath',
        3: 'SynFlood',
        4: 'DNS_Amp'
    }
    
    CLASS_TO_INDEX = {v: k for k, v in ATTACK_CLASSES.items()}
    
    def __init__(self, input_dim: int = 17, architecture: str = 'mlp'):
        """
        Khởi tạo mô hình
        
        Args:
            input_dim: Số lượng features đầu vào
            architecture: 'mlp', 'cnn', hoặc 'lstm'
        """
        if not TF_AVAILABLE:
            raise ImportError("TensorFlow is required for model training. Install with: pip install tensorflow")
        
        self.input_dim = input_dim
        self.architecture = architecture
        self.model = None
        self.history = None
        
        # Tạo mô hình
        self._build_model()
        
        logger.info(f"Model initialized with architecture: {architecture}, input_dim: {input_dim}")
    
    def _build_model(self):
        """Xây dựng mô hình Deep Learning"""
        if self.architecture == 'mlp':
            self.model = self._build_mlp()
        elif self.architecture == 'cnn':
            self.model = self._build_cnn()
        elif self.architecture == 'lstm':
            self.model = self._build_lstm()
        else:
            raise ValueError(f"Unknown architecture: {self.architecture}")
    
    def _build_mlp(self) -> keras.Model:
        """Xây dựng MLP (Multilayer Perceptron)"""
        model = models.Sequential([
            layers.Input(shape=(self.input_dim,)),
            layers.Dense(128, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            
            layers.Dense(64, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            
            layers.Dense(32, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.2),
            
            layers.Dense(16, activation='relu'),
            
            layers.Dense(5, activation='softmax')  # 5 classes
        ])
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='categorical_crossentropy',
            metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall()]
        )
        
        return model
    
    def _build_cnn(self) -> keras.Model:
        """Xây dựng CNN (Convolutional Neural Network)"""
        model = models.Sequential([
            layers.Input(shape=(self.input_dim, 1)),
            
            layers.Conv1D(32, kernel_size=3, activation='relu', padding='same'),
            layers.BatchNormalization(),
            layers.MaxPooling1D(pool_size=2),
            layers.Dropout(0.3),
            
            layers.Conv1D(64, kernel_size=3, activation='relu', padding='same'),
            layers.BatchNormalization(),
            layers.MaxPooling1D(pool_size=2),
            layers.Dropout(0.3),
            
            layers.Flatten(),
            layers.Dense(128, activation='relu'),
            layers.Dropout(0.3),
            
            layers.Dense(64, activation='relu'),
            layers.Dropout(0.2),
            
            layers.Dense(5, activation='softmax')
        ])
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='categorical_crossentropy',
            metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall()]
        )
        
        return model
    
    def _build_lstm(self) -> keras.Model:
        """Xây dựng LSTM (Long Short-Term Memory)"""
        model = models.Sequential([
            layers.Input(shape=(self.input_dim, 1)),
            
            layers.LSTM(64, activation='relu', return_sequences=True),
            layers.Dropout(0.2),
            
            layers.LSTM(32, activation='relu'),
            layers.Dropout(0.2),
            
            layers.Dense(64, activation='relu'),
            layers.Dropout(0.3),
            
            layers.Dense(32, activation='relu'),
            
            layers.Dense(5, activation='softmax')
        ])
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='categorical_crossentropy',
            metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall()]
        )
        
        return model
    
    def train(self, 
              X_train: np.ndarray, 
              y_train: np.ndarray,
              X_val: Optional[np.ndarray] = None,
              y_val: Optional[np.ndarray] = None,
              epochs: int = 50,
              batch_size: int = 32) -> dict:
        """
        Huấn luyện mô hình
        
        Args:
            X_train: Training features (n_samples, n_features)
            y_train: Training labels (n_samples, n_classes) - one-hot encoded
            X_val: Validation features (optional)
            y_val: Validation labels (optional)
            epochs: Số epoch
            batch_size: Batch size
            
        Returns:
            Training history
        """
        try:
            # Reshape dữ liệu cho các architecture khác nhau
            if self.architecture in ['cnn', 'lstm']:
                X_train = X_train.reshape((X_train.shape[0], X_train.shape[1], 1))
                if X_val is not None:
                    X_val = X_val.reshape((X_val.shape[0], X_val.shape[1], 1))
            
            # Callbacks
            early_stop = callbacks.EarlyStopping(
                monitor='val_loss' if X_val is not None else 'loss',
                patience=10,
                restore_best_weights=True
            )
            
            reduce_lr = callbacks.ReduceLROnPlateau(
                monitor='val_loss' if X_val is not None else 'loss',
                factor=0.5,
                patience=5,
                min_lr=1e-6
            )
            
            # Training
            self.history = self.model.fit(
                X_train, y_train,
                validation_data=(X_val, y_val) if X_val is not None else None,
                epochs=epochs,
                batch_size=batch_size,
                callbacks=[early_stop, reduce_lr],
                verbose=1
            )
            
            logger.info("Model training completed successfully")
            return self.history.history
        
        except Exception as e:
            logger.error(f"Error training model: {str(e)}")
            raise
    
    def predict(self, X: np.ndarray, threshold: float = 0.5) -> Tuple[np.ndarray, np.ndarray]:
        """
        Dự đoán trên dữ liệu mới
        
        Args:
            X: Input features (n_samples, n_features)
            threshold: Ngưỡng confidence
            
        Returns:
            Tuple (predicted_classes, confidences)
        """
        try:
            # Reshape cho CNN/LSTM
            if self.architecture in ['cnn', 'lstm']:
                X = X.reshape((X.shape[0], X.shape[1], 1))
            
            # Predict probabilities
            predictions = self.model.predict(X, verbose=0)
            
            # Get predicted classes
            predicted_classes = np.argmax(predictions, axis=1)
            confidences = np.max(predictions, axis=1)
            
            # Áp dụng threshold
            predicted_classes[confidences < threshold] = 0  # Mặc định là Normal nếu confidence thấp
            
            return predicted_classes, confidences
        
        except Exception as e:
            logger.error(f"Error during prediction: {str(e)}")
            raise
    
    def save(self, model_path: str):
        """Lưu mô hình"""
        try:
            self.model.save(model_path)
            logger.info(f"Model saved to {model_path}")
        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
            raise
    
    def load(self, model_path: str):
        """Load mô hình"""
        try:
            self.model = keras.models.load_model(model_path)
            logger.info(f"Model loaded from {model_path}")
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise
    
    def get_summary(self) -> str:
        """Lấy tóm tắt mô hình"""
        if self.model:
            return self.model.summary()
        return "Model not initialized"
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> dict:
        """
        Đánh giá mô hình trên test set
        
        Args:
            X_test: Test features
            y_test: Test labels (one-hot encoded)
            
        Returns:
            Dictionary chứa các metric
        """
        try:
            # Reshape
            if self.architecture in ['cnn', 'lstm']:
                X_test = X_test.reshape((X_test.shape[0], X_test.shape[1], 1))
            
            results = self.model.evaluate(X_test, y_test, verbose=0)
            
            # Lấy tên metrics
            metric_names = ['loss'] + [m.name for m in self.model.metrics]
            
            evaluation_dict = {}
            for name, value in zip(metric_names, results):
                evaluation_dict[name] = float(value)
            
            logger.info(f"Model evaluation: {evaluation_dict}")
            return evaluation_dict
        
        except Exception as e:
            logger.error(f"Error evaluating model: {str(e)}")
            raise
