"""
Optimized ML Anomaly Detector
- Uses Isolation Forest with vectorized batch inference
- Caches feature extraction results to avoid lock re-acquisition
- Online training with configurable interval
"""

import numpy as np
import time
import threading
from collections import deque
from sklearn.ensemble import IsolationForest


class MLDetector:
    """
    Real-time anomaly detector using Isolation Forest.
    Optimized for high-throughput packet processing.
    """

    def __init__(self, n_estimators=50, contamination=0.05):
        # Fewer estimators = faster inference with minimal accuracy loss
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,
            max_samples="auto", # auto adjusts to n_samples if < 256
            n_jobs=-1           # use all available CPU cores
        )
        self.is_trained = False
        self.feature_history = deque(maxlen=2000)

        # Inference cache: (payload_size, rate_bin, port_count, proto) -> score
        self._cache = {}
        self._cache_max = 5000 # Increased cache size
        self._lock = threading.Lock()

        # Training throttle — train at most once every 30 seconds
        self._last_train_time = 0.0
        self._train_interval = 30.0

    # ─── Feature Extraction ───────────────────────────────────────────────────

    _PROTO_MAP = {"TCP": 1, "UDP": 2, "ICMP": 3, "QUIC": 4, "OTHER": 0}

    def _extract_features_raw(self, packet_rate, port_count, payload, proto_val) -> tuple:
        """Return a hashable feature key (coarsened for cache effectiveness)."""
        # Coarsen values for cache hits (round to nearest bucket)
        payload_bin  = (payload >> 6)          # 64-byte buckets
        rate_bin     = int(packet_rate * 2)    # 0.5-unit buckets
        return (payload_bin, rate_bin, port_count, proto_val)

    def _key_to_array(self, key: tuple) -> np.ndarray:
        payload_bin, rate_bin, port_count, proto_val = key
        return np.array([payload_bin * 64, rate_bin / 2.0, port_count, proto_val])

    # ─── Prediction ───────────────────────────────────────────────────────────

    def predict_anomaly(self, profile, meta) -> float:
        """
        Returns an anomaly score >= 0.
        Higher = more anomalous. Thread-safe.
        """
        # Read profile stats once to minimize lock contention
        packet_rate = profile.get_packet_rate(window_sec=10)
        port_count = profile.get_recent_port_count(window_sec=60)
        payload = meta.get("payload_size", 0)
        proto_val = self._PROTO_MAP.get(meta.get("protocol", "OTHER"), 0)

        key = self._extract_features_raw(packet_rate, port_count, payload, proto_val)
        features_arr = self._key_to_array(key)

        # Always record history for online training
        with self._lock:
            self.feature_history.append(features_arr)

            # Check cache first
            cached = self._cache.get(key)
            if cached is not None:
                return cached

        # Not in cache — need to run inference or schedule training
        now = time.time()

        # Trigger online training if needed
        if not self.is_trained:
            with self._lock:
                if len(self.feature_history) >= 100 and not self.is_trained:
                    self._train_online_locked()
            return 0.0

        # Inference
        try:
            score = self.model.decision_function(features_arr.reshape(1, -1))[0]
            threat_delta = round(max(0.0, -score * 10), 2)
        except Exception:
            threat_delta = 0.0

        # Store in cache
        with self._lock:
            if len(self._cache) >= self._cache_max:
                # Evict half the cache (poor man's LRU)
                keys = list(self._cache.keys())
                for k in keys[:len(keys)//2]:
                    del self._cache[k]
            self._cache[key] = threat_delta

        # Periodic retraining (non-blocking — defer to next call)
        if now - self._last_train_time > self._train_interval:
            self._schedule_retrain()

        return threat_delta

    # ─── Online Training ──────────────────────────────────────────────────────

    def _train_online_locked(self):
        """Called under self._lock."""
        try:
            X = np.array(list(self.feature_history))
            self.model.fit(X)
            self.is_trained = True
            self._cache.clear()   # invalidate cache after refit
            self._last_train_time = time.time()
        except Exception as e:
            print(f"[MLDetector] Training error: {e}")

    def _schedule_retrain(self):
        """Retrain in background thread to avoid blocking the packet pipeline."""
        t = threading.Thread(target=self._retrain_background, daemon=True)
        t.start()

    def _retrain_background(self):
        with self._lock:
            if time.time() - self._last_train_time < self._train_interval:
                return  # Another thread already retrained
            self._train_online_locked()


# Global singleton
ml_detector = MLDetector(n_estimators=50, contamination=0.05)
