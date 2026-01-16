"""
Искусственная иммунная система для Windows
"""

import sys
import numpy as np
import pandas as pd
import json
import time
import threading
import logging
import os
import pickle  # Добавлено для сохранения состояния
from datetime import datetime, timedelta
from collections import deque
import warnings
warnings.filterwarnings('ignore')

# Импорты для Windows мониторинга
import psutil
import socket
import platform
import subprocess
import ctypes

# Импорты для PyQt6
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QTextEdit,
                             QTabWidget, QGroupBox, QTableWidget, QTableWidgetItem,
                             QProgressBar, QSplitter, QFrame, QMessageBox,
                             QStatusBar, QSystemTrayIcon, QMenu, QDialog, QSpinBox, QCheckBox, QDoubleSpinBox)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QSize
from PyQt6.QtGui import QFont, QColor, QPalette, QIcon, QAction
import pyqtgraph as pg  # Для графиков

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ais_security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("AISecurity")

# ============================================
# БАЗОВЫЕ КЛАССЫ ИИС С СОХРАНЕНИЕМ СОСТОЯНИЯ
# ============================================

class StandardScaler:
    """Упрощенный StandardScaler с возможностью сохранения"""

    def __init__(self):
        self.mean_ = None
        self.scale_ = None

    def fit(self, X):
        self.mean_ = np.mean(X, axis=0)
        self.scale_ = np.std(X, axis=0)
        self.scale_[self.scale_ == 0] = 1.0
        return self

    def transform(self, X):
        if self.mean_ is None or self.scale_ is None:
            return X
        return (X - self.mean_) / self.scale_

    def fit_transform(self, X):
        self.fit(X)
        return self.transform(X)

    def get_state(self):
        """Получить состояние scaler для сохранения"""
        return {
            'mean': self.mean_.tolist() if self.mean_ is not None else None,
            'scale': self.scale_.tolist() if self.scale_ is not None else None
        }

    def set_state(self, state):
        """Восстановить состояние scaler из сохраненных данных"""
        if state['mean'] is not None:
            self.mean_ = np.array(state['mean'])
        if state['scale'] is not None:
            self.scale_ = np.array(state['scale'])

class IncidentLogger:
    """Логирование инцидентов в JSON файл"""
    
    def __init__(self, filename='ais_incidents.json'):
        self.filename = filename
        self.incidents = []
        self.load_existing_incidents()
        
    def load_existing_incidents(self):
        """Загрузка существующих инцидентов из файла"""
        try:
            if os.path.exists(self.filename):
                with open(self.filename, 'r', encoding='utf-8') as f:
                    self.incidents = json.load(f)
                logger.info(f"Загружено {len(self.incidents)} инцидентов из {self.filename}")
            else:
                self.incidents = []
        except Exception as e:
            logger.error(f"Ошибка загрузки инцидентов: {e}")
            self.incidents = []
            
    def log_incident(self, incident_data):
        """Логирование нового инцидента"""
        try:
            # Добавляем временную метку, если её нет
            if 'timestamp' not in incident_data:
                incident_data['timestamp'] = datetime.now().isoformat()
            
            # Конвертируем объекты datetime в строки
            incident_data = self._convert_for_json(incident_data)
            
            # Добавляем инцидент в список
            self.incidents.append(incident_data)
            
            # Сохраняем в файл
            self._save_to_file()
            
            logger.info(f"Инцидент записан: {incident_data.get('threat_level', 'unknown')} - {incident_data.get('timestamp')}")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка записи инцидента: {e}")
            return False
            
    def _convert_for_json(self, obj):
        """Конвертация объектов для JSON сериализации"""
        if isinstance(obj, dict):
            return {k: self._convert_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_for_json(item) for item in obj]
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, np.generic):
            return obj.item()
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, pd.Timestamp):
            return obj.isoformat()
        elif hasattr(obj, 'tolist'):
            return obj.tolist()
        else:
            return obj
            
    def _save_to_file(self):
        """Сохранение инцидентов в файл"""
        try:
            # Ограничиваем количество инцидентов (последние 1000)
            if len(self.incidents) > 1000:
                self.incidents = self.incidents[-1000:]
                
            with open(self.filename, 'w', encoding='utf-8') as f:
                json.dump(self.incidents, f, indent=2, ensure_ascii=False)
                
            return True
        except Exception as e:
            logger.error(f"Ошибка сохранения инцидентов: {e}")
            return False
            
    def get_incidents(self, limit=None):
        """Получение списка инцидентов"""
        if limit:
            return self.incidents[-limit:]
        return self.incidents.copy()
        
    def clear_incidents(self):
        """Очистка всех инцидентов"""
        self.incidents = []
        self._save_to_file()
        logger.info("Все инциденты очищены")

class ArtificialImmuneSystem:
    """Базовый класс искусственной иммунной системы с сохранением состояния"""

    def __init__(self, n_detectors=100, self_radius=0.1,
                 activation_threshold=0.7, memory_size=50):
        self.n_detectors = n_detectors
        self.self_radius = self_radius
        self.activation_threshold = activation_threshold
        self.memory_size = memory_size

        self.detectors = []
        self.self_patterns = []
        self.memory_cells = deque(maxlen=memory_size)
        self.anomaly_history = []
        self.scaler = StandardScaler()
        self.baseline_metrics = {}  # Добавлено для сохранения baseline
        self.trained = False  # Флаг обучения
        self.incident_logger = IncidentLogger()  # Логирование инцидентов

    def generate_self_patterns(self, normal_data, n_samples=1000):
        if len(normal_data) < n_samples:
            n_samples = len(normal_data)

        indices = np.random.choice(len(normal_data), n_samples, replace=False)
        self.self_patterns = normal_data[indices]

        # Нормализация данных
        self.self_patterns = self.scaler.fit_transform(self.self_patterns)
        self.trained = True

    def generate_detectors(self, max_attempts=1000):
        if len(self.self_patterns) == 0:
            logger.error("Нельзя генерировать детекторы без self-паттернов")
            return 0

        self.detectors = []
        attempts = 0

        while len(self.detectors) < self.n_detectors and attempts < max_attempts:
            detector = np.random.randn(self.self_patterns.shape[1])
            detector = detector / np.linalg.norm(detector)

            is_self = False
            for self_pattern in self.self_patterns:
                distance = np.linalg.norm(detector - self_pattern)
                if distance < self.self_radius:
                    is_self = True
                    break

            if not is_self:
                self.detectors.append({
                    'vector': detector,
                    'affinity': 0.0,
                    'age': 0,
                    'activation_count': 0
                })

            attempts += 1

        logger.info(f"Сгенерировано {len(self.detectors)} детекторов")
        return len(self.detectors)

    def calculate_similarity(self, vec1, vec2):
        distance = np.linalg.norm(vec1 - vec2)
        max_distance = np.linalg.norm(vec1) + np.linalg.norm(vec2)
        return 1.0 - (distance / max_distance) if max_distance > 0 else 0.0

    def detect_anomaly(self, data_point):
        if not self.trained:
            return False, 0.0, []

        if len(data_point.shape) == 1:
            data_point = data_point.reshape(1, -1)

        try:
            data_point = self.scaler.transform(data_point)[0]
        except:
            # Если scaler не обучен, используем сырые данные
            data_point = data_point[0]

        activated_detectors = []
        max_affinity = 0.0

        for detector in self.detectors:
            affinity = self.calculate_similarity(data_point, detector['vector'])

            if affinity > self.activation_threshold:
                activated_detectors.append({
                    'detector': detector['vector'],
                    'affinity': affinity
                })
                detector['activation_count'] += 1

                if affinity > max_affinity:
                    max_affinity = affinity

        is_anomaly = len(activated_detectors) > 0
        confidence = max_affinity * len(activated_detectors) / max(len(self.detectors), 1)

        return is_anomaly, confidence, activated_detectors

    def adaptive_response(self, anomaly_data, anomaly_type='unknown'):
        memory_entry = {
            'timestamp': datetime.now(),
            'data': anomaly_data,
            'type': anomaly_type,
            'detectors_activated': len(anomaly_data.get('activated_detectors', []))
        }
        self.memory_cells.append(memory_entry)

        if len(anomaly_data.get('activated_detectors', [])) > 0:
            self.clonal_selection(anomaly_data)

        self.anomaly_history.append({
            'timestamp': datetime.now(),
            'type': anomaly_type,
            'confidence': anomaly_data.get('confidence', 0),
            'activated_detectors': len(anomaly_data.get('activated_detectors', []))
        })
        
        # Логирование инцидента в JSON
        self._log_incident(anomaly_data, anomaly_type)

    def _log_incident(self, anomaly_data, anomaly_type):
        """Логирование инцидента в JSON файл"""
        try:
            incident = {
                'timestamp': datetime.now(),
                'incident_type': anomaly_type,
                'threat_level': anomaly_data.get('threat_level', 'unknown'),
                'confidence': float(anomaly_data.get('confidence', 0)),
                'activated_detectors_count': len(anomaly_data.get('activated_detectors', [])),
                'activated_detectors': [
                    {
                        'affinity': float(detector.get('affinity', 0)),
                        'vector': detector.get('detector', []).tolist() if hasattr(detector.get('detector', []), 'tolist') else list(detector.get('detector', []))
                    }
                    for detector in anomaly_data.get('activated_detectors', [])
                ],
                'system_metrics': anomaly_data.get('metrics', {}),
                'feature_vector': anomaly_data.get('feature_vector', []),
                'actions_taken': anomaly_data.get('actions_taken', []),
                'memory_cells_updated': True,
                'clonal_selection_performed': len(anomaly_data.get('activated_detectors', [])) > 0
            }
            
            # Добавляем информацию о системе
            incident['system_info'] = {
                'total_detectors': len(self.detectors),
                'memory_cells_count': len(self.memory_cells),
                'total_incidents': len(self.anomaly_history)
            }
            
            # Логируем инцидент
            self.incident_logger.log_incident(incident)
            
        except Exception as e:
            logger.error(f"Ошибка логирования инцидента: {e}")

    def clonal_selection(self, anomaly_data):
        if not anomaly_data.get('activated_detectors'):
            return

        best_detector = max(anomaly_data['activated_detectors'],
                          key=lambda x: x['affinity'])

        clone = best_detector['detector'].copy()
        mutation_rate = 0.1 * (1 - best_detector['affinity'])

        mutation = np.random.randn(len(clone)) * mutation_rate
        clone = clone + mutation
        clone = clone / np.linalg.norm(clone)

        is_self = False
        for self_pattern in self.self_patterns:
            if self.calculate_similarity(clone, self_pattern) > self.activation_threshold:
                is_self = True
                break

        if not is_self and len(self.detectors) < self.n_detectors * 1.5:
            self.detectors.append({
                'vector': clone,
                'affinity': best_detector['affinity'],
                'age': 0,
                'activation_count': 0
            })

    def update_detectors(self):
        for detector in self.detectors:
            detector['age'] += 1

        self.detectors = [
            d for d in self.detectors
            if not (d['age'] > 100 and d['activation_count'] == 0)
        ]

    def get_system_status(self):
        return {
            'total_detectors': len(self.detectors),
            'memory_cells': len(self.memory_cells),
            'anomalies_detected': len(self.anomaly_history),
            'avg_confidence': np.mean([a['confidence'] for a in self.anomaly_history])
                            if self.anomaly_history else 0,
            'trained': self.trained,
            'self_patterns_count': len(self.self_patterns),
            'incidents_logged': len(self.incident_logger.get_incidents())
        }

    def save_state(self, filename='ais_state.pkl'):
        """Сохранение состояния системы"""
        try:
            # Подготовка данных для сохранения
            state = {
                'detectors': self.detectors,
                'self_patterns': self.self_patterns,
                'scaler_state': self.scaler.get_state(),
                'memory_cells': list(self.memory_cells),
                'anomaly_history': self.anomaly_history,
                'baseline_metrics': self.baseline_metrics,
                'trained': self.trained,
                'config': {
                    'n_detectors': self.n_detectors,
                    'self_radius': self.self_radius,
                    'activation_threshold': self.activation_threshold
                }
            }

            with open(filename, 'wb') as f:
                pickle.dump(state, f)

            logger.info(f"Состояние системы сохранено в {filename}")
            return True

        except Exception as e:
            logger.error(f"Ошибка сохранения состояния: {e}")
            return False

    def load_state(self, filename='ais_state.pkl'):
        """Загрузка состояния системы"""
        try:
            if not os.path.exists(filename):
                logger.info(f"Файл состояния {filename} не найден, будет создана новая система")
                return False

            with open(filename, 'rb') as f:
                state = pickle.load(f)

            # Восстановление состояния
            self.detectors = state['detectors']
            self.self_patterns = state['self_patterns']
            self.scaler.set_state(state['scaler_state'])
            self.memory_cells = deque(state['memory_cells'], maxlen=self.memory_size)
            self.anomaly_history = state['anomaly_history']
            self.baseline_metrics = state.get('baseline_metrics', {})
            self.trained = state.get('trained', False)

            # Восстановление конфигурации (если есть)
            if 'config' in state:
                self.n_detectors = state['config'].get('n_detectors', self.n_detectors)
                self.self_radius = state['config'].get('self_radius', self.self_radius)
                self.activation_threshold = state['config'].get('activation_threshold', self.activation_threshold)

            logger.info(f"Состояние системы загружено из {filename}")
            logger.info(f"Загружено: {len(self.detectors)} детекторов, {len(self.self_patterns)} self-паттернов")
            return True

        except Exception as e:
            logger.error(f"Ошибка загрузки состояния: {e}")
            return False

    def retrain(self, normal_data, n_samples=1000):
        """Переобучение системы"""
        logger.info("Начато переобучение системы")

        # Сохраняем историю для восстановления
        old_memory_cells = list(self.memory_cells)
        old_anomaly_history = self.anomaly_history.copy()

        # Сброс системы
        self.detectors = []
        self.self_patterns = []
        self.memory_cells.clear()
        self.anomaly_history = []
        self.scaler = StandardScaler()
        self.trained = False

        # Новое обучение
        self.generate_self_patterns(normal_data, n_samples)
        detectors_count = self.generate_detectors()

        # Восстанавливаем память (но не все)
        self.memory_cells = deque(old_memory_cells[-self.memory_size//2:],
                                 maxlen=self.memory_size)
        self.anomaly_history = old_anomaly_history[-100:]  # Сохраняем последние 100 инцидентов

        logger.info(f"Переобучение завершено. Создано {detectors_count} детекторов")
        return detectors_count

# ============================================
# КЛАССЫ МОНИТОРИНГА С СОХРАНЕНИЕМ BASELINE
# ============================================

class WindowsSystemMonitor:
    """Мониторинг системных событий Windows с сохранением baseline"""

    def __init__(self):
        self.system_info = self.get_system_info()
        self.baseline_metrics = {}
        self.previous_metrics = {}
        self.metrics_history = deque(maxlen=1000)  # История метрик

    def get_system_info(self):
        return {
            'hostname': socket.gethostname(),
            'os': platform.platform(),
            'cpu_count': psutil.cpu_count(),
            'total_memory': psutil.virtual_memory().total,
            'windows_version': platform.version()
        }

    def collect_system_metrics(self):
        """Сбор текущих метрик системы"""
        try:
            # Системные метрики
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()

            # Сетевые метрики
            net_io = psutil.net_io_counters()

            # Дисковые метрики
            disk_io = psutil.disk_io_counters()

            # Процессы
            processes = []
            try:
                processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']))
            except:
                pass

            suspicious_processes = 0
            for p in processes:
                try:
                    info = p.info
                    if (info.get('cpu_percent', 0) > 50 or
                        info.get('memory_percent', 0) > 30):
                        suspicious_processes += 1
                except:
                    continue

            # Сетевые соединения
            connections = 0
            try:
                connections = len(psutil.net_connections())
            except:
                pass

            metrics = {
                # Системные
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'process_count': len(psutil.pids()),
                'suspicious_processes': suspicious_processes,

                # Сетевые
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'active_connections': connections,

                # Дисковые
                'disk_read_bytes': disk_io.read_bytes,
                'disk_write_bytes': disk_io.write_bytes,
                'disk_read_count': disk_io.read_count,
                'disk_write_count': disk_io.write_count,

                # Временные
                'timestamp': datetime.now(),
                'hour_of_day': datetime.now().hour,
                'is_working_hours': 8 <= datetime.now().hour <= 18,
            }

            # Расчет производных метрик
            if self.previous_metrics:
                time_diff = (metrics['timestamp'] - self.previous_metrics['timestamp']).total_seconds()
                if time_diff > 0:
                    metrics['bytes_sent_per_sec'] = (metrics['bytes_sent'] - self.previous_metrics['bytes_sent']) / time_diff
                    metrics['bytes_recv_per_sec'] = (metrics['bytes_recv'] - self.previous_metrics['bytes_recv']) / time_diff
                    metrics['disk_read_per_sec'] = (metrics['disk_read_bytes'] - self.previous_metrics['disk_read_bytes']) / time_diff
                    metrics['disk_write_per_sec'] = (metrics['disk_write_bytes'] - self.previous_metrics['disk_write_bytes']) / time_diff
                else:
                    metrics['bytes_sent_per_sec'] = 0
                    metrics['bytes_recv_per_sec'] = 0
                    metrics['disk_read_per_sec'] = 0
                    metrics['disk_write_per_sec'] = 0
            else:
                metrics['bytes_sent_per_sec'] = 0
                metrics['bytes_recv_per_sec'] = 0
                metrics['disk_read_per_sec'] = 0
                metrics['disk_write_per_sec'] = 0

            self.previous_metrics = metrics.copy()
            self.metrics_history.append(metrics)

            return metrics

        except Exception as e:
            logger.error(f"Ошибка сбора метрик: {e}")
            return {}

    def calculate_baseline(self, duration_sec=60):
        """Расчет baseline метрик"""
        logger.info(f"Расчет baseline за {duration_sec} секунд...")

        metrics_list = []
        start_time = datetime.now()

        while (datetime.now() - start_time).total_seconds() < duration_sec:
            metrics = self.collect_system_metrics()
            if metrics:
                metrics_list.append(metrics)
            time.sleep(2)  # Сбор каждые 2 секунды

        if metrics_list:
            df = pd.DataFrame(metrics_list)
            self.baseline_metrics = {
                col: {
                    'mean': float(df[col].mean()),
                    'std': float(df[col].std()),
                    'min': float(df[col].min()),
                    'max': float(df[col].max())
                }
                for col in df.columns if col not in ['timestamp']
            }

            logger.info(f"Baseline рассчитан для {len(df.columns)-1} метрик")
            return True

        logger.warning("Не удалось собрать данные для baseline")
        return False

    def get_baseline(self):
        """Получение текущего baseline"""
        return self.baseline_metrics.copy()

    def set_baseline(self, baseline):
        """Установка baseline"""
        self.baseline_metrics = baseline.copy()

    def save_baseline(self, filename='baseline.json'):
        """Сохранение baseline в файл"""
        try:
            # Конвертация для JSON
            baseline_json = {}
            for metric, stats in self.baseline_metrics.items():
                baseline_json[metric] = stats

            with open(filename, 'w') as f:
                json.dump(baseline_json, f, indent=2)

            logger.info(f"Baseline сохранен в {filename}")
            return True

        except Exception as e:
            logger.error(f"Ошибка сохранения baseline: {e}")
            return False

    def load_baseline(self, filename='baseline.json'):
        """Загрузка baseline из файла"""
        try:
            if not os.path.exists(filename):
                logger.info(f"Файл baseline {filename} не найден")
                return False

            with open(filename, 'r') as f:
                baseline_json = json.load(f)

            self.baseline_metrics = baseline_json
            logger.info(f"Baseline загружен из {filename}")
            return True

        except Exception as e:
            logger.error(f"Ошибка загрузки baseline: {e}")
            return False

# ============================================
# ПОТОК МОНИТОРИНГА С УЧЕТОМ СОХРАНЕННОГО СОСТОЯНИЯ
# ============================================

class MonitoringThread(QThread):
    """Поток для фонового мониторинга с сохранением состояния"""

    # Сигналы для обновления GUI
    metrics_updated = pyqtSignal(dict)  # Новые метрики
    anomaly_detected = pyqtSignal(dict)  # Обнаружена аномалия
    status_updated = pyqtSignal(dict)    # Статус системы
    training_progress = pyqtSignal(int)  # Прогресс обучения
    training_completed = pyqtSignal()    # Обучение завершено
    training_skipped = pyqtSignal()      # Обучение пропущено (уже обучено)

    def __init__(self, ais_system, config):
        super().__init__()
        self.ais = ais_system
        self.config = config
        self.running = False
        self.stop_event = threading.Event()
        self.need_training = not ais_system.trained  # Проверка необходимости обучения

    def run(self):
        """Основной цикл мониторинга"""
        self.running = True
        logger.info("Поток мониторинга запущен")

        # Проверка необходимости обучения
        if self.need_training:
            self._training_phase()
        else:
            logger.info("Пропуск обучения - система уже обучена")
            self.training_skipped.emit()
            self.training_completed.emit()  # Все равно сигнализируем о готовности

        # Основной цикл мониторинга
        iteration = 0
        while self.running and not self.stop_event.is_set():
            try:
                metrics = self.ais.monitor.collect_system_metrics()
                if metrics:
                    # Преобразование в вектор признаков
                    feature_vector = self.ais._prepare_feature_vector(metrics)

                    # Обнаружение аномалий
                    is_anomaly, confidence, activated = self.ais.detect_anomaly(feature_vector)

                    # Событие
                    event = {
                        'timestamp': datetime.now(),
                        'metrics': metrics,
                        'is_anomaly': is_anomaly,
                        'confidence': confidence,
                        'activated_detectors': activated,
                        'feature_vector': feature_vector.tolist() if hasattr(feature_vector, 'tolist') else list(feature_vector)
                    }

                    # Отправка сигналов в GUI
                    self.metrics_updated.emit(metrics)
                    self.status_updated.emit(self.ais.get_system_status())

                    if is_anomaly:
                        # Реагирование
                        threat_level = self.ais._assess_threat_level(event)
                        
                        # Определение действий в зависимости от уровня угрозы
                        actions_taken = []
                        if threat_level == 'high':
                            actions_taken = ["network_isolation", "process_blocking", "file_quarantine"]
                        elif threat_level == 'medium':
                            actions_taken = ["process_blocking", "restoration_point"]
                        else:
                            actions_taken = ["logging", "enhanced_monitoring"]
                        
                        anomaly_data = {
                            'confidence': float(confidence),
                            'activated_detectors': activated,
                            'threat_level': threat_level,
                            'timestamp': event['timestamp'],
                            'metrics': metrics,
                            'feature_vector': feature_vector.tolist() if hasattr(feature_vector, 'tolist') else list(feature_vector),
                            'actions_taken': actions_taken
                        }
                        
                        self.ais.adaptive_response(anomaly_data, 'auto_detected')

                        # Отправка сигнала об аномалии
                        self.anomaly_detected.emit({
                            'threat_level': threat_level,
                            'confidence': confidence,
                            'detectors': len(activated),
                            'metrics': metrics,
                            'actions_taken': actions_taken
                        })

                    # Периодическое обслуживание и сохранение
                    if iteration % 50 == 0:
                        self.ais.update_detectors()
                        # Автосохранение каждые 100 итераций
                        if iteration % 100 == 0:
                            self.ais.save_state()
                            self.ais.monitor.save_baseline()

                    iteration += 1

                # Пауза
                self.stop_event.wait(timeout=self.config.get('monitoring_interval', 2))

            except Exception as e:
                logger.error(f"Ошибка в потоке мониторинга: {e}")
                time.sleep(5)

        # Финальное сохранение при остановке
        self.ais.save_state()
        self.ais.monitor.save_baseline()
        logger.info("Поток мониторинга остановлен")

    def _training_phase(self):
        """Фаза обучения с обновлением прогресса"""
        logger.info("Начало фазы обучения")
        training_data = []
        duration = self.config.get('training_duration', 300)  # 5 минут по умолчанию

        # Сначала собираем baseline
        self.ais.monitor.calculate_baseline(duration_sec=min(60, duration))

        for i in range(duration // 2):  # Каждые 2 секунды
            if not self.running or self.stop_event.is_set():
                break

            metrics = self.ais.monitor.collect_system_metrics()
            if metrics:
                feature_vector = self.ais._prepare_feature_vector(metrics)
                training_data.append(feature_vector)

            # Отправка прогресса
            progress = int((i + 1) / (duration // 2) * 100)
            self.training_progress.emit(progress)

            time.sleep(2)

        if training_data:
            training_array = np.array(training_data)
            self.ais.generate_self_patterns(training_array)
            detectors_count = self.ais.generate_detectors()

            # Сохранение состояния после обучения
            self.ais.save_state()
            self.ais.monitor.save_baseline()

            logger.info(f"Обучение завершено. Создано {detectors_count} детекторов")
            self.training_completed.emit()

    def retrain(self):
        """Запуск переобучения"""
        logger.info("Запуск переобучения")
        self.need_training = True
        self._training_phase()

    def stop(self):
        """Остановка потока"""
        self.running = False
        self.stop_event.set()
        self.wait(5000)  # Ожидаем до 5 секунд

# ============================================
# ГЛАВНОЕ ОКНО ПРОГРАММЫ С ПОЛНЫМ ЭКРАНОМ
# ============================================

class MainWindow(QMainWindow):
    """Главное окно приложения с графическим интерфейсом"""

    def __init__(self):
        super().__init__()
        self.ais = None
        self.monitor_thread = None
        self.is_monitoring = False

        # Инициализация UI
        self.init_ui()

        # Таймер для обновления UI
        self.ui_timer = QTimer()
        self.ui_timer.timeout.connect(self.update_ui)
        self.ui_timer.start(1000)  # Обновление каждую секунду

        # Загрузка конфигурации
        self.load_config()

        # Системный трей
        self.setup_system_tray()

        # Открытие на весь экран
        self.showMaximized()

    def init_ui(self):
        """Инициализация пользовательского интерфейса"""
        self.setWindowTitle("Ais Windows")

        # Устанавливаем минимальный размер
        self.setMinimumSize(1000, 700)

        # Центральный виджет
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Основной layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        # Верхняя панель с кнопками управления
        control_panel = self.create_control_panel()
        main_layout.addWidget(control_panel)

        # Splitter для основного содержимого
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(5)

        # Левая панель - мониторинг
        left_panel = self.create_monitoring_panel()
        splitter.addWidget(left_panel)

        # Правая панель - детали и логи
        right_panel = self.create_details_panel()
        splitter.addWidget(right_panel)

        splitter.setSizes([700, 500])
        main_layout.addWidget(splitter)

        # Статус бар
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Система неактивна")

        # Стилизация
        self.apply_styles()

    def create_control_panel(self):
        """Создание панели управления с кнопкой переобучения"""
        panel = QWidget()
        layout = QHBoxLayout(panel)
        layout.setSpacing(10)

        # Кнопки управления
        self.btn_start = QPushButton("▶ Запуск мониторинга")
        self.btn_start.clicked.connect(self.start_monitoring)
        self.btn_start.setFixedHeight(40)
        self.btn_start.setMinimumWidth(150)

        self.btn_stop = QPushButton("⏹ Остановить")
        self.btn_stop.clicked.connect(self.stop_monitoring)
        self.btn_stop.setFixedHeight(40)
        self.btn_stop.setMinimumWidth(150)
        self.btn_stop.setEnabled(False)

        self.btn_retrain = QPushButton("🔄 Переобучить")
        self.btn_retrain.clicked.connect(self.confirm_retraining)
        self.btn_retrain.setFixedHeight(40)
        self.btn_retrain.setMinimumWidth(150)
        self.btn_retrain.setToolTip("Переобучить систему на текущем поведении")

        self.btn_settings = QPushButton("⚙ Настройки")
        self.btn_settings.clicked.connect(self.show_settings)
        self.btn_settings.setFixedHeight(40)
        self.btn_settings.setMinimumWidth(150)
        
        self.btn_view_incidents = QPushButton("📋 Просмотр инцидентов")
        self.btn_view_incidents.clicked.connect(self.view_incidents)
        self.btn_view_incidents.setFixedHeight(40)
        self.btn_view_incidents.setMinimumWidth(150)
        self.btn_view_incidents.setToolTip("Просмотр журнала инцидентов в JSON формате")

        # Индикаторы
        self.lbl_status = QLabel("Статус: Остановлено")
        self.lbl_status.setStyleSheet("font-weight: bold; color: red; padding: 5px;")
        self.lbl_status.setMinimumWidth(150)

        self.lbl_training = QLabel("Обучение: Нет")
        self.lbl_training.setStyleSheet("padding: 5px;")
        self.lbl_training.setMinimumWidth(150)

        self.lbl_threat = QLabel("Уровень угрозы: НОРМА")
        self.lbl_threat.setStyleSheet("font-weight: bold; color: green; padding: 5px; border: 1px solid #ccc; border-radius: 3px;")
        self.lbl_threat.setMinimumWidth(200)

        # Прогресс бар для обучения
        self.progress_training = QProgressBar()
        self.progress_training.setVisible(False)
        self.progress_training.setMinimumWidth(200)

        # Разделитель
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.VLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)

        layout.addWidget(self.btn_start)
        layout.addWidget(self.btn_stop)
        layout.addWidget(separator)
        layout.addWidget(self.btn_retrain)
        layout.addWidget(self.btn_settings)
        layout.addWidget(self.btn_view_incidents)
        layout.addStretch()
        layout.addWidget(self.lbl_status)
        layout.addWidget(self.lbl_training)
        layout.addWidget(self.lbl_threat)
        layout.addWidget(self.progress_training)

        return panel

    def create_monitoring_panel(self):
        """Создание панели мониторинга"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setSpacing(10)

        # Графики мониторинга
        self.graph_widget = pg.GraphicsLayoutWidget()
        self.graph_widget.setBackground('w')

        # График CPU
        self.cpu_plot = self.graph_widget.addPlot(title="Загрузка CPU (%)", row=0, col=0)
        self.cpu_curve = self.cpu_plot.plot(pen=pg.mkPen(color='r', width=2))
        self.cpu_data = []
        self.cpu_plot.setYRange(0, 100)
        self.cpu_plot.setLabel('left', 'CPU %')
        self.cpu_plot.setLabel('bottom', 'Время')
        self.cpu_plot.showGrid(x=True, y=True, alpha=0.3)

        # График памяти
        self.memory_plot = self.graph_widget.addPlot(title="Использование памяти (%)", row=1, col=0)
        self.memory_curve = self.memory_plot.plot(pen=pg.mkPen(color='b', width=2))
        self.memory_data = []
        self.memory_plot.setYRange(0, 100)
        self.memory_plot.setLabel('left', 'Память %')
        self.memory_plot.showGrid(x=True, y=True, alpha=0.3)

        # График сети
        self.network_plot = self.graph_widget.addPlot(title="Сетевая активность (КБ/сек)", row=2, col=0)
        self.network_sent_curve = self.network_plot.plot(pen=pg.mkPen(color='g', width=2), name="Отправлено")
        self.network_recv_curve = self.network_plot.plot(pen=pg.mkPen(color='y', width=2), name="Получено")
        self.network_sent_data = []
        self.network_recv_data = []
        self.network_plot.addLegend()
        self.network_plot.showGrid(x=True, y=True, alpha=0.3)

        layout.addWidget(self.graph_widget)

        # Таблица процессов
        process_group = QGroupBox("🔍 Активные процессы (подозрительные выделены)")
        process_layout = QVBoxLayout()

        self.process_table = QTableWidget()
        self.process_table.setColumnCount(4)
        self.process_table.setHorizontalHeaderLabels(["PID", "Имя процесса", "CPU %", "Память %"])
        self.process_table.horizontalHeader().setStretchLastSection(True)
        self.process_table.setMaximumHeight(200)

        process_layout.addWidget(self.process_table)
        process_group.setLayout(process_layout)

        layout.addWidget(process_group)

        return panel

    def create_details_panel(self):
        """Создание панели деталей и логов"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setSpacing(10)

        # Вкладки
        tabs = QTabWidget()
        tabs.setTabPosition(QTabWidget.TabPosition.North)

        # Вкладка статуса системы
        status_tab = QWidget()
        status_layout = QVBoxLayout(status_tab)

        # Статистика системы
        stats_group = QGroupBox("📊 Статистика системы")
        stats_layout = QVBoxLayout()

        self.lbl_detectors = QLabel("Детекторов: 0")
        self.lbl_anomalies = QLabel("Аномалий обнаружено: 0")
        self.lbl_memory_cells = QLabel("Клеток памяти: 0")
        self.lbl_avg_confidence = QLabel("Средняя уверенность: 0%")
        self.lbl_self_patterns = QLabel("Self-паттернов: 0")
        self.lbl_system_trained = QLabel("Система обучена: Нет")
        self.lbl_incidents_logged = QLabel("Инцидентов в журнале: 0")

        stats_layout.addWidget(self.lbl_detectors)
        stats_layout.addWidget(self.lbl_anomalies)
        stats_layout.addWidget(self.lbl_memory_cells)
        stats_layout.addWidget(self.lbl_avg_confidence)
        stats_layout.addWidget(self.lbl_self_patterns)
        stats_layout.addWidget(self.lbl_system_trained)
        stats_layout.addWidget(self.lbl_incidents_logged)
        stats_group.setLayout(stats_layout)

        status_layout.addWidget(stats_group)

        # Текущие метрики
        metrics_group = QGroupBox("📈 Текущие метрики")
        metrics_layout = QVBoxLayout()

        self.lbl_cpu = QLabel("CPU: --%")
        self.lbl_memory = QLabel("Память: --%")
        self.lbl_processes = QLabel("Процессы: --")
        self.lbl_network_sent = QLabel("Сеть отправлено: -- КБ/сек")
        self.lbl_network_recv = QLabel("Сеть получено: -- КБ/сек")
        self.lbl_disk_read = QLabel("Диск чтение: -- КБ/сек")
        self.lbl_disk_write = QLabel("Диск запись: -- КБ/сек")

        metrics_layout.addWidget(self.lbl_cpu)
        metrics_layout.addWidget(self.lbl_memory)
        metrics_layout.addWidget(self.lbl_processes)
        metrics_layout.addWidget(self.lbl_network_sent)
        metrics_layout.addWidget(self.lbl_network_recv)
        metrics_layout.addWidget(self.lbl_disk_read)
        metrics_layout.addWidget(self.lbl_disk_write)
        metrics_group.setLayout(metrics_layout)

        status_layout.addWidget(metrics_group)
        status_layout.addStretch()

        tabs.addTab(status_tab, "📊 Статус")

        # Вкладка логов
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(400)
        self.log_text.setStyleSheet("font-family: 'Courier New'; font-size: 10pt;")

        log_layout.addWidget(QLabel("📝 Журнал событий:"))
        log_layout.addWidget(self.log_text)

        # Кнопки управления логами
        log_buttons = QHBoxLayout()
        btn_clear_log = QPushButton("🗑 Очистить")
        btn_clear_log.clicked.connect(self.clear_log)
        btn_save_log = QPushButton("💾 Сохранить")
        btn_save_log.clicked.connect(self.save_log)
        btn_export_state = QPushButton("📤 Экспорт состояния")
        btn_export_state.clicked.connect(self.export_state)
        btn_export_incidents = QPushButton("📤 Экспорт инцидентов")
        btn_export_incidents.clicked.connect(self.export_incidents)

        log_buttons.addWidget(btn_clear_log)
        log_buttons.addWidget(btn_save_log)
        log_buttons.addWidget(btn_export_state)
        log_buttons.addWidget(btn_export_incidents)
        log_buttons.addStretch()

        log_layout.addLayout(log_buttons)

        tabs.addTab(log_tab, "📝 Логи")

        # Вкладка инцидентов
        incidents_tab = QWidget()
        incidents_layout = QVBoxLayout(incidents_tab)

        self.incidents_table = QTableWidget()
        self.incidents_table.setColumnCount(6)
        self.incidents_table.setHorizontalHeaderLabels(["Время", "Уровень", "Уверенность", "Детекторов", "Действия", "Статус"])
        self.incidents_table.horizontalHeader().setStretchLastSection(True)

        incidents_layout.addWidget(QLabel("⚠️ История инцидентов:"))
        incidents_layout.addWidget(self.incidents_table)

        tabs.addTab(incidents_tab, "⚠️ Инциденты")

        layout.addWidget(tabs)

        return panel

    def apply_styles(self):
        """Применение стилей к интерфейсу"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 12px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 11pt;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #0D47A1;
            }
            QPushButton:disabled {
                background-color: #BDBDBD;
                color: #757575;
            }
            QGroupBox {
                font-weight: bold;
                font-size: 11pt;
                border: 2px solid #BDBDBD;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background-color: white;
                color: black;  /* ДОБАВЛЕНО: явно задаем черный цвет текста */
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px 0 10px;
                color: #2196F3;
            }
            QTableWidget {
                background-color: white;
                alternate-background-color: #F5F5F5;
                border: 1px solid #E0E0E0;
                font-size: 10pt;
                color: black;  /* ДОБАВЛЕНО: явно задаем черный цвет текста */
            }
            QTableWidget::item {
                padding: 5px;
                color: black;  /* ДОБАВЛЕНО: явно задаем черный цвет текста */
            }
            QTableWidget::item:selected {
                background-color: #2196F3;
                color: white;
            }
            QTextEdit {
                background-color: white;
                border: 1px solid #E0E0E0;
                font-family: 'Courier New';
                font-size: 10pt;
                padding: 5px;
                color: black;  /* ДОБАВЛЕНО: явно задаем черный цвет текста */
            }
            QProgressBar {
                border: 1px solid #BDBDBD;
                border-radius: 4px;
                text-align: center;
                font-weight: bold;
                background-color: white;
                color: black;  /* ДОБАВЛЕНО: явно задаем черный цвет текста */
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 3px;
            }
            QTabWidget::pane {
                border: 1px solid #BDBDBD;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #E0E0E0;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                color: black;  /* ДОБАВЛЕНО: явно задаем черный цвет текста */
            }
            QTabBar::tab:selected {
                background-color: white;
                font-weight: bold;
                color: black;  /* ДОБАВЛЕНО: явно задаем черный цвет текста */
            }
            QTabBar::tab:hover {
                background-color: #F5F5F5;
                color: black;  /* ДОБАВЛЕНО: явно задаем черный цвет текста */
            }
            QStatusBar {
                background-color: #E0E0E0;
                color: #424242;
                font-weight: bold;
            }
            /* ДОБАВЛЕНО: стили для меток (QLabel) */
            QLabel {
                color: black;
            }
            /* ДОБАВЛЕНО: стили для полей ввода (QSpinBox, QDoubleSpinBox) */
            QSpinBox, QDoubleSpinBox {
                background-color: white;
                color: black;
                border: 1px solid #BDBDBD;
                border-radius: 3px;
                padding: 3px;
            }
        """)

    def apply_dialog_styles(self):
        """Применение стилей для окна настроек"""
        self.setStyleSheet("""
            QDialog {
                background-color: white;
            }
            QGroupBox {
                font-weight: bold;
                font-size: 11pt;
                border: 2px solid #BDBDBD;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background-color: white;
                color: black;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px 0 10px;
                color: #2196F3;
            }
            QLabel {
                color: black;
                background-color: transparent;
            }
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 12px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 11pt;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #0D47A1;
            }
            QCheckBox {
                color: black;
                spacing: 8px;
                font-size: 10pt;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QSpinBox, QDoubleSpinBox {
                background-color: white;
                color: black;
                border: 1px solid #BDBDBD;
                border-radius: 3px;
                padding: 5px;
                selection-background-color: #2196F3;
                selection-color: white;
            }
            QSpinBox::up-button, QSpinBox::down-button,
            QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {
                width: 20px;
                border: 1px solid #BDBDBD;
                background-color: #E0E0E0;
            }
            QSpinBox::up-button:hover, QSpinBox::down-button:hover,
            QDoubleSpinBox::up-button:hover, QDoubleSpinBox::down-button:hover {
                background-color: #BDBDBD;
            }
        """)

    def setup_system_tray(self):
        """Настройка системного трея"""
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray_icon = QSystemTrayIcon(self)

            # Создание меню трея
            tray_menu = QMenu()

            show_action = QAction("📊 Показать панель", self)
            show_action.triggered.connect(self.showNormal)
            show_action.triggered.connect(self.activateWindow)
            tray_menu.addAction(show_action)

            tray_menu.addSeparator()

            start_action = QAction("▶ Запустить мониторинг", self)
            start_action.triggered.connect(self.start_monitoring)
            tray_menu.addAction(start_action)

            stop_action = QAction("⏹ Остановить мониторинг", self)
            stop_action.triggered.connect(self.stop_monitoring)
            tray_menu.addAction(stop_action)

            retrain_action = QAction("🔄 Переобучить систему", self)
            retrain_action.triggered.connect(self.confirm_retraining)
            tray_menu.addAction(retrain_action)
            
            view_incidents_action = QAction("📋 Просмотр инцидентов", self)
            view_incidents_action.triggered.connect(self.view_incidents)
            tray_menu.addAction(view_incidents_action)

            tray_menu.addSeparator()

            settings_action = QAction("⚙ Настройки", self)
            settings_action.triggered.connect(self.show_settings)
            tray_menu.addAction(settings_action)

            tray_menu.addSeparator()

            quit_action = QAction("🚪 Выход", self)
            quit_action.triggered.connect(self.close)
            tray_menu.addAction(quit_action)

            self.tray_icon.setContextMenu(tray_menu)

            # Установка иконки
            self.tray_icon.setToolTip("ИИС - Защита Windows\nСтатус: Неактивна")
            self.tray_icon.show()

    def load_config(self):
        """Загрузка конфигурации"""
        self.config = {
            'n_detectors': 200,
            'self_radius': 0.15,
            'activation_threshold': 0.8,
            'memory_size': 100,
            'monitoring_interval': 2,
            'training_duration': 60,  # 1 минута для демо
            'enable_active_response': True,
            'auto_save_state': True,
            'save_interval': 100
        }

        # Попытка загрузки из файла
        try:
            if os.path.exists('ais_config.json'):
                with open('ais_config.json', 'r') as f:
                    saved_config = json.load(f)
                    self.config.update(saved_config)
                self.log_message("⚙ Конфигурация загружена из файла")
        except Exception as e:
            logger.error(f"Ошибка загрузки конфигурации: {e}")
            self.log_message(f"❌ Ошибка загрузки конфигурации: {e}")

    def start_monitoring(self):
        """Запуск мониторинга с проверкой сохраненного состояния"""
        if self.is_monitoring:
            return

        try:
            # Создание системы AIS
            self.ais = WindowsAISGUI(self.config)

            # Попытка загрузки сохраненного состояния
            state_loaded = self.ais.load_state()
            baseline_loaded = self.ais.monitor.load_baseline()

            if state_loaded and baseline_loaded:
                self.log_message("✅ Загружено сохраненное состояние системы")
                self.log_message(f"📊 Загружено: {len(self.ais.detectors)} детекторов, {len(self.ais.self_patterns)} self-паттернов")
                self.lbl_training.setText("Обучение: Загружено")
                self.lbl_training.setStyleSheet("font-weight: bold; color: green; padding: 5px;")
            else:
                self.log_message("📚 Система требует обучения")
                self.ais.training_mode = True
                self.lbl_training.setText("Обучение: Требуется")
                self.lbl_training.setStyleSheet("font-weight: bold; color: orange; padding: 5px;")

            # Создание и запуск потока мониторинга
            self.monitor_thread = MonitoringThread(self.ais, self.config)
            self.monitor_thread.metrics_updated.connect(self.on_metrics_updated)
            self.monitor_thread.anomaly_detected.connect(self.on_anomaly_detected)
            self.monitor_thread.status_updated.connect(self.on_status_updated)
            self.monitor_thread.training_progress.connect(self.on_training_progress)
            self.monitor_thread.training_completed.connect(self.on_training_completed)
            self.monitor_thread.training_skipped.connect(self.on_training_skipped)

            # Запуск
            self.monitor_thread.start()
            self.is_monitoring = True

            # Обновление UI
            self.btn_start.setEnabled(False)
            self.btn_stop.setEnabled(True)
            self.btn_retrain.setEnabled(True)
            self.lbl_status.setText("Статус: АКТИВЕН")
            self.lbl_status.setStyleSheet("font-weight: bold; color: green; padding: 5px;")

            # Обновление трея
            if hasattr(self, 'tray_icon'):
                self.tray_icon.setToolTip("ИИС - Защита Windows\nСтатус: Активна")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось запустить мониторинг: {str(e)}")
            logger.error(f"Ошибка запуска мониторинга: {e}")
            self.log_message(f"❌ Ошибка запуска мониторинга: {e}")

    def stop_monitoring(self):
        """Остановка мониторинга"""
        if not self.is_monitoring:
            return

        try:
            # Остановка потока
            if self.monitor_thread:
                self.monitor_thread.stop()
                self.monitor_thread = None

            self.is_monitoring = False

            # Обновление UI
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.lbl_status.setText("Статус: ОСТАНОВЛЕНО")
            self.lbl_status.setStyleSheet("font-weight: bold; color: red; padding: 5px;")
            self.progress_training.setVisible(False)

            # Обновление трея
            if hasattr(self, 'tray_icon'):
                self.tray_icon.setToolTip("ИИС - Защита Windows\nСтатус: Неактивна")

        except Exception as e:
            logger.error(f"Ошибка остановки мониторинга: {e}")
            self.log_message(f"❌ Ошибка остановки мониторинга: {e}")

    def confirm_retraining(self):
        """Подтверждение переобучения системы"""
        if not self.is_monitoring:
            QMessageBox.warning(self, "Предупреждение",
                              "Мониторинг не активен. Запустите мониторинг для переобучения.")
            return

        # Диалог подтверждения
        reply = QMessageBox.question(
            self, 'Подтверждение переобучения',
            'Вы уверены, что хотите переобучить систему?\n\n'
            'Это действие:\n'
            '• Удалит текущие детекторы и self-паттерны\n'
            '• Создаст новые на основе текущего поведения\n'
            '• Сохранит часть истории инцидентов\n'
            '• Займет несколько минут\n\n'
            'Текущее состояние системы будет сохранено в backup.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.start_retraining()

    def start_retraining(self):
        """Запуск переобучения системы"""
        try:
            # Создаем backup текущего состояния
            backup_filename = f"ais_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pkl"
            if self.ais.save_state(backup_filename):
                self.log_message(f"📂 Backup состояния сохранен в {backup_filename}")

            # Показываем прогресс
            self.progress_training.setVisible(True)
            self.progress_training.setValue(0)
            self.lbl_training.setText("Обучение: Переобучение...")
            self.lbl_training.setStyleSheet("font-weight: bold; color: orange; padding: 5px;")

            # Блокируем кнопки во время переобучения
            self.btn_retrain.setEnabled(False)
            self.btn_start.setEnabled(False)
            self.btn_stop.setEnabled(False)

            # Запуск переобучения в отдельном потоке
            self.retrain_thread = RetrainingThread(self.ais, self.config)
            self.retrain_thread.progress_updated.connect(self.on_training_progress)
            self.retrain_thread.retraining_completed.connect(self.on_retraining_completed)
            self.retrain_thread.start()

            self.log_message("🔄 Начато переобучение системы...")

        except Exception as e:
            logger.error(f"Ошибка запуска переобучения: {e}")
            self.log_message(f"❌ Ошибка переобучения: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось запустить переобучение: {str(e)}")

    def on_retraining_completed(self, detectors_count):
        """Обработка завершения переобучения"""
        # Разблокируем кнопки
        self.btn_retrain.setEnabled(True)
        self.btn_stop.setEnabled(True)

        # Скрываем прогресс
        self.progress_training.setVisible(False)

        # Обновляем статус
        self.lbl_training.setText("Обучение: Переобучено")
        self.lbl_training.setStyleSheet("font-weight: bold; color: green; padding: 5px;")

        # Сообщение в лог
        self.log_message(f"✅ Переобучение завершено! Создано {detectors_count} новых детекторов")

        # Уведомление
        if hasattr(self, 'tray_icon'):
            self.tray_icon.showMessage(
                "Переобучение завершено",
                f"Создано {detectors_count} новых детекторов",
                QSystemTrayIcon.MessageIcon.Information,
                3000
            )

        # Обновляем статистику
        if self.ais:
            status = self.ais.get_system_status()
            self.on_status_updated(status)

    def on_metrics_updated(self, metrics):
        """Обработка обновления метрик"""
        # Обновление текстовых меток
        self.lbl_cpu.setText(f"CPU: {metrics.get('cpu_percent', 0):.1f}%")
        self.lbl_memory.setText(f"Память: {metrics.get('memory_percent', 0):.1f}%")
        self.lbl_processes.setText(f"Процессы: {metrics.get('process_count', 0)}")

        # Сетевая активность
        sent_kbps = metrics.get('bytes_sent_per_sec', 0) / 1024
        recv_kbps = metrics.get('bytes_recv_per_sec', 0) / 1024
        self.lbl_network_sent.setText(f"Сеть отправлено: {sent_kbps:.1f} КБ/сек")
        self.lbl_network_recv.setText(f"Сеть получено: {recv_kbps:.1f} КБ/сек")

        # Дисковая активность
        read_kbps = metrics.get('disk_read_per_sec', 0) / 1024
        write_kbps = metrics.get('disk_write_per_sec', 0) / 1024
        self.lbl_disk_read.setText(f"Диск чтение: {read_kbps:.1f} КБ/сек")
        self.lbl_disk_write.setText(f"Диск запись: {write_kbps:.1f} КБ/сек")

        # Обновление графиков
        self.update_graphs(metrics)

        # Обновление таблицы процессов
        self.update_process_table()

    def on_anomaly_detected(self, anomaly_info):
        """Обработка обнаруженной аномалии"""
        threat_level = anomaly_info.get('threat_level', 'low')
        confidence = anomaly_info.get('confidence', 0)
        detectors = anomaly_info.get('detectors', 0)
        actions_taken = anomaly_info.get('actions_taken', [])

        # Обновление индикатора угрозы
        if threat_level == 'high':
            self.lbl_threat.setText("Уровень угрозы: ⚠️ ВЫСОКИЙ")
            self.lbl_threat.setStyleSheet("font-weight: bold; color: white; background-color: red; padding: 8px; border-radius: 5px;")

            # Звуковое предупреждение
            try:
                import winsound
                for _ in range(3):
                    winsound.Beep(1000, 300)
                    time.sleep(0.1)
            except:
                pass
        elif threat_level == 'medium':
            self.lbl_threat.setText("Уровень угрозы: 🔶 СРЕДНИЙ")
            self.lbl_threat.setStyleSheet("font-weight: bold; color: black; background-color: orange; padding: 8px; border-radius: 5px;")
        else:
            self.lbl_threat.setText("Уровень угрозы: 📊 НИЗКИЙ")
            self.lbl_threat.setStyleSheet("font-weight: bold; color: white; background-color: blue; padding: 8px; border-radius: 5px;")

        # Добавление в таблицу инцидентов
        row = self.incidents_table.rowCount()
        self.incidents_table.insertRow(row)

        self.incidents_table.setItem(row, 0, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))

        level_item = QTableWidgetItem(threat_level.upper())
        if threat_level == 'high':
            level_item.setBackground(QColor(255, 200, 200))  # Красный
        elif threat_level == 'medium':
            level_item.setBackground(QColor(255, 255, 200))  # Желтый
        else:
            level_item.setBackground(QColor(200, 255, 200))  # Зеленый
        self.incidents_table.setItem(row, 1, level_item)

        self.incidents_table.setItem(row, 2, QTableWidgetItem(f"{confidence:.1%}"))
        self.incidents_table.setItem(row, 3, QTableWidgetItem(str(detectors)))

        # Отображение предпринятых действий
        actions_text = ""
        if threat_level == 'high':
            actions_text = "🔒 Изоляция сети, 📁 Карантин файлов, 🛑 Блокировка процессов"
        elif threat_level == 'medium':
            actions_text = "🛑 Блокировка процессов, 💾 Точка восстановления"
        else:
            actions_text = "📝 Логирование, 👁 Усиленный мониторинг"
            
        self.incidents_table.setItem(row, 4, QTableWidgetItem(actions_text))
        self.incidents_table.setItem(row, 5, QTableWidgetItem("✅ Обработан"))

        # Запись в лог
        self.log_message(f"⚠️ АНОМАЛИЯ: Уровень {threat_level.upper()}, Уверенность {confidence:.1%}, Детекторов {detectors}")
        self.log_message(f"   Предпринятые действия: {', '.join(actions_taken)}")

        # Уведомление в трей
        if hasattr(self, 'tray_icon'):
            icon_map = {
                'high': QSystemTrayIcon.MessageIcon.Critical,
                'medium': QSystemTrayIcon.MessageIcon.Warning,
                'low': QSystemTrayIcon.MessageIcon.Information
            }

            self.tray_icon.showMessage(
                f"Обнаружена аномалия ({threat_level})",
                f"Уверенность: {confidence:.1%}\nДетекторов: {detectors}\nДействия: {', '.join(actions_taken)}",
                icon_map.get(threat_level, QSystemTrayIcon.MessageIcon.Information),
                5000
            )

    def on_status_updated(self, status):
        """Обновление статуса системы"""
        self.lbl_detectors.setText(f"Детекторов: {status.get('total_detectors', 0)}")
        self.lbl_anomalies.setText(f"Аномалий обнаружено: {status.get('anomalies_detected', 0)}")
        self.lbl_memory_cells.setText(f"Клеток памяти: {status.get('memory_cells', 0)}")

        avg_conf = status.get('avg_confidence', 0)
        self.lbl_avg_confidence.setText(f"Средняя уверенность: {avg_conf:.1%}")

        self.lbl_self_patterns.setText(f"Self-паттернов: {status.get('self_patterns_count', 0)}")

        trained = status.get('trained', False)
        self.lbl_system_trained.setText(f"Система обучена: {'Да' if trained else 'Нет'}")
        if trained:
            self.lbl_system_trained.setStyleSheet("color: green; font-weight: bold;")
        else:
            self.lbl_system_trained.setStyleSheet("color: red; font-weight: bold;")
            
        incidents_logged = status.get('incidents_logged', 0)
        self.lbl_incidents_logged.setText(f"Инцидентов в журнале: {incidents_logged}")

    def on_training_progress(self, progress):
        """Обновление прогресса обучения"""
        self.progress_training.setValue(progress)
        self.status_bar.showMessage(f"Обучение системы: {progress}%")

    def on_training_completed(self):
        """Обучение завершено"""
        self.progress_training.setVisible(False)
        self.log_message("✅ Обучение завершено! Система готова к работе.")
        self.status_bar.showMessage("Система активна и обучена")
        self.lbl_training.setText("Обучение: Завершено")
        self.lbl_training.setStyleSheet("font-weight: bold; color: green; padding: 5px;")

        if hasattr(self, 'tray_icon'):
            self.tray_icon.showMessage(
                "Обучение завершено",
                "Система готова к обнаружению угроз",
                QSystemTrayIcon.MessageIcon.Information,
                3000
            )

    def on_training_skipped(self):
        """Обучение пропущено (система уже обучена)"""
        self.log_message("✅ Используется сохраненное состояние системы")
        self.status_bar.showMessage("Используется сохраненное состояние")
        self.lbl_training.setText("Обучение: Загружено")
        self.lbl_training.setStyleSheet("font-weight: bold; color: blue; padding: 5px;")

    def update_graphs(self, metrics):
        """Обновление графиков"""
        # Ограничение истории
        max_history = 100

        # CPU
        self.cpu_data.append(metrics.get('cpu_percent', 0))
        if len(self.cpu_data) > max_history:
            self.cpu_data.pop(0)
        self.cpu_curve.setData(self.cpu_data)

        # Память
        self.memory_data.append(metrics.get('memory_percent', 0))
        if len(self.memory_data) > max_history:
            self.memory_data.pop(0)
        self.memory_curve.setData(self.memory_data)

        # Сеть
        sent_kbps = metrics.get('bytes_sent_per_sec', 0) / 1024
        recv_kbps = metrics.get('bytes_recv_per_sec', 0) / 1024

        self.network_sent_data.append(sent_kbps)
        self.network_recv_data.append(recv_kbps)

        if len(self.network_sent_data) > max_history:
            self.network_sent_data.pop(0)
            self.network_recv_data.pop(0)

        self.network_sent_curve.setData(self.network_sent_data)
        self.network_recv_curve.setData(self.network_recv_data)

    def update_process_table(self):
        """Обновление таблицы процессов"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    info = proc.info
                    processes.append({
                        'pid': info['pid'],
                        'name': info['name'] or 'Unknown',
                        'cpu': info['cpu_percent'],
                        'memory': info['memory_percent']
                    })
                except:
                    continue

            # Сортировка по использованию CPU
            processes.sort(key=lambda x: x['cpu'], reverse=True)

            # Ограничение до 20 процессов
            processes = processes[:20]

            self.process_table.setRowCount(len(processes))

            for i, proc in enumerate(processes):
                self.process_table.setItem(i, 0, QTableWidgetItem(str(proc['pid'])))
                self.process_table.setItem(i, 1, QTableWidgetItem(proc['name']))

                cpu_item = QTableWidgetItem(f"{proc['cpu']:.1f}%")
                memory_item = QTableWidgetItem(f"{proc['memory']:.1f}%")

                self.process_table.setItem(i, 2, cpu_item)
                self.process_table.setItem(i, 3, memory_item)

                # Подсветка подозрительных процессов
                if proc['cpu'] > 80 or proc['memory'] > 50:
                    cpu_item.setBackground(QColor(255, 200, 200))
                    memory_item.setBackground(QColor(255, 200, 200))
                elif proc['cpu'] > 50 or proc['memory'] > 30:
                    cpu_item.setBackground(QColor(255, 255, 200))
                    memory_item.setBackground(QColor(255, 255, 200))

        except Exception as e:
            logger.error(f"Ошибка обновления таблицы процессов: {e}")

    def update_ui(self):
        """Периодическое обновление UI"""
        if not self.is_monitoring:
            return

        # Обновление времени в статус баре
        current_time = datetime.now().strftime("%H:%M:%S")
        self.status_bar.showMessage(f"Мониторинг активен | {current_time} | Автосохранение включено")

    def log_message(self, message):
        """Добавление сообщения в лог"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")

        # Прокрутка вниз
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def clear_log(self):
        """Очистка лога"""
        self.log_text.clear()
        self.log_message("🗑 Лог очищен")

    def save_log(self):
        """Сохранение лога в файл"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ais_log_{timestamp}.txt"

            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.log_text.toPlainText())

            self.log_message(f"📁 Лог сохранен в {filename}")
            QMessageBox.information(self, "Сохранено", f"Лог сохранен в {filename}")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить лог: {str(e)}")
            self.log_message(f"❌ Ошибка сохранения лога: {e}")
            
    def export_incidents(self):
        """Экспорт инцидентов в отдельный файл"""
        if not self.ais:
            QMessageBox.warning(self, "Предупреждение", "Система не инициализирована")
            return
            
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ais_incidents_export_{timestamp}.json"
            
            # Получаем все инциденты
            incidents = self.ais.incident_logger.get_incidents()
            
            if not incidents:
                QMessageBox.information(self, "Информация", "Нет инцидентов для экспорта")
                return
                
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(incidents, f, indent=2, ensure_ascii=False)
                
            self.log_message(f"📤 Экспортировано {len(incidents)} инцидентов в {filename}")
            QMessageBox.information(self, "Экспорт", 
                                  f"Экспортировано {len(incidents)} инцидентов в:\n{filename}")
            
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось экспортировать инциденты: {str(e)}")
            self.log_message(f"❌ Ошибка экспорта инцидентов: {e}")
            
    def view_incidents(self):
        """Просмотр журнала инцидентов"""
        if not self.ais:
            QMessageBox.warning(self, "Предупреждение", "Система не инициализирована")
            return
            
        try:
            # Получаем последние 50 инцидентов
            incidents = self.ais.incident_logger.get_incidents(limit=50)
            
            if not incidents:
                QMessageBox.information(self, "Информация", "Журнал инцидентов пуст")
                return
                
            # Создаем диалоговое окно для просмотра
            dialog = QDialog(self)
            dialog.setWindowTitle("Журнал инцидентов")
            dialog.setGeometry(200, 200, 800, 600)
            
            layout = QVBoxLayout()
            
            # Текст для отображения JSON
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setFont(QFont("Courier New", 10))
            text_edit.setText(json.dumps(incidents, indent=2, ensure_ascii=False))
            
            # Кнопки
            button_layout = QHBoxLayout()
            btn_close = QPushButton("Закрыть")
            btn_refresh = QPushButton("Обновить")
            btn_export = QPushButton("Экспортировать")
            
            btn_close.clicked.connect(dialog.accept)
            btn_refresh.clicked.connect(lambda: self.refresh_incidents_view(text_edit))
            btn_export.clicked.connect(self.export_incidents)
            
            button_layout.addWidget(btn_refresh)
            button_layout.addWidget(btn_export)
            button_layout.addStretch()
            button_layout.addWidget(btn_close)
            
            layout.addWidget(QLabel(f"Последние {len(incidents)} инцидентов:"))
            layout.addWidget(text_edit)
            layout.addLayout(button_layout)
            
            dialog.setLayout(layout)
            dialog.exec()
            
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось открыть журнал инцидентов: {str(e)}")
            logger.error(f"Ошибка просмотра инцидентов: {e}")
            
    def refresh_incidents_view(self, text_edit):
        """Обновление просмотра инцидентов"""
        if not self.ais:
            return
            
        try:
            incidents = self.ais.incident_logger.get_incidents(limit=50)
            text_edit.setText(json.dumps(incidents, indent=2, ensure_ascii=False))
        except Exception as e:
            logger.error(f"Ошибка обновления просмотра инцидентов: {e}")

    def export_state(self):
        """Экспорт состояния системы"""
        if not self.ais:
            QMessageBox.warning(self, "Предупреждение", "Система не инициализирована")
            return

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ais_export_{timestamp}.pkl"

            if self.ais.save_state(filename):
                self.log_message(f"📤 Состояние системы экспортировано в {filename}")
                QMessageBox.information(self, "Экспорт",
                                      f"Состояние системы экспортировано в:\n{filename}")
            else:
                raise Exception("Не удалось сохранить состояние")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось экспортировать состояние: {str(e)}")
            self.log_message(f"❌ Ошибка экспорта состояния: {e}")

    def show_settings(self):
        """Показ окна настроек"""
        settings_dialog = SettingsDialog(self.config, self)
        if settings_dialog.exec() == QDialog.DialogCode.Accepted:
            # Сохранение новых настроек
            self.config = settings_dialog.get_config()

            # Сохранение в файл
            try:
                with open('ais_config.json', 'w') as f:
                    json.dump(self.config, f, indent=2)
                self.log_message("⚙ Конфигурация обновлена")

                # Применение новых настроек к текущей системе
                if self.ais:
                    self.ais.n_detectors = self.config.get('n_detectors', 200)
                    self.ais.self_radius = self.config.get('self_radius', 0.15)
                    self.ais.activation_threshold = self.config.get('activation_threshold', 0.8)
                    self.ais.memory_size = self.config.get('memory_size', 100)

            except Exception as e:
                logger.error(f"Ошибка сохранения конфигурации: {e}")
                self.log_message(f"❌ Ошибка сохранения конфигурации: {e}")

    def closeEvent(self, event):
        """Обработка закрытия окна"""
        if self.is_monitoring:
            reply = QMessageBox.question(
                self, 'Подтверждение',
                'Мониторинг активен. Вы уверены, что хотите выйти?\n\n'
                'Состояние системы будет автоматически сохранено.',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                # Сохраняем состояние перед выходом
                if self.ais:
                    self.ais.save_state()
                    self.ais.monitor.save_baseline()
                    self.log_message("💾 Состояние системы сохранено перед выходом")

                self.stop_monitoring()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

# ============================================
# ПОТОК ПЕРЕОБУЧЕНИЯ
# ============================================

class RetrainingThread(QThread):
    """Поток для переобучения системы"""

    progress_updated = pyqtSignal(int)
    retraining_completed = pyqtSignal(int)

    def __init__(self, ais_system, config):
        super().__init__()
        self.ais = ais_system
        self.config = config

    def run(self):
        """Процесс переобучения"""
        try:
            # Сбор данных для переобучения
            training_data = []
            duration = self.config.get('training_duration', 300)

            for i in range(duration // 2):
                metrics = self.ais.monitor.collect_system_metrics()
                if metrics:
                    feature_vector = self.ais._prepare_feature_vector(metrics)
                    training_data.append(feature_vector)

                # Отправка прогресса
                progress = int((i + 1) / (duration // 2) * 100)
                self.progress_updated.emit(progress)

                time.sleep(2)

            if training_data:
                training_array = np.array(training_data)
                detectors_count = self.ais.retrain(training_array)

                # Сохранение нового состояния
                self.ais.save_state()
                self.ais.monitor.save_baseline()

                self.retraining_completed.emit(detectors_count)

        except Exception as e:
            logger.error(f"Ошибка в потоке переобучения: {e}")

# ============================================
# КЛАСС AIS ДЛЯ GUI
# ============================================

class WindowsAISGUI(ArtificialImmuneSystem):
    """Искусственная иммунная система для Windows с поддержкой GUI"""

    def __init__(self, config):
        super().__init__(
            n_detectors=config.get('n_detectors', 200),
            self_radius=config.get('self_radius', 0.15),
            activation_threshold=config.get('activation_threshold', 0.8),
            memory_size=config.get('memory_size', 100)
        )

        self.config = config
        self.monitor = WindowsSystemMonitor()
        self.training_mode = False  # По умолчанию не требуем обучения

    def _prepare_feature_vector(self, metrics):
        """Подготовка вектора признаков"""
        key_metrics = [
            'cpu_percent',
            'memory_percent',
            'suspicious_processes',
            'bytes_sent_per_sec',
            'bytes_recv_per_sec',
            'active_connections',
            'disk_read_per_sec',
            'disk_write_per_sec'
        ]

        vector = []
        for metric in key_metrics:
            value = metrics.get(metric, 0)

            # Нормализация с учетом baseline
            baseline = self.monitor.baseline_metrics.get(metric, {})
            baseline_mean = baseline.get('mean', 0)
            baseline_std = baseline.get('std', 1)

            if baseline_std > 0:
                normalized = (value - baseline_mean) / baseline_std
            else:
                normalized = 0

            vector.append(normalized)

        return np.array(vector)

    def _assess_threat_level(self, event):
        """Оценка уровня угрозы"""
        confidence = event['confidence']
        detectors = event['activated_detectors']

        if confidence > 0.9 and detectors > 5:
            return 'high'
        elif confidence > 0.7 and detectors > 3:
            return 'medium'
        elif confidence > 0.5:
            return 'low'
        else:
            return 'info'

# ============================================
# ДИАЛОГ НАСТРОЕК (БЕЗ ИЗМЕНЕНИЙ)
# ============================================

class SettingsDialog(QDialog):
    """Диалоговое окно настроек"""

    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config.copy()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Настройки системы")
        self.setGeometry(300, 300, 400, 500)

        # Явно задаем стиль для диалога настроек
        self.setStyleSheet("""
            QDialog {
                background-color: white;
            }
            QGroupBox {
                font-weight: bold;
                font-size: 11pt;
                border: 2px solid #BDBDBD;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                background-color: white;
                color: black;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 10px 0 10px;
                color: #2196F3;
            }
            QLabel {
                color: black;
                background-color: transparent;
            }
            QCheckBox {
                color: black;
                background-color: transparent;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
            QSpinBox, QDoubleSpinBox {
                background-color: white;
                color: black;
                border: 1px solid #BDBDBD;
                border-radius: 3px;
                padding: 3px;
            }
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 12px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 11pt;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)

        layout = QVBoxLayout()

        # Настройки детекторов
        detector_group = QGroupBox("Настройки детекторов")
        detector_layout = QVBoxLayout()

        detector_layout.addWidget(QLabel("Количество детекторов:"))
        self.spin_detectors = QSpinBox()
        self.spin_detectors.setRange(50, 1000)
        self.spin_detectors.setValue(self.config.get('n_detectors', 200))
        detector_layout.addWidget(self.spin_detectors)

        detector_layout.addWidget(QLabel("Радиус self-распознавания:"))
        self.spin_radius = QDoubleSpinBox()
        self.spin_radius.setRange(0.01, 1.0)
        self.spin_radius.setSingleStep(0.01)
        self.spin_radius.setValue(self.config.get('self_radius', 0.15))
        detector_layout.addWidget(self.spin_radius)

        detector_layout.addWidget(QLabel("Порог активации:"))
        self.spin_threshold = QDoubleSpinBox()
        self.spin_threshold.setRange(0.1, 1.0)
        self.spin_threshold.setSingleStep(0.05)
        self.spin_threshold.setValue(self.config.get('activation_threshold', 0.8))
        detector_layout.addWidget(self.spin_threshold)

        detector_group.setLayout(detector_layout)
        layout.addWidget(detector_group)

        # Настройки мониторинга
        monitor_group = QGroupBox("Настройки мониторинга")
        monitor_layout = QVBoxLayout()

        monitor_layout.addWidget(QLabel("Интервал мониторинга (сек):"))
        self.spin_interval = QSpinBox()
        self.spin_interval.setRange(1, 60)
        self.spin_interval.setValue(self.config.get('monitoring_interval', 2))
        monitor_layout.addWidget(self.spin_interval)

        monitor_layout.addWidget(QLabel("Время обучения (сек):"))
        self.spin_training = QSpinBox()
        self.spin_training.setRange(30, 1800)
        self.spin_training.setValue(self.config.get('training_duration', 300))
        monitor_layout.addWidget(self.spin_training)

        monitor_layout.addWidget(QLabel("Размер памяти:"))
        self.spin_memory = QSpinBox()
        self.spin_memory.setRange(10, 1000)
        self.spin_memory.setValue(self.config.get('memory_size', 100))
        monitor_layout.addWidget(self.spin_memory)

        monitor_group.setLayout(monitor_layout)
        layout.addWidget(monitor_group)

        # Дополнительные настройки
        advanced_group = QGroupBox("Дополнительные настройки")
        advanced_layout = QVBoxLayout()

        self.cb_active_response = QCheckBox("Активное реагирование")
        self.cb_active_response.setChecked(self.config.get('enable_active_response', True))
        self.cb_active_response.setStyleSheet("color: black;")
        advanced_layout.addWidget(self.cb_active_response)

        self.cb_auto_save = QCheckBox("Автосохранение состояния")
        self.cb_auto_save.setChecked(self.config.get('auto_save_state', True))
        self.cb_auto_save.setStyleSheet("color: black;")
        advanced_layout.addWidget(self.cb_auto_save)

        self.cb_notifications = QCheckBox("Показывать уведомления")
        self.cb_notifications.setChecked(self.config.get('show_notifications', True))
        self.cb_notifications.setStyleSheet("color: black;")
        advanced_layout.addWidget(self.cb_notifications)

        advanced_group.setLayout(advanced_layout)
        layout.addWidget(advanced_group)

        # Кнопки
        button_layout = QHBoxLayout()
        btn_ok = QPushButton("OK")
        btn_cancel = QPushButton("Отмена")
        btn_default = QPushButton("По умолчанию")

        btn_ok.clicked.connect(self.accept)
        btn_cancel.clicked.connect(self.reject)
        btn_default.clicked.connect(self.reset_defaults)

        button_layout.addWidget(btn_default)
        button_layout.addStretch()
        button_layout.addWidget(btn_cancel)
        button_layout.addWidget(btn_ok)

        layout.addLayout(button_layout)

        self.setLayout(layout)

    def get_config(self):
        """Получение конфигурации из UI"""
        return {
            'n_detectors': self.spin_detectors.value(),
            'self_radius': self.spin_radius.value(),
            'activation_threshold': self.spin_threshold.value(),
            'memory_size': self.spin_memory.value(),
            'monitoring_interval': self.spin_interval.value(),
            'training_duration': self.spin_training.value(),
            'enable_active_response': self.cb_active_response.isChecked(),
            'auto_save_state': self.cb_auto_save.isChecked(),
            'show_notifications': self.cb_notifications.isChecked()
        }

    def reset_defaults(self):
        """Сброс настроек по умолчанию"""
        defaults = {
            'n_detectors': 200,
            'self_radius': 0.15,
            'activation_threshold': 0.8,
            'memory_size': 100,
            'monitoring_interval': 2,
            'training_duration': 300,
            'enable_active_response': True,
            'auto_save_state': True,
            'show_notifications': True
        }

        self.spin_detectors.setValue(defaults['n_detectors'])
        self.spin_radius.setValue(defaults['self_radius'])
        self.spin_threshold.setValue(defaults['activation_threshold'])
        self.spin_memory.setValue(defaults['memory_size'])
        self.spin_interval.setValue(defaults['monitoring_interval'])
        self.spin_training.setValue(defaults['training_duration'])
        self.cb_active_response.setChecked(defaults['enable_active_response'])
        self.cb_auto_save.setChecked(defaults['auto_save_state'])
        self.cb_notifications.setChecked(defaults['show_notifications'])

# ============================================
# ТОЧКА ВХОДА ПРОГРАММЫ
# ============================================

def main():
    """Главная функция запуска"""
    # Проверка прав администратора
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        is_admin = False

    # Создание приложения
    app = QApplication(sys.argv)
    app.setApplicationName("AIS Security System")

    # Установка стиля
    app.setStyle('Fusion')

    if not is_admin:
        # Предупреждение о правах
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Icon.Warning)
        msg_box.setWindowTitle("Предупреждение")
        msg_box.setText("Программа запущена без прав администратора!")
        msg_box.setInformativeText("Некоторые функции могут быть недоступны.\nДля полной функциональности запустите от имени администратора.")
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.exec()

    # Создание и показ главного окна
    window = MainWindow()
    window.showMaximized()  # Открываем на весь экран

    # Запуск приложения
    sys.exit(app.exec())


if __name__ == "__main__":
    main()