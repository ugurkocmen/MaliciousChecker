import requests
import json
import re
import time
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
import logging
from concurrent.futures import ThreadPoolExecutor
import threading
import sqlite3
import os

class ThreatIntelCollector:
    def __init__(self, db_path='threat_intel.db'):
        self.db_path = db_path
        self.setup_logging()
        self.setup_database()
        self.lock = threading.Lock()
        
    def setup_logging(self):
        # Create logs directory if it doesn't exist
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, 'threat_intel.log')
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('ThreatIntelCollector')
        
    def setup_database(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Tehdit veritabanı tablosu
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT NOT NULL,
                    type TEXT NOT NULL,
                    confidence_score INTEGER,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    source TEXT,
                    tags TEXT,
                    description TEXT,
                    UNIQUE(indicator, type)
                )
            ''')
            
            # Tehdit ilişkileri tablosu
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_relations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id INTEGER,
                    target_id INTEGER,
                    relation_type TEXT,
                    confidence_score INTEGER,
                    FOREIGN KEY (source_id) REFERENCES threats(id),
                    FOREIGN KEY (target_id) REFERENCES threats(id)
                )
            ''')
            
            conn.commit()
    
    def collect_phishing_domains(self):
        """Phishing domainlerini toplar"""
        try:
            # OpenPhish veya benzeri bir kaynaktan phishing domainleri çek
            domains = [
                {'indicator': 'malicious-example.com', 'type': 'domain', 'confidence': 80},
                {'indicator': 'phishing-example.net', 'type': 'domain', 'confidence': 75}
            ]
            
            for domain in domains:
                self.save_threat(
                    indicator=domain['indicator'],
                    type=domain['type'],
                    confidence_score=domain['confidence'],
                    source='OpenPhish',
                    tags='phishing'
                )
                
        except Exception as e:
            self.logger.error(f"Error collecting phishing domains: {str(e)}")
    
    def collect_malware_ips(self):
        """Zararlı IP'leri toplar"""
        try:
            # Blocklist.de veya benzeri bir kaynaktan IP'leri çek
            ips = [
                {'indicator': '192.168.1.100', 'type': 'ip', 'confidence': 90},
                {'indicator': '10.0.0.100', 'type': 'ip', 'confidence': 85}
            ]
            
            for ip in ips:
                self.save_threat(
                    indicator=ip['indicator'],
                    type=ip['type'],
                    confidence_score=ip['confidence'],
                    source='Blocklist.de',
                    tags='malware,attack'
                )
                
        except Exception as e:
            self.logger.error(f"Error collecting malware IPs: {str(e)}")
    
    def collect_ransomware_indicators(self):
        """Fidye yazılımı göstergelerini toplar"""
        try:
            # Ransomware Tracker veya benzeri bir kaynaktan göstergeleri çek
            indicators = [
                {'indicator': 'ransom-example.com', 'type': 'domain', 'confidence': 95},
                {'indicator': '192.168.2.100', 'type': 'ip', 'confidence': 90}
            ]
            
            for indicator in indicators:
                self.save_threat(
                    indicator=indicator['indicator'],
                    type=indicator['type'],
                    confidence_score=indicator['confidence'],
                    source='Ransomware Tracker',
                    tags='ransomware,malware'
                )
                
        except Exception as e:
            self.logger.error(f"Error collecting ransomware indicators: {str(e)}")
    
    def collect_c2_servers(self):
        """C2 sunucularını toplar"""
        try:
            # Feodo Tracker veya benzeri bir kaynaktan C2 sunucularını çek
            servers = [
                {'indicator': 'c2-example.com', 'type': 'domain', 'confidence': 95},
                {'indicator': '172.16.0.100', 'type': 'ip', 'confidence': 90}
            ]
            
            for server in servers:
                self.save_threat(
                    indicator=server['indicator'],
                    type=server['type'],
                    confidence_score=server['confidence'],
                    source='Feodo Tracker',
                    tags='c2,malware'
                )
                
        except Exception as e:
            self.logger.error(f"Error collecting C2 servers: {str(e)}")
    
    def save_threat(self, indicator, type, confidence_score=50, source=None, tags=None, description=None):
        """Tehdidi veritabanına kaydeder"""
        try:
            current_time = datetime.utcnow()
            with self.lock:  # Thread-safe database access
                with sqlite3.connect(self.db_path, timeout=20) as conn:  # Increased timeout
                    cursor = conn.cursor()
                    
                    cursor.execute('''
                        INSERT OR REPLACE INTO threats 
                        (indicator, type, confidence_score, first_seen, last_seen, source, tags, description)
                        VALUES (?, ?, ?, COALESCE((SELECT first_seen FROM threats WHERE indicator = ? AND type = ?), ?),
                                ?, ?, ?, ?)
                    ''', (indicator, type, confidence_score, indicator, type, current_time,
                          current_time, source, tags, description))
                    
                    conn.commit()
                    return True
        except Exception as e:
            self.logger.error(f"Error saving threat: {str(e)}")
            return False
    
    def is_valid_ip(self, ip):
        """IP adresinin geçerli olup olmadığını kontrol eder"""
        pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(pattern, ip))
    
    def collect_all(self):
        """Tüm tehdit kaynaklarından veri toplar"""
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(self.collect_phishing_domains),
                executor.submit(self.collect_malware_ips),
                executor.submit(self.collect_c2_servers),
                executor.submit(self.collect_ransomware_indicators)
            ]
            # Wait for all tasks to complete
            for future in futures:
                future.result()
    
    def get_recent_threats(self, limit=15):
        """Son tehditleri getir
        
        Args:
            limit (int): Getirilecek tehdit sayısı (varsayılan: 15)
            
        Returns:
            list: Son tehditlerin listesi
        """
        try:
            with self.get_db_connection() as conn:
                cursor = conn.cursor()
                # Tarihi düzgün formatta getir ve NULL değerleri kontrol et
                cursor.execute("""
                    SELECT 
                        t.id,
                        t.indicator,
                        t.type,
                        t.confidence_score,
                        CASE 
                            WHEN t.first_seen IS NULL THEN datetime('now')
                            ELSE datetime(t.first_seen)
                        END as first_seen,
                        CASE 
                            WHEN t.last_seen IS NULL THEN datetime('now')
                            ELSE datetime(t.last_seen)
                        END as last_seen,
                        t.source,
                        t.tags
                    FROM threats t
                    WHERE t.indicator IS NOT NULL 
                    AND t.indicator != ''
                    AND t.type IS NOT NULL
                    AND t.type != ''
                    ORDER BY first_seen DESC, id DESC
                    LIMIT ?
                """, (limit,))
                
                results = cursor.fetchall()
                
                # Sonuçları işle ve formatla
                formatted_results = []
                for row in results:
                    try:
                        # Tarihleri düzgün formatta string'e çevir
                        first_seen = datetime.strptime(row[4], '%Y-%m-%d %H:%M:%S')
                        last_seen = datetime.strptime(row[5], '%Y-%m-%d %H:%M:%S')
                        
                        formatted_results.append((
                            row[0],  # id
                            row[1],  # indicator
                            row[2],  # type
                            row[3],  # confidence_score
                            first_seen.strftime('%Y-%m-%d %H:%M:%S'),  # first_seen
                            last_seen.strftime('%Y-%m-%d %H:%M:%S'),  # last_seen
                            row[6],  # source
                            row[7]   # tags
                        ))
                    except (ValueError, TypeError) as e:
                        self.logger.error(f"Error formatting threat data: {str(e)}")
                        continue
                
                return formatted_results
                
        except Exception as e:
            self.logger.error(f"Error getting recent threats: {str(e)}")
            return []
    
    def get_db_connection(self):
        """Veritabanı bağlantısı oluştur"""
        return sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
    
    def search_threats(self, indicator=None, type=None, tags=None):
        """Tehdit veritabanında arama yapar"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                query = "SELECT * FROM threats WHERE 1=1"
                params = []
                
                if indicator:
                    query += " AND indicator LIKE ?"
                    params.append(f"%{indicator}%")
                
                if type:
                    query += " AND type = ?"
                    params.append(type)
                
                if tags:
                    query += " AND tags LIKE ?"
                    params.append(f"%{tags}%")
                
                cursor.execute(query, params)
                return cursor.fetchall()
        except Exception as e:
            self.logger.error(f"Error searching threats: {str(e)}")
            return []

    def scrape_ransomware_indicators(self):
        """Fidye yazılımı göstergelerini toplar (örnek fonksiyon)"""
        return [
            {'value': 'example.com', 'type': 'domain'},
            {'value': '192.168.1.1', 'type': 'ip'}
        ]

    def get_usom_threats(self):
        """USOM'dan zararlı bağlantıları çeker"""
        try:
            # USOM API URL'i
            url = "https://www.usom.gov.tr/api/address/index"
            
            # API'ye istek gönder
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            # JSON yanıtını parse et
            data = response.json()
            threats = []
            
            # Her tehdidi işle
            for item in data.get('models', []):
                # Tarih formatını düzelt
                date_str = item.get('date', '')
                try:
                    # USOM'un kullandığı tarih formatı: "2025-04-07 19.32.49"
                    # Önce noktalı kısımları tire ile değiştir
                    date_str = date_str.replace('.', ':')
                    first_seen = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    # Tarih parse edilemezse şu anki zamanı kullan
                    first_seen = datetime.now()
                
                threat = {
                    'indicator': item.get('url', ''),
                    'type': 'url',
                    'confidence_score': 90,  # USOM güvenilir bir kaynak olduğu için yüksek skor
                    'first_seen': first_seen,
                    'source': 'USOM',
                    'tags': 'malicious,usom',
                    'description': item.get('description', '')
                }
                
                # Tehdidi veritabanına kaydet
                self.save_threat(
                    indicator=threat['indicator'],
                    type=threat['type'],
                    confidence_score=threat['confidence_score'],
                    source=threat['source'],
                    tags=threat['tags'],
                    description=threat['description']
                )
                threats.append(threat)
            
            return threats
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"USOM tehditlerini çekerken hata oluştu: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"USOM tehditlerini işlerken hata oluştu: {str(e)}")
            return []
