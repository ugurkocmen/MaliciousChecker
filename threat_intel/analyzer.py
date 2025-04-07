import sqlite3
import json
import re
import math
from datetime import datetime, timedelta
import networkx as nx
from collections import defaultdict
import logging
import os

class ThreatAnalyzer:
    def __init__(self, db_path='threat_intel.db'):
        self.db_path = db_path
        self.setup_logging()
        
    def setup_logging(self):
        # Create logs directory if it doesn't exist
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, 'threat_analysis.log')
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('ThreatAnalyzer')
    
    def analyze_threat_patterns(self, timeframe_hours=24):
        """Tehdit paternlerini analiz eder"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                since = datetime.utcnow() - timedelta(hours=timeframe_hours)
                
                # Tehdit türlerine göre dağılım
                cursor.execute('''
                    SELECT type, COUNT(*) as count
                    FROM threats
                    WHERE last_seen >= ?
                    GROUP BY type
                    ORDER BY count DESC
                ''', (since,))
                
                type_distribution = cursor.fetchall()
                
                # Güven skorlarına göre dağılım
                cursor.execute('''
                    SELECT 
                        CASE 
                            WHEN confidence_score >= 90 THEN 'Very High'
                            WHEN confidence_score >= 70 THEN 'High'
                            WHEN confidence_score >= 50 THEN 'Medium'
                            ELSE 'Low'
                        END as confidence_level,
                        COUNT(*) as count
                    FROM threats
                    WHERE last_seen >= ?
                    GROUP BY confidence_level
                    ORDER BY count DESC
                ''', (since,))
                
                confidence_distribution = cursor.fetchall()
                
                # Kaynaklara göre dağılım
                cursor.execute('''
                    SELECT source, COUNT(*) as count
                    FROM threats
                    WHERE last_seen >= ?
                    GROUP BY source
                    ORDER BY count DESC
                ''', (since,))
                
                source_distribution = cursor.fetchall()
                
                return {
                    'type_distribution': type_distribution,
                    'confidence_distribution': confidence_distribution,
                    'source_distribution': source_distribution
                }
        except Exception as e:
            self.logger.error(f"Error analyzing threat patterns: {str(e)}")
            return None
    
    def calculate_threat_score(self, indicator):
        """Belirli bir gösterge için tehdit skorunu hesaplar"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Temel bilgileri al
                cursor.execute('''
                    SELECT confidence_score, type, tags, source
                    FROM threats
                    WHERE indicator = ?
                    ORDER BY last_seen DESC
                    LIMIT 1
                ''', (indicator,))
                
                result = cursor.fetchone()
                if not result:
                    return 0
                
                base_score = result[0]  # confidence_score
                threat_type = result[1]
                tags = result[2].split(',') if result[2] else []
                source = result[3]
                
                # Tip bazlı ağırlıklar
                type_weights = {
                    'ip': 1.2,
                    'domain': 1.1,
                    'url': 1.0,
                    'hash': 1.3
                }
                
                # Tag bazlı ağırlıklar
                tag_weights = {
                    'malware': 1.3,
                    'phishing': 1.2,
                    'ransomware': 1.4,
                    'c2': 1.5,
                    'botnet': 1.3,
                    'spam': 0.8
                }
                
                # Tip ağırlığını uygula
                score = base_score * type_weights.get(threat_type, 1.0)
                
                # Tag ağırlıklarını uygula
                tag_multiplier = 1.0
                for tag in tags:
                    tag_multiplier *= tag_weights.get(tag.strip(), 1.0)
                
                score *= tag_multiplier
                
                # Normalize et (0-100 arası)
                return min(100, max(0, score))
                
        except Exception as e:
            self.logger.error(f"Error calculating threat score: {str(e)}")
            return 0
    
    def find_related_threats(self, indicator):
        """Belirli bir gösterge ile ilişkili tehditleri bulur"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # İlişkili tehditleri bul
                cursor.execute('''
                    SELECT t2.*
                    FROM threats t1
                    JOIN threat_relations tr ON t1.id = tr.source_id
                    JOIN threats t2 ON tr.target_id = t2.id
                    WHERE t1.indicator = ?
                    UNION
                    SELECT t2.*
                    FROM threats t1
                    JOIN threat_relations tr ON t1.id = tr.target_id
                    JOIN threats t2 ON tr.source_id = t2.id
                    WHERE t1.indicator = ?
                ''', (indicator, indicator))
                
                return cursor.fetchall()
                
        except Exception as e:
            self.logger.error(f"Error finding related threats: {str(e)}")
            return []
    
    def generate_threat_graph(self, indicator):
        """Tehdit ilişkilerini görselleştirmek için graph oluşturur"""
        try:
            G = nx.Graph()
            
            # Ana göstergeyi ekle
            G.add_node(indicator, type='primary')
            
            # İlişkili tehditleri bul ve ekle
            related = self.find_related_threats(indicator)
            for threat in related:
                G.add_node(threat[1], type=threat[2])  # indicator ve type
                G.add_edge(indicator, threat[1])
            
            return G
            
        except Exception as e:
            self.logger.error(f"Error generating threat graph: {str(e)}")
            return None
    
    def analyze_threat_trends(self, days=7):
        """Tehdit trendlerini analiz eder"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                since = datetime.utcnow() - timedelta(days=days)
                
                # Günlük tehdit sayıları
                cursor.execute('''
                    SELECT 
                        date(first_seen) as date,
                        type,
                        COUNT(*) as count
                    FROM threats
                    WHERE first_seen >= ?
                    GROUP BY date, type
                    ORDER BY date
                ''', (since,))
                
                results = cursor.fetchall()
                
                # Sonuçları düzenle
                trends = defaultdict(lambda: defaultdict(int))
                for date, type, count in results:
                    trends[date][type] = count
                
                return dict(trends)
                
        except Exception as e:
            self.logger.error(f"Error analyzing threat trends: {str(e)}")
            return {}
    
    def calculate_threat_similarity(self, indicator1, indicator2):
        """İki tehdit göstergesi arasındaki benzerliği hesaplar"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Her iki göstergenin özelliklerini al
                cursor.execute('''
                    SELECT type, tags, confidence_score
                    FROM threats
                    WHERE indicator IN (?, ?)
                ''', (indicator1, indicator2))
                
                results = cursor.fetchall()
                if len(results) != 2:
                    return 0
                
                # Özellikleri karşılaştır
                type_similarity = 1 if results[0][0] == results[1][0] else 0
                
                tags1 = set(results[0][1].split(',')) if results[0][1] else set()
                tags2 = set(results[1][1].split(',')) if results[1][1] else set()
                tag_similarity = len(tags1.intersection(tags2)) / max(len(tags1.union(tags2)), 1)
                
                score_similarity = 1 - abs(results[0][2] - results[1][2]) / 100
                
                # Ağırlıklı ortalama
                weights = {'type': 0.3, 'tags': 0.4, 'score': 0.3}
                similarity = (
                    weights['type'] * type_similarity +
                    weights['tags'] * tag_similarity +
                    weights['score'] * score_similarity
                )
                
                return similarity
                
        except Exception as e:
            self.logger.error(f"Error calculating threat similarity: {str(e)}")
            return 0
