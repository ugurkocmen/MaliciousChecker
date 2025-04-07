import os
import json
import logging
import tldextract
import dns.resolver
import whois
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import socket
import hashlib
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LocalAnalyzer:
    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self._ensure_data_dir()
        self.hash_database = self._load_hash_database()
        
    def _ensure_data_dir(self):
        """Veri dizinini oluştur"""
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
            logger.info(f"Veri dizini oluşturuldu: {self.data_dir}")
            
    def _load_hash_database(self) -> Dict[str, Dict]:
        """Hash veritabanını yükle"""
        db_path = os.path.join(self.data_dir, "hash_database.json")
        if os.path.exists(db_path):
            try:
                with open(db_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Hash veritabanı yüklenirken hata: {str(e)}")
        return {}
        
    def _save_hash_database(self):
        """Hash veritabanını kaydet"""
        db_path = os.path.join(self.data_dir, "hash_database.json")
        try:
            with open(db_path, 'w') as f:
                json.dump(self.hash_database, f, indent=4)
        except Exception as e:
            logger.error(f"Hash veritabanı kaydedilirken hata: {str(e)}")
            
    def analyze_url(self, url: str) -> Dict:
        """URL'yi analiz et"""
        try:
            parsed_url = urlparse(url)
            extracted = tldextract.extract(url)
            
            # Domain analizi
            domain_info = self._analyze_domain(extracted.domain + '.' + extracted.suffix)
            
            # URL yapı analizi
            url_structure = self._analyze_url_structure(parsed_url)
            
            # DNS kayıtları analizi
            dns_records = self._analyze_dns_records(extracted.domain + '.' + extracted.suffix)
            
            # Risk skoru hesapla
            risk_score = self._calculate_risk_score(domain_info, url_structure, dns_records)
            
            return {
                'url': url,
                'domain_info': domain_info,
                'url_structure': url_structure,
                'dns_records': dns_records,
                'risk_score': risk_score,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"URL analizi sırasında hata: {str(e)}")
            return {
                'url': url,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            
    def _analyze_domain(self, domain: str) -> Dict:
        """Domain bilgilerini analiz et"""
        try:
            domain_info = whois.whois(domain)
            
            # Domain yaşı hesapla
            domain_age = None
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                domain_age = (datetime.now() - creation_date).days
                
            return {
                'registrar': domain_info.registrar,
                'creation_date': str(domain_info.creation_date),
                'expiration_date': str(domain_info.expiration_date),
                'domain_age_days': domain_age,
                'name_servers': domain_info.name_servers,
                'status': domain_info.status
            }
            
        except Exception as e:
            logger.error(f"Domain analizi sırasında hata: {str(e)}")
            return {}
            
    def _analyze_url_structure(self, parsed_url) -> Dict:
        """URL yapısını analiz et"""
        return {
            'scheme': parsed_url.scheme,
            'netloc': parsed_url.netloc,
            'path': parsed_url.path,
            'params': parsed_url.params,
            'query': parsed_url.query,
            'fragment': parsed_url.fragment,
            'path_length': len(parsed_url.path),
            'query_length': len(parsed_url.query),
            'has_parameters': bool(parsed_url.query),
            'has_fragment': bool(parsed_url.fragment)
        }
        
    def _analyze_dns_records(self, domain: str) -> Dict:
        """DNS kayıtlarını analiz et"""
        records = {}
        try:
            # A kayıtları
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                records['a_records'] = [str(r) for r in a_records]
            except:
                records['a_records'] = []
                
            # MX kayıtları
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                records['mx_records'] = [str(r.exchange) for r in mx_records]
            except:
                records['mx_records'] = []
                
            # TXT kayıtları
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                records['txt_records'] = [r.strings[0].decode() for r in txt_records]
            except:
                records['txt_records'] = []
                
            # NS kayıtları
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                records['ns_records'] = [str(r) for r in ns_records]
            except:
                records['ns_records'] = []
                
        except Exception as e:
            logger.error(f"DNS kayıtları analizi sırasında hata: {str(e)}")
            
        return records
        
    def _calculate_risk_score(self, domain_info: Dict, url_structure: Dict, dns_records: Dict) -> int:
        """Risk skorunu hesapla"""
        score = 0
        
        # Domain yaşı kontrolü
        if domain_info.get('domain_age_days'):
            if domain_info['domain_age_days'] < 30:
                score += 20  # Yeni domain
            elif domain_info['domain_age_days'] < 180:
                score += 10  # 6 aydan küçük domain
                
        # URL yapısı kontrolü
        if url_structure['path_length'] > 50:
            score += 10  # Uzun path
        if url_structure['query_length'] > 100:
            score += 15  # Uzun query
        if url_structure['has_parameters']:
            score += 5  # Parametre içeriyor
            
        # DNS kayıtları kontrolü
        if not dns_records.get('a_records'):
            score += 20  # A kaydı yok
        if not dns_records.get('mx_records'):
            score += 10  # MX kaydı yok
        if not dns_records.get('ns_records'):
            score += 15  # NS kaydı yok
            
        return min(score, 100)  # Maksimum 100 puan
        
    def analyze_hash(self, hash_value: str) -> Dict:
        """Hash değerini analiz et"""
        try:
            # Hash formatını kontrol et
            hash_type = self._detect_hash_type(hash_value)
            if not hash_type:
                return {
                    'hash': hash_value,
                    'error': 'Geçersiz hash formatı',
                    'timestamp': datetime.now().isoformat()
                }
                
            # Hash veritabanında ara
            if hash_value in self.hash_database:
                return {
                    'hash': hash_value,
                    'type': hash_type,
                    'known': True,
                    'info': self.hash_database[hash_value],
                    'timestamp': datetime.now().isoformat()
                }
                
            return {
                'hash': hash_value,
                'type': hash_type,
                'known': False,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Hash analizi sırasında hata: {str(e)}")
            return {
                'hash': hash_value,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            
    def _detect_hash_type(self, hash_value: str) -> Optional[str]:
        """Hash tipini belirle"""
        hash_patterns = {
            'md5': r'^[a-fA-F0-9]{32}$',
            'sha1': r'^[a-fA-F0-9]{40}$',
            'sha256': r'^[a-fA-F0-9]{64}$',
            'sha512': r'^[a-fA-F0-9]{128}$'
        }
        
        for hash_type, pattern in hash_patterns.items():
            if re.match(pattern, hash_value):
                return hash_type
        return None
        
    def add_hash_to_database(self, hash_value: str, info: Dict) -> bool:
        """Hash veritabanına yeni hash ekle"""
        try:
            hash_type = self._detect_hash_type(hash_value)
            if not hash_type:
                return False
                
            self.hash_database[hash_value] = {
                'type': hash_type,
                'info': info,
                'added_at': datetime.now().isoformat()
            }
            
            self._save_hash_database()
            return True
            
        except Exception as e:
            logger.error(f"Hash veritabanına ekleme sırasında hata: {str(e)}")
            return False 