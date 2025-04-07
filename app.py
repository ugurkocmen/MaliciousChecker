from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from urllib.parse import quote
import re
import uuid
import requests
import json
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
import time
import difflib
from nltk.stem.snowball import SnowballStemmer
import Levenshtein
import tldextract
import dns.resolver
import dns.exception
from threat_intel.collector import ThreatIntelCollector
from threat_intel.analyzer import ThreatAnalyzer
import threading
import schedule
import logging
from logging.handlers import RotatingFileHandler
import os
from api import api_bp
from yara_engine import YaraEngine
from local_analyzer import LocalAnalyzer
from flask_socketio import SocketIO
import tempfile
import yara
from flask_wtf import FlaskForm

# Logging yapılandırması
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['WTF_CSRF_ENABLED'] = True
app.config['YARA_RULES_DIR'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules')
csrf = CSRFProtect(app)

# API blueprint'i kaydet
app.register_blueprint(api_bp, url_prefix='/api')

# Logging yapılandırması
if not app.debug:
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    file_handler = RotatingFileHandler(
        os.path.join(log_dir, 'app.log'),
        maxBytes=1024 * 1024,  # 1 MB
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup')

# Rate Limiter yapılandırması
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Cache yapılandırması
cache = Cache(app, config={
    'CACHE_TYPE': 'SimpleCache',
    'CACHE_DEFAULT_TIMEOUT': 300  # 5 minutes
})

# API Anahtarları
URLSCAN_API_KEY = '01960dde-fa26-738d-a733-fdc56a8509ad'
ABUSEIPDB_API_KEY = '81685fdd2405aceaa812234d15ed0128622ad7efc3481b730b4d2c6d34ef600ed011b70bd608e845'
MALWAREBAZAAR_API_KEY = '2127f03c7c078cf70849e957ec78bc6a0dc3e012bbdddd37'

# Tehdit istihbaratı nesnelerini oluştur
threat_collector = ThreatIntelCollector()
threat_analyzer = ThreatAnalyzer()

# Yerel analiz motorunu başlat
local_analyzer = LocalAnalyzer()

# API istek sayaçları ve limitleri
api_counters = {
    'urlscan': {'count': 0, 'limit': 100, 'reset_time': datetime.now()},
    'abuseipdb': {'count': 0, 'limit': 1000, 'reset_time': datetime.now()},
    'malwarebazaar': {'count': 0, 'limit': 500, 'reset_time': datetime.now()}
}

# YARA dizinini oluştur
os.makedirs(app.config['YARA_RULES_DIR'], exist_ok=True)

def init_yara_engine():
    """YARA motorunu başlat"""
    # Uygulama yapılandırmasında tanımlı olan YARA_RULES_DIR kullan
    rules_dir = app.config['YARA_RULES_DIR']
    
    # Dizinin varlığını kontrol et ve oluştur
    if not os.path.exists(rules_dir):
        os.makedirs(rules_dir)
        app.logger.info(f"YARA kuralları dizini oluşturuldu: {rules_dir}")
    
    app.logger.info(f"YARA motoru başlatılıyor, dizin: {rules_dir}")
    return YaraEngine(rules_dir)

# YARA kural motorunu başlat
yara_engine = init_yara_engine()

# Flask eklentileri
socketio = SocketIO(app)

def reset_api_counters():
    """API sayaçlarını sıfırla"""
    global api_counters
    for api in api_counters:
        api_counters[api]['count'] = 0
        api_counters[api]['reset_time'] = datetime.now()

def check_api_limit(api_name):
    """API limitini kontrol et"""
    global api_counters
    
    if api_name not in api_counters:
        return True
    
    counter = api_counters[api_name]
    
    # 24 saat geçtiyse sayacı sıfırla
    if (datetime.now() - counter['reset_time']).total_seconds() > 86400:
        counter['count'] = 0
        counter['reset_time'] = datetime.now()
    
    if counter['count'] >= counter['limit']:
        return False
    
    counter['count'] += 1
    return True

def sanitize_input(input_str):
    """Gelişmiş input sanitizasyonu"""
    if not input_str:
        return ""
    
    # HTML karakterlerini temizle
    input_str = re.sub(r'[<>]', '', input_str)
    
    # SQL injection karakterlerini temizle
    input_str = re.sub(r'[\'";\-]', '', input_str)
    
    # Kontrol karakterlerini temizle
    input_str = ''.join(char for char in input_str if ord(char) >= 32)
    
    # Maximum uzunluk kontrolü
    return input_str[:500]  # Maximum 500 karakter

def check_url(url):
    try:
        # Gelişmiş phishing kontrolü
        def analyze_phishing_indicators(url):
            try:
                from urllib.parse import urlparse
                import socket
                import whois
                from datetime import datetime
                import tldextract
                
                indicators = {
                    'score': 0,
                    'reasons': [],
                    'details': {
                        'domain_analysis': {},
                        'similar_domains': [],
                        'ssl_analysis': {},
                        'whois_analysis': {},
                        'ip_analysis': {},
                        'url_structure': {}
                    }
                }
                
                # URL parse
                parsed_url = urlparse(url)
                domain = parsed_url.netloc.lower()
                extracted = tldextract.extract(domain)
                
                # IP Analizi
                try:
                    ip = socket.gethostbyname(domain)
                    is_private = False
                    
                    # Özel IP aralıklarını kontrol et
                    private_ranges = [
                        ('10.0.0.0', '10.255.255.255'),
                        ('172.16.0.0', '172.31.255.255'),
                        ('192.168.0.0', '192.168.255.255')
                    ]
                    
                    ip_parts = list(map(int, ip.split('.')))
                    for start, end in private_ranges:
                        start_parts = list(map(int, start.split('.')))
                        end_parts = list(map(int, end.split('.')))
                        if all(s <= i <= e for s, i, e in zip(start_parts, ip_parts, end_parts)):
                            is_private = True
                            break
                    
                    indicators['details']['ip_analysis'] = {
                        'ip': ip,
                        'is_private': is_private,
                        'is_loopback': ip == '127.0.0.1'
                    }
                    
                    if is_private:
                        indicators['score'] += 5
                        indicators['reasons'].append("Özel IP adresi kullanılıyor")
                except:
                    indicators['details']['ip_analysis'] = {
                        'ip': 'Bilinmiyor',
                        'is_private': False,
                        'is_loopback': False
                    }
                
                # Benzer domain kontrolü
                similar_domains = []
                base_domain = f"{extracted.domain}.{extracted.suffix}"
                
                # Popüler domainler listesi
                popular_domains = [
                    'google.com', 'facebook.com', 'twitter.com', 'instagram.com',
                    'youtube.com', 'amazon.com', 'microsoft.com', 'apple.com',
                    'netflix.com', 'spotify.com', 'linkedin.com', 'ebay.com',
                    'paypal.com', 'bankofamerica.com', 'wellsfargo.com',
                    'chase.com', 'citi.com', 'hsbc.com', 'garanti.com.tr',
                    'isbank.com.tr', 'akbank.com', 'yapikredi.com.tr',
                    'ziraatbank.com.tr', 'finansbank.com', 'denizbank.com'
                ]
                
                # Sadece girilen domain'in benzerlik kontrolü
                for popular in popular_domains:
                    distance = Levenshtein.distance(base_domain.lower(), popular.lower())
                    max_len = max(len(base_domain), len(popular))
                    similarity = ((max_len - distance) / max_len) * 100
                    
                    if similarity >= 70:  # %70 ve üzeri benzerlik
                        similar_domains.append(popular)
                        indicators['score'] += 10  # Benzerlik durumunda daha yüksek skor
                
                if similar_domains:
                    indicators['score'] += len(similar_domains) * 5
                    indicators['reasons'].append(f"Benzer domain tespiti: {len(similar_domains)} adet")
                    indicators['details']['similar_domains'] = similar_domains
                
                # Domain Analizi
                if len(domain) > 30:
                    indicators['score'] += 2
                    indicators['reasons'].append("Domain adı çok uzun")
                
                # Alt domain sayısı
                subdomains = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
                if subdomains > 2:
                    indicators['score'] += 3
                    indicators['reasons'].append(f"Çok fazla alt domain: {subdomains}")
                
                # Özel karakterler
                special_chars = re.findall(r'[^a-z0-9.-]', domain)
                if special_chars:
                    indicators['score'] += 2
                    indicators['reasons'].append(f"Domain adında özel karakterler: {', '.join(set(special_chars))}")
                
                indicators['details']['domain_analysis'] = {
                    'length': len(domain),
                    'subdomains': subdomains,
                    'special_chars': list(set(special_chars))
                }
                
                # SSL Analizi
                if not parsed_url.scheme == 'https':
                    indicators['score'] += 3
                    indicators['reasons'].append("HTTPS kullanılmıyor")
                
                indicators['details']['ssl_analysis'] = {
                    'uses_https': parsed_url.scheme == 'https',
                    'scheme': parsed_url.scheme
                }
                
                # WHOIS Analizi
                try:
                    domain_info = whois.whois(domain)
                    
                    if domain_info.creation_date:
                        if isinstance(domain_info.creation_date, list):
                            creation_date = domain_info.creation_date[0]
                        else:
                            creation_date = domain_info.creation_date
                        
                        age_days = (datetime.now() - creation_date).days
                        if age_days < 30:
                            indicators['score'] += 4
                            indicators['reasons'].append(f"Domain çok yeni: {age_days} günlük")
                        
                        indicators['details']['whois_analysis'] = {
                            'age_days': age_days,
                            'registrar': domain_info.registrar,
                            'creation_date': str(creation_date),
                            'expiration_date': str(domain_info.expiration_date)
                        }
                except:
                    pass
                
                # URL Yapısı Analizi
                if len(url) > 100:
                    indicators['score'] += 2
                    indicators['reasons'].append("URL çok uzun")
                
                params = parsed_url.query.split('&') if parsed_url.query else []
                if len(params) > 5:
                    indicators['score'] += 2
                    indicators['reasons'].append(f"Çok fazla URL parametresi: {len(params)}")
                
                indicators['details']['url_structure'] = {
                    'length': len(url),
                    'param_count': len(params),
                    'has_fragment': bool(parsed_url.fragment)
                }
                
                # Normalize score (0-100 arası)
                indicators['score'] = min(100, indicators['score'])
                
                return indicators
                
            except Exception as e:
                print(f"Error in analyze_phishing_indicators: {str(e)}")
                return None
        
        # URLScan.io analizi
        def get_urlscan_results(url):
            try:
                headers = {
                    'API-Key': URLSCAN_API_KEY,
                    'Content-Type': 'application/json'
                }
                data = {
                    'url': url,
                    'visibility': 'public'
                }
                
                print("Sending scan request to URLScan.io...")  # Debug log
                scan_response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data)
                print(f"Scan response status: {scan_response.status_code}")  # Debug log
                
                if scan_response.status_code != 200:
                    print(f"Scan request failed: {scan_response.text}")  # Debug log
                    return None
                
                scan_data = scan_response.json()
                scan_id = scan_data['uuid']
                result_url = f'https://urlscan.io/api/v1/result/{scan_id}/'
                
                print(f"Waiting for scan results... (ID: {scan_id})")  # Debug log
                
                max_retries = 8  # Daha az deneme
                retry_delay = 3   # Daha kısa bekleme aralığı
                
                for attempt in range(max_retries):
                    try:
                        print(f"Attempt {attempt + 1} of {max_retries}")  # Debug log
                        result_response = requests.get(result_url, headers=headers)
                        
                        if result_response.status_code == 200:
                            result_data = result_response.json()
                            if 'verdicts' in result_data and 'overall' in result_data['verdicts']:
                                print("Scan results retrieved successfully")  # Debug log
                                return result_data
                            else:
                                print("Results not complete yet")  # Debug log
                        
                        if attempt < max_retries - 1:  # Son denemede beklemeye gerek yok
                            time.sleep(retry_delay)
                        
                    except Exception as e:
                        print(f"Error fetching results: {str(e)}")  # Debug log
                        if attempt < max_retries - 1:
                            time.sleep(retry_delay)
                
                print("Max retries reached, no complete results available")  # Debug log
                return None
                
            except Exception as e:
                print(f"URLScan.io error: {str(e)}")  # Debug log
                return None
        
        # Her iki analizi de çalıştır
        urlscan_results = get_urlscan_results(url)
        phishing_indicators = analyze_phishing_indicators(url)
        
        # Sonuçları birleştir
        return {
            'status': 'success',
            'data': {
                'url': url,
                'urlscan': {
                    'available': bool(urlscan_results),
                    'results': urlscan_results
                },
                'phishing_analysis': {
                    'score': phishing_indicators['score'],
                    'reasons': phishing_indicators['reasons'],
                    'details': phishing_indicators['details']
                }
            }
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'message': f'URL kontrolü sırasında hata oluştu: {str(e)}'
        }

def check_ip(ip):
    """AbuseIPDB'de IP kontrolü yapar"""
    logging.info(f"Checking IP: {ip}")
    
    try:
        logging.info("Sending request to AbuseIPDB...")
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json',
        }
        
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90',
            'verbose': 'true'
        }
        
        response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
        logging.info(f"Response status code: {response.status_code}")
        logging.info(f"Response content: {response.text}")
        
        if response.status_code == 200:
            api_counters['abuseipdb']['count'] += 1
            data = response.json()
            
            # Data hazırla
            result = {
                'status': 'success',
                'data': {
                    'ip': data['data']['ipAddress'],
                    'is_malicious': data['data']['abuseConfidenceScore'] > 50,
                    'confidence_score': data['data']['abuseConfidenceScore'],
                    'country': data['data']['countryName'],
                    'isp': data['data'].get('isp', 'Bilinmiyor'),
                    'domain': data['data'].get('domain', 'Bilinmiyor'),
                    'usage_type': data['data'].get('usageType', 'Bilinmiyor'),
                    'total_reports': data['data'].get('totalReports', 0),
                    'number_of_distinct_users': data['data'].get('numDistinctUsers', 0),
                    'last_reported_at': data['data'].get('lastReportedAt', 'Bilinmiyor'),
                    'risk_level': 'Yüksek' if data['data']['abuseConfidenceScore'] > 75 
                               else 'Orta' if data['data']['abuseConfidenceScore'] > 25 
                               else 'Düşük'
                }
            }
            
            return result
        else:
            return {
                'status': 'error',
                'message': f'AbuseIPDB API hatası: {response.status_code}'
            }
            
    except Exception as e:
        logging.error(f"AbuseIPDB kontrol hatası: {str(e)}")
        return {
            'status': 'error',
            'message': f'IP kontrolü sırasında bir hata oluştu: {str(e)}'
        }

def check_hash(hash_value):
    try:
        # MalwareBazaar API'si
        headers = {
            'API-KEY': MALWAREBAZAAR_API_KEY
        }
        data = {
            'query': 'get_info',
            'hash': hash_value
        }
        response = requests.post('https://mb-api.abuse.ch/api/v1/', headers=headers, data=data)
        
        if response.status_code == 200:
            hash_data = response.json()
            print(f"MalwareBazaar API Response: {hash_data}")  # Debug için
            
            if hash_data.get('query_status') == 'ok' and hash_data.get('data'):
                malware_data = hash_data['data'][0]
                return {
                    'status': 'success',
                    'data': {
                        'hash': hash_value,
                        'malicious': True,
                        # Temel Dosya Bilgileri
                        'file_name': malware_data.get('file_name', 'Bilinmiyor'),
                        'file_size': malware_data.get('file_size', 'Bilinmiyor'),
                        'file_type': malware_data.get('file_type', 'Bilinmiyor'),
                        'file_type_mime': malware_data.get('file_type_mime', 'Bilinmiyor'),
                        'md5_hash': malware_data.get('md5_hash', 'Bilinmiyor'),
                        'sha1_hash': malware_data.get('sha1_hash', 'Bilinmiyor'),
                        'sha256_hash': malware_data.get('sha256_hash', 'Bilinmiyor'),
                        'sha3_384_hash': malware_data.get('sha3_384_hash', 'Bilinmiyor'),
                        
                        # Zararlı Yazılım Bilgileri
                        'signature': malware_data.get('signature', 'Bilinmiyor'),
                        'imphash': malware_data.get('imphash', 'Bilinmiyor'),
                        'tlsh': malware_data.get('tlsh', 'Bilinmiyor'),
                        'telfhash': malware_data.get('telfhash', 'Bilinmiyor'),
                        'vendor_intel': malware_data.get('vendor_intel', {}),
                        
                        # Zaman Bilgileri
                        'first_seen': malware_data.get('first_seen', 'Bilinmiyor'),
                        'last_seen': malware_data.get('last_seen', 'Bilinmiyor'),
                        
                        # Etiketler ve Sınıflandırma
                        'tags': malware_data.get('tags', []),
                        'delivery_method': malware_data.get('delivery_method', 'Bilinmiyor'),
                        'intelligence': malware_data.get('intelligence', {}),
                        
                        # YARA Kuralları
                        'yara_rules': malware_data.get('yara_rules', []),
                        
                        # Ek Bilgiler
                        'file_information': malware_data.get('file_information', {}),
                        'ole_information': malware_data.get('ole_information', {}),
                        'pe_information': malware_data.get('pe_information', {}),
                        'comments': malware_data.get('comments', []),
                        'reporter': malware_data.get('reporter', 'Bilinmiyor')
                    }
                }
            else:
                # Hash bulunamadı veya başka bir hata durumu
                return {
                    'status': 'success',
                    'data': {
                        'hash': hash_value,
                        'malicious': False,
                        'message': 'Hash veritabanında bulunamadı'
                    }
                }
        return {
            'status': 'error',
            'message': 'Hash kontrolü başarısız oldu'
        }
    except Exception as e:
        print(f"Error in check_hash: {str(e)}")  # Debug için
        return {
            'status': 'error',
            'message': str(e)
        }

def get_malware_list():
    try:
        headers = {
            'API-KEY': MALWAREBAZAAR_API_KEY
        }
        data = {
            'query': 'get_recent',
            'selector': 'time',
            'limit': 10  # Son 10 zararlı yazılım
        }
        
        print("Sending request to MalwareBazaar API...")  # Debug log
        response = requests.post('https://mb-api.abuse.ch/api/v1/', headers=headers, data=data)
        print(f"Response status code: {response.status_code}")  # Debug log
        
        if response.status_code == 200:
            data = response.json()
            print(f"Response data: {json.dumps(data, indent=2)}")  # Debug log
            
            if data.get('query_status') == 'ok':
                malware_list = []
                for item in data.get('data', []):
                    malware_list.append({
                        'file_name': item.get('file_name', 'Bilinmiyor'),
                        'sha256_hash': item.get('sha256_hash', ''),
                        'file_size': f"{item.get('file_size', 0):,} bytes",
                        'file_type': item.get('file_type', 'Bilinmiyor'),
                        'first_seen': item.get('first_seen', ''),
                        'tags': item.get('tags', [])
                    })
                return malware_list
            else:
                print(f"Query status not OK: {data.get('query_status')}")  # Debug log
                return []
        else:
            print(f"Error response from API: {response.text}")  # Debug log
            return []
    except Exception as e:
        print(f"Error fetching malware list: {str(e)}")  # Debug log
        return []

@cache.memoize(timeout=300)
def get_usom_threats():
    """USOM tehditlerini getir ve önbellekle"""
    try:
        # USOM verilerini çek
        threats = threat_collector.get_usom_threats()
        return threats
    except Exception as e:
        app.logger.error(f"Error fetching USOM threats: {str(e)}")
        return []

def check_mail_security(domain):
    try:
        results = {
            'spf': check_spf(domain),
            'dmarc': check_dmarc(domain),
            'dkim': check_dkim(domain),
            'mx': check_mx(domain),
            'domain': domain,
            'score': 0,
            'recommendations': []
        }
        
        # Skor hesaplama
        if results['spf']['exists']:
            results['score'] += 30
        if results['dmarc']['exists']:
            results['score'] += 40
        if results['dkim']['exists']:
            results['score'] += 30
            
        # Öneriler
        if not results['spf']['exists']:
            results['recommendations'].append("SPF kaydı oluşturulmalı")
        elif 'all' not in results['spf']['record'].lower():
            results['recommendations'].append("SPF kaydında all parametresi eksik")
            
        if not results['dmarc']['exists']:
            results['recommendations'].append("DMARC kaydı oluşturulmalı")
        elif results['dmarc']['exists'] and 'p=none' in results['dmarc']['record'].lower():
            results['recommendations'].append("DMARC politikası none olarak ayarlanmış, daha sıkı bir politika önerilir")
            
        if not results['dkim']['exists']:
            results['recommendations'].append("DKIM kaydı oluşturulmalı")
            
        if not results['mx']['exists']:
            results['recommendations'].append("MX kaydı bulunamadı")
            
        return {
            'status': 'success',
            'data': results
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_record = None
        
        for rdata in answers:
            for txt_string in rdata.strings:
                txt_record = txt_string.decode('utf-8')
                if txt_record.startswith('v=spf1'):
                    spf_record = txt_record
                    break
        
        mechanisms = []
        if spf_record:
            parts = spf_record.split()
            for part in parts[1:]:  # v=spf1'i atla
                if part.startswith(('ip4:', 'ip6:', 'include:', 'a:', 'mx:', 'ptr:', 'exists:', 'redirect=')):
                    mechanisms.append(part)
        
        return {
            'exists': bool(spf_record),
            'record': spf_record if spf_record else None,
            'mechanisms': mechanisms
        }
    except dns.exception.DNSException:
        return {
            'exists': False,
            'record': None,
            'mechanisms': []
        }

def check_dmarc(domain):
    try:
        dmarc_domain = f'_dmarc.{domain}'
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_record = None
        
        for rdata in answers:
            for txt_string in rdata.strings:
                txt_record = txt_string.decode('utf-8')
                if txt_record.startswith('v=DMARC1'):
                    dmarc_record = txt_record
                    break
        
        policy = None
        sub_policy = None
        pct = None
        
        if dmarc_record:
            for tag in dmarc_record.split(';'):
                tag = tag.strip()
                if tag.startswith('p='):
                    policy = tag[2:]
                elif tag.startswith('sp='):
                    sub_policy = tag[3:]
                elif tag.startswith('pct='):
                    pct = tag[4:]
        
        return {
            'exists': bool(dmarc_record),
            'record': dmarc_record if dmarc_record else None,
            'policy': policy,
            'sub_policy': sub_policy,
            'pct': pct
        }
    except dns.exception.DNSException:
        return {
            'exists': False,
            'record': None,
            'policy': None,
            'sub_policy': None,
            'pct': None
        }

def check_dkim(domain):
    try:
        # Yaygın DKIM seçici isimleri
        selectors = ['default', 'google', 'k1', 'selector1', 'selector2', 'dkim', 'mail']
        dkim_records = []
        
        for selector in selectors:
            try:
                dkim_domain = f'{selector}._domainkey.{domain}'
                answers = dns.resolver.resolve(dkim_domain, 'TXT')
                
                for rdata in answers:
                    for txt_string in rdata.strings:
                        txt_record = txt_string.decode('utf-8')
                        if 'v=DKIM1' in txt_record:
                            dkim_records.append({
                                'selector': selector,
                                'record': txt_record
                            })
            except dns.exception.DNSException:
                continue
        
        return {
            'exists': bool(dkim_records),
            'records': dkim_records
        }
    except Exception:
        return {
            'exists': False,
            'records': []
        }

def check_mx(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = []
        
        for rdata in answers:
            mx_records.append({
                'preference': rdata.preference,
                'exchange': str(rdata.exchange)
            })
        
        return {
            'exists': bool(mx_records),
            'records': mx_records
        }
    except dns.exception.DNSException:
        return {
            'exists': False,
            'records': []
        }

def background_threat_collection():
    """Arka planda tehdit istihbaratı toplama"""
    while True:
        try:
            threat_collector.collect_all()
            time.sleep(3600)  # Her saat başı
        except Exception as e:
            app.logger.error(f"Background threat collection error: {str(e)}")
            time.sleep(300)  # Hata durumunda 5 dakika bekle

# Arka plan iş parçacığını başlat
threat_thread = threading.Thread(target=background_threat_collection, daemon=True)
threat_thread.start()

@app.route('/')
def index():
    try:
        # USOM tehditlerini al
        usom_threats = get_usom_threats()
        
        # MalwareBazaar verilerini al
        malware_list = get_malware_list()
        
        # Son tehditleri birleştir ve formatla
        recent_threats = []
        
        # USOM tehditlerini ekle
        for threat in usom_threats[:5]:  # Son 5 USOM tehdidi
            if not threat.get('indicator'):  # Boş indicator'ları atla
                continue
                
            # Tarih formatını düzenle
            timestamp = threat.get('first_seen')
            if isinstance(timestamp, datetime):
                formatted_date = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            else:
                try:
                    # USOM formatı: "2025-04-07 19.32.49"
                    formatted_date = datetime.strptime(
                        str(timestamp).replace('.', ':'), 
                        '%Y-%m-%d %H:%M:%S'
                    ).strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, TypeError):
                    formatted_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            recent_threats.append({
                'timestamp': formatted_date,
                'type': 'URL',
                'type_color': 'danger',
                'type_icon': 'link',
                'value': threat.get('indicator'),  # 'url' yerine 'indicator' kullan
                'status': 'Aktif',
                'status_color': 'danger',
                'status_icon': 'shield-alt',
                'details_url': url_for('threat_search', indicator=threat.get('indicator'))
            })
        
        # MalwareBazaar verilerini ekle
        for malware in malware_list[:5]:  # Son 5 zararlı yazılım
            if not malware.get('sha256_hash'):  # Boş hash değerlerini atla
                continue
                
            recent_threats.append({
                'timestamp': malware.get('first_seen', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                'type': 'Hash',
                'type_color': 'warning',
                'type_icon': 'file-code',
                'value': malware.get('sha256_hash', '')[:32] + '...',  # Hash'i kısalt
                'status': 'Zararlı',
                'status_color': 'danger',
                'status_icon': 'virus',
                'details_url': url_for('threat_search', indicator=malware.get('sha256_hash', ''))
            })
        
        # Tarihe göre sırala
        recent_threats.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return render_template('index.html', recent_threats=recent_threats[:10])  # Son 10 tehdit
    except Exception as e:
        app.logger.error(f"Error in index route: {str(e)}")
        return render_template('index.html', recent_threats=[])

@app.route('/search', methods=['GET', 'POST'])
def search():
    # URL'den gelen type parametresini al
    default_type = request.args.get('type', 'url')
    
    if request.method == 'POST':
        check_type = request.form.get('check_type')
        value = request.form.get('value')
        
        value = sanitize_input(value)
        
        if not value:
            flash('Lütfen bir değer girin', 'error')
            return render_template('search.html', default_type=default_type)
        
        try:
            if check_type == 'url':
                if not re.match(r'^https?://', value):
                    value = 'http://' + value
                result = check_url(value)
                # URL sonuçları için yapı kontrolü
                if result['status'] == 'success' and 'data' in result:
                    return render_template('search.html', result=result['data'], check_type=check_type, value=value, default_type=default_type)
            elif check_type == 'ip':
                if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
                    flash('Geçersiz IP adresi formatı', 'error')
                    return render_template('search.html', default_type=default_type)
                result = check_ip(value)
                # IP sonuçları için yapı kontrolü
                if result['status'] == 'success' and 'data' in result:
                    # IP sonuçlarını doğrudan işle
                    return render_template('search.html', result=result['data'], check_type=check_type, value=value, default_type=default_type)
            elif check_type == 'hash':
                if not re.match(r'^[a-fA-F0-9]{32,64}$', value):
                    flash('Geçersiz hash formatı', 'error')
                    return render_template('search.html', default_type=default_type)
                result = check_hash(value)
                if result['status'] == 'success' and 'data' in result:
                    # Hash sonuçlarını doğrudan işle
                    return render_template('search.html', result=result['data'], check_type=check_type, value=value, default_type=default_type)
            
            # Eğer success durumu yoksa veya data yoksa
            flash(result.get('message', 'Bir hata oluştu. Tekrar deneyin.'), 'error')
            return render_template('search.html', default_type=default_type)
                
        except Exception as e:
            app.logger.error(f"Search error: {str(e)}")
            flash('Bir hata oluştu: ' + str(e), 'error')
            return render_template('search.html', default_type=default_type)
    
    return render_template('search.html', default_type=default_type)

@app.route('/malware-list')
def malware_list():
    """Zararlı yazılım listesi sayfası"""
    try:
        malwares = get_malware_list()
        return render_template('malware_list.html', malware_list=malwares)
    except Exception as e:
        app.logger.error(f"Error in malware list route: {str(e)}")
        flash('Zararlı yazılım listesi alınırken bir hata oluştu.', 'error')
        return render_template('malware_list.html', malware_list=[])

@app.route('/usom-threats')
def usom_threats():
    """USOM zararlı bağlantılar sayfası"""
    try:
        threats = get_usom_threats()
        return render_template('usom_threats.html', threats=threats)
    except Exception as e:
        app.logger.error(f"Error in USOM threats route: {str(e)}")
        flash('USOM tehditleri alınırken bir hata oluştu.', 'error')
        return render_template('usom_threats.html', threats=[])

@app.route('/mail-security', methods=['GET', 'POST'])
def mail_security():
    if request.method == 'POST':
        domain = request.form.get('domain')
        
        if not domain:
            flash('Lütfen bir domain girin', 'error')
            return render_template('mail_security.html')
        
        try:
            result = check_mail_security(domain)
            if result['status'] == 'success':
                return render_template('mail_security.html', result=result['data'])
            else:
                flash(result['message'], 'error')
                return render_template('mail_security.html')
        except Exception as e:
            flash('Bir hata oluştu: ' + str(e), 'error')
            return render_template('mail_security.html')
    
    return render_template('mail_security.html')

@app.route('/threat-intel')
@limiter.limit("30/minute")  # Rate limiting ekle
@cache.cached(timeout=60)  # 60 saniyelik önbellek
def threat_intel_dashboard():
    try:
        # Son 24 saatteki tehdit paternlerini al
        patterns = threat_analyzer.analyze_threat_patterns()
        
        # Tehdit trendlerini al (son 7 gün)
        trends = threat_analyzer.analyze_threat_trends()
        
        # Son tehditleri al
        recent_threats = threat_collector.get_recent_threats()
        
        # Grafik verilerini hazırla
        type_labels = []
        type_data = []
        confidence_labels = []
        confidence_data = []
        
        if patterns and 'type_distribution' in patterns and 'confidence_distribution' in patterns:
            type_labels = [t[0] for t in patterns['type_distribution']]
            type_data = [t[1] for t in patterns['type_distribution']]
            
            confidence_labels = [c[0] for c in patterns['confidence_distribution']]
            confidence_data = [c[1] for c in patterns['confidence_distribution']]
        
        # Trend verilerini hazırla
        trend_dates = []
        trend_datasets = []
        
        if trends:
            trend_dates = list(trends.keys())
            # Her tehdit türü için bir dataset oluştur
            threat_types = set()
            for daily_data in trends.values():
                threat_types.update(daily_data.keys())
            
            colors = ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
            for i, threat_type in enumerate(threat_types):
                dataset = {
                    'label': threat_type,
                    'data': [trends[date].get(threat_type, 0) for date in trend_dates],
                    'borderColor': colors[i % len(colors)],
                    'fill': False
                }
                trend_datasets.append(dataset)
        
        # Tehditleri formatlı hale getir
        formatted_threats = []
        for threat in recent_threats:
            if len(threat) >= 8:  # Ensure we have all required fields
                type_class = {
                    'ip': 'danger',
                    'domain': 'warning',
                    'url': 'info',
                    'hash': 'dark'
                }.get(threat[2], 'secondary')
                
                score = threat[3] if threat[3] is not None else 0
                score_class = 'success' if score >= 80 else 'warning' if score >= 50 else 'danger'
                
                formatted_threats.append({
                    'indicator': threat[1],
                    'type': threat[2],
                    'type_class': type_class,
                    'confidence_score': score,
                    'score_class': score_class,
                    'source': threat[6] if threat[6] else 'Unknown',
                    'tags': threat[7] if threat[7] else '',
                    'last_seen': threat[5] if threat[5] else 'Unknown'
                })
        
        return render_template('threat_intel.html',
                             type_labels=type_labels,
                             type_data=type_data,
                             confidence_labels=confidence_labels,
                             confidence_data=confidence_data,
                             trend_dates=trend_dates,
                             trend_datasets=trend_datasets,
                             recent_threats=formatted_threats)
    except Exception as e:
        app.logger.error(f"Error in threat intel dashboard: {str(e)}")
        return render_template('threat_intel.html',
                             type_labels=[],
                             type_data=[],
                             confidence_labels=[],
                             confidence_data=[],
                             trend_dates=[],
                             trend_datasets=[],
                             recent_threats=[])

@app.route('/threat-search', methods=['GET', 'POST'])
@limiter.limit("20/minute")  # Rate limiting ekle
def threat_search():
    """Tehdit arama sayfası"""
    if request.method == 'POST':
        # Input sanitizasyonu
        indicator = sanitize_input(request.form.get('indicator'))
        type = sanitize_input(request.form.get('type'))
        tags = sanitize_input(request.form.get('tags'))
        
        # Cache key oluştur
        cache_key = f"threat_search_{indicator}_{type}_{tags}"
        
        # Önbellekten sonuçları kontrol et
        cached_result = cache.get(cache_key)
        if cached_result:
            return cached_result
        
        results = threat_collector.search_threats(
            indicator=indicator,
            type=type,
            tags=tags
        )
        
        if indicator:
            # Tehdit skoru hesapla
            threat_score = threat_analyzer.calculate_threat_score(indicator)
            
            # İlişkili tehditleri bul
            related_threats = threat_analyzer.find_related_threats(indicator)
            
            response = render_template(
                'threat_search.html',
                results=results,
                threat_score=threat_score,
                related_threats=related_threats
            )
            
            # Sonuçları önbelleğe al
            cache.set(cache_key, response, timeout=300)  # 5 dakika
            return response
        
        return render_template('threat_search.html', results=results)
    
    return render_template('threat_search.html')

# API sayaçlarını sıfırlamak için zamanlayıcı
def reset_api_counters_job():
    reset_api_counters()
    
schedule.every().day.at("00:00").do(reset_api_counters_job)

# Hata yönetimi
@app.errorhandler(404)
def not_found_error(error):
    app.logger.error(f'Page not found: {request.url}')
    return render_template('errors/404.html'), 404

@app.errorhandler(429)
def ratelimit_error(error):
    app.logger.warning(f'Rate limit exceeded for {request.remote_addr}')
    return render_template('errors/429.html'), 429

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Server Error: {error}', exc_info=True)
    return render_template('errors/500.html', error_message=str(error)), 500

@app.route('/yara')
def yara_rules():
    """YARA kural yöneticisi sayfası"""
    try:
        # Boş form oluştur (CSRF token için)
        form = FlaskForm()
        
        # YARA kurallarını listele
        rules_dir = app.config['YARA_RULES_DIR']
        rules = []
        
        if os.path.exists(rules_dir):
            for file in os.listdir(rules_dir):
                if file.endswith('.yar'):
                    rules.append(file)
        
        return render_template('yara_rules.html', rules=rules, form=form)
    except Exception as e:
        app.logger.error(f"Error listing YARA rules: {str(e)}")
        flash('YARA kuralları listelenirken bir hata oluştu.', 'error')
        return render_template('yara_rules.html', rules=[], form=form)

@app.route('/yara/test', methods=['POST'])
@csrf.exempt
def test_yara_rule():
    try:
        app.logger.info(f"Test YARA Rule - Request data: {request.form}")
        rule_content = request.form.get('rule')
        if not rule_content:
            app.logger.warning("YARA Rule test failed: Empty rule content")
            return jsonify({'error': 'Kural içeriği boş olamaz'}), 400

        # Geçici dosya oluştur
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as tmp_file:
            tmp_file.write(rule_content)
            tmp_file_path = tmp_file.name
            tmp_file.flush()
            app.logger.info(f"YARA Rule test - Temp file created: {tmp_file_path}")

        try:
            # Kuralı derle
            yara.compile(filepath=tmp_file_path)
            app.logger.info("YARA Rule compiled successfully")
            return jsonify({'message': 'YARA kuralı başarıyla derlendi'})
        except Exception as e:
            app.logger.error(f"YARA Rule compilation error: {str(e)}")
            return jsonify({'error': f'YARA kuralı derlenirken hata oluştu: {str(e)}'}), 400
        finally:
            if os.path.exists(tmp_file_path):
                os.unlink(tmp_file_path)
                app.logger.info(f"YARA Rule test - Temp file deleted: {tmp_file_path}")
    except Exception as e:
        app.logger.error(f"Unexpected error in test_yara_rule: {str(e)}")
        return jsonify({'error': f'Beklenmeyen bir hata oluştu: {str(e)}'}), 500

@app.route('/yara/create', methods=['POST'])
@csrf.exempt
def create_yara_rule():
    try:
        app.logger.info(f"Create YARA Rule - Request data: {request.form}")
        rule_name = request.form.get('name')
        rule_content = request.form.get('rule')

        if not rule_name or not rule_content:
            app.logger.warning("YARA Rule creation failed: Missing name or content")
            return jsonify({'error': 'Kural adı ve içeriği gereklidir'}), 400

        # Dosya adı için güvenli bir isim oluştur
        safe_rule_name = re.sub(r'[^\w\.-]', '_', rule_name)
        if not safe_rule_name.endswith('.yar'):
            safe_rule_name += '.yar'

        # Geçici dosya oluştur ve test et
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as tmp_file:
            tmp_file.write(rule_content)
            tmp_file_path = tmp_file.name
            tmp_file.flush()
            app.logger.info(f"YARA Rule creation - Temp file created: {tmp_file_path}")

        try:
            # Kuralı derle (test et)
            yara.compile(filepath=tmp_file_path)
            
            # Başarılı ise kaydet
            rule_path = os.path.join(app.config['YARA_RULES_DIR'], safe_rule_name)
            app.logger.info(f"YARA Rule will be saved to: {rule_path}")
            
            # YARA_RULES_DIR dizini yoksa oluştur
            os.makedirs(app.config['YARA_RULES_DIR'], exist_ok=True)
            
            with open(rule_path, 'w') as f:
                f.write(rule_content)
            
            app.logger.info(f"YARA Rule saved successfully: {rule_path}")
            return jsonify({'message': 'YARA kuralı başarıyla kaydedildi'})
        except Exception as e:
            app.logger.error(f"YARA Rule creation error: {str(e)}")
            return jsonify({'error': f'YARA kuralı derlenirken hata oluştu: {str(e)}'}), 400
        finally:
            if os.path.exists(tmp_file_path):
                os.unlink(tmp_file_path)
                app.logger.info(f"YARA Rule creation - Temp file deleted: {tmp_file_path}")
    except Exception as e:
        app.logger.error(f"Unexpected error in create_yara_rule: {str(e)}")
        return jsonify({'error': f'Beklenmeyen bir hata oluştu: {str(e)}'}), 500

@app.route('/yara/view/<rule_name>')
def view_yara_rule(rule_name):
    """YARA kuralını görüntüle"""
    try:
        app.logger.info(f"View YARA Rule - Rule name: {rule_name}")
        rule_path = os.path.join(app.config['YARA_RULES_DIR'], rule_name)
        app.logger.info(f"YARA Rule path: {rule_path}")
        
        if os.path.exists(rule_path):
            with open(rule_path, 'r') as f:
                content = f.read()
            app.logger.info(f"YARA Rule content retrieved successfully")
            return jsonify({'content': content})
        
        app.logger.warning(f"YARA Rule not found: {rule_path}")
        return jsonify({'error': 'Kural bulunamadı'}), 404
    except Exception as e:
        app.logger.error(f"Error viewing YARA rule: {str(e)}")
        return jsonify({'error': f'Kural görüntülenirken bir hata oluştu: {str(e)}'}), 500

@app.route('/yara/delete/<rule_name>', methods=['POST', 'DELETE'])
@csrf.exempt
def delete_yara_rule(rule_name):
    """YARA kuralını sil"""
    try:
        app.logger.info(f"Delete YARA Rule - Rule name: {rule_name}")
        rule_path = os.path.join(app.config['YARA_RULES_DIR'], rule_name)
        app.logger.info(f"YARA Rule path to delete: {rule_path}")
        
        if os.path.exists(rule_path):
            os.remove(rule_path)
            app.logger.info(f"YARA Rule deleted successfully: {rule_path}")
            return jsonify({'success': True, 'message': 'Kural başarıyla silindi'})
        
        app.logger.warning(f"YARA Rule not found for deletion: {rule_path}")
        return jsonify({'success': False, 'error': 'Kural bulunamadı'})
    except Exception as e:
        app.logger.error(f"Error deleting YARA rule: {str(e)}")
        return jsonify({'success': False, 'error': f'Kural silinirken bir hata oluştu: {str(e)}'})

@app.route('/local-analysis', methods=['GET', 'POST'])
def local_analysis():
    """Yerel tehdit analizi sayfası"""
    try:
        if request.method == 'POST':
            analysis_type = request.form.get('analysis_type')
            value = request.form.get('value')
            
            if not value:
                flash('Lütfen bir değer girin', 'error')
                return render_template('local_analysis.html')
                
            try:
                if analysis_type == 'url':
                    result = local_analyzer.analyze_url(value)
                elif analysis_type == 'hash':
                    result = local_analyzer.analyze_hash(value)
                else:
                    flash('Geçersiz analiz tipi', 'error')
                    return render_template('local_analysis.html')
                    
                return render_template('local_analysis.html', result=result, analysis_type=analysis_type)
                
            except Exception as e:
                flash(f'Analiz sırasında hata oluştu: {str(e)}', 'error')
                return render_template('local_analysis.html')
        
        # GET isteği
        return render_template('local_analysis.html')
    except Exception as e:
        app.logger.error(f"Error in local analysis: {str(e)}")
        flash(f'Bir hata oluştu: {str(e)}', 'error')
        return render_template('local_analysis.html')

@app.route('/local-analysis/add-hash', methods=['POST'])
def add_hash():
    """Hash veritabanına yeni hash ekle"""
    try:
        data = request.get_json()
        hash_value = data.get('hash')
        info = data.get('info', {})
        
        if not hash_value:
            return jsonify({'success': False, 'error': 'Hash değeri gerekli'})
            
        success = local_analyzer.add_hash_to_database(hash_value, info)
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Geçersiz hash formatı'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# WebSocket olayları
@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected')

@app.route('/recent-threats')
@cache.cached(timeout=300)  # 5 dakika önbellekleme
def recent_threats():
    """Son tehditleri görüntüle"""
    try:
        # Sadece son 15 tehdidi al
        threats = threat_collector.get_recent_threats(limit=15)
        
        # Tehditleri formatlı hale getir
        formatted_threats = []
        for threat in threats:
            if len(threat) >= 8:  # Ensure we have all required fields
                type_class = {
                    'ip': 'danger',
                    'domain': 'warning',
                    'url': 'info',
                    'hash': 'dark'
                }.get(threat[2], 'secondary')
                
                score = threat[3] if threat[3] is not None else 0
                score_class = 'success' if score >= 80 else 'warning' if score >= 50 else 'danger'
                
                # Tehdit değerini kontrol et
                value = threat[1]
                if not value or value.strip() == '':
                    continue  # Boş değerleri atla
                
                # Tarih kontrolü
                timestamp = threat[4]
                if not timestamp or timestamp == 'None':
                    continue  # Geçersiz tarihleri atla

                formatted_threats.append({
                    'timestamp': timestamp,  # Artık datetime string olarak geliyor
                    'type': threat[2],
                    'type_color': type_class,
                    'type_icon': {
                        'ip': 'network-wired',
                        'domain': 'globe',
                        'url': 'link',
                        'hash': 'file-code'
                    }.get(threat[2], 'exclamation-triangle'),
                    'value': value,
                    'status': 'Aktif' if score >= 75 else 'Şüpheli' if score >= 25 else 'Temiz',
                    'status_color': score_class,
                    'status_icon': 'shield-alt',
                    'details_url': url_for('threat_search', indicator=value)
                })
        
        # Tarihe göre sırala (artık gereksiz çünkü veritabanından sıralı geliyor)
        return render_template('recent_threats.html', threats=formatted_threats)
    except Exception as e:
        app.logger.error(f"Error in recent threats: {str(e)}")
        return render_template('recent_threats.html', threats=[])

if __name__ == '__main__':
    logger.info('Application startup')
    socketio.run(app, debug=True) 