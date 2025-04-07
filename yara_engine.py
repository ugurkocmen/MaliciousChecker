import yara
import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class YaraEngine:
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = rules_dir
        self.rules = {}
        self.compiled_rules = None
        self._ensure_rules_dir()
        self._load_rules()
        
    def _ensure_rules_dir(self):
        """Kurallar dizinini oluştur"""
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            logger.info(f"Kurallar dizini oluşturuldu: {self.rules_dir}")
            
    def _load_rules(self):
        """Tüm YARA kurallarını yükle"""
        try:
            rules_files = [f for f in os.listdir(self.rules_dir) if f.endswith('.yar')]
            if not rules_files:
                logger.warning("Hiç YARA kuralı bulunamadı")
                return
                
            rules_dict = {}
            for rule_file in rules_files:
                rule_path = os.path.join(self.rules_dir, rule_file)
                rules_dict[rule_file] = rule_path
                
            self.compiled_rules = yara.compile(filepaths=rules_dict)
            logger.info(f"{len(rules_files)} YARA kuralı yüklendi")
            
        except Exception as e:
            logger.error(f"YARA kuralları yüklenirken hata: {str(e)}")
            
    def create_rule(self, rule_name: str, rule_content: str) -> bool:
        """Yeni bir YARA kuralı oluştur"""
        try:
            # Kural içeriğini doğrula
            yara.compile(source=rule_content)
            
            # Kuralı kaydet
            rule_path = os.path.join(self.rules_dir, f"{rule_name}.yar")
            with open(rule_path, 'w') as f:
                f.write(rule_content)
                
            # Kuralları yeniden yükle
            self._load_rules()
            logger.info(f"Yeni YARA kuralı oluşturuldu: {rule_name}")
            return True
            
        except Exception as e:
            logger.error(f"YARA kuralı oluşturulurken hata: {str(e)}")
            return False
            
    def scan_file(self, file_path: str) -> List[Dict]:
        """Dosyayı YARA kuralları ile tara"""
        if not self.compiled_rules:
            logger.warning("Taranacak YARA kuralı bulunamadı")
            return []
            
        try:
            matches = self.compiled_rules.match(file_path)
            results = []
            
            for match in matches:
                results.append({
                    'rule': match.rule,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': [str(s) for s in match.strings]
                })
                
            return results
            
        except Exception as e:
            logger.error(f"Dosya taranırken hata: {str(e)}")
            return []
            
    def scan_memory(self, data: bytes) -> List[Dict]:
        """Bellek verisini YARA kuralları ile tara"""
        if not self.compiled_rules:
            logger.warning("Taranacak YARA kuralı bulunamadı")
            return []
            
        try:
            matches = self.compiled_rules.match(data=data)
            results = []
            
            for match in matches:
                results.append({
                    'rule': match.rule,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': [str(s) for s in match.strings]
                })
                
            return results
            
        except Exception as e:
            logger.error(f"Bellek taranırken hata: {str(e)}")
            return []
            
    def list_rules(self) -> List[Dict]:
        """Tüm YARA kurallarını listele"""
        rules = []
        try:
            for rule_file in os.listdir(self.rules_dir):
                if rule_file.endswith('.yar'):
                    rule_path = os.path.join(self.rules_dir, rule_file)
                    with open(rule_path, 'r') as f:
                        content = f.read()
                        rules.append({
                            'name': rule_file,
                            'content': content,
                            'last_modified': datetime.fromtimestamp(
                                os.path.getmtime(rule_path)
                            ).isoformat()
                        })
        except Exception as e:
            logger.error(f"Kurallar listelenirken hata: {str(e)}")
            
        return rules
        
    def delete_rule(self, rule_name: str) -> bool:
        """YARA kuralını sil"""
        try:
            rule_path = os.path.join(self.rules_dir, f"{rule_name}.yar")
            if os.path.exists(rule_path):
                os.remove(rule_path)
                self._load_rules()
                logger.info(f"YARA kuralı silindi: {rule_name}")
                return True
            return False
        except Exception as e:
            logger.error(f"YARA kuralı silinirken hata: {str(e)}")
            return False
            
    def test_rule(self, rule_content: str, test_data: str) -> Dict:
        """YARA kuralını test et"""
        try:
            # Kuralı derle
            rule = yara.compile(source=rule_content)
            
            # Test verisi ile eşleşmeleri kontrol et
            matches = rule.match(data=test_data.encode())
            
            return {
                'valid': True,
                'matches': [{
                    'rule': match.rule,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': [str(s) for s in match.strings]
                } for match in matches]
            }
            
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            } 