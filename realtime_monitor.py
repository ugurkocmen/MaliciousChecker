import asyncio
import json
import websockets
import aiohttp
import logging
import random
from datetime import datetime
from typing import Set, Dict
from dataclasses import dataclass, asdict
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ThreatEvent:
    id: str
    type: str
    indicator: str
    confidence_score: int
    severity: str
    timestamp: str
    location: Dict[str, float]
    source: str
    details: Dict

class ThreatMonitor:
    def __init__(self):
        self.clients: Set[websockets.WebSocketServerProtocol] = set()
        self.geolocator = Nominatim(user_agent="malicious_checker")
        self.executor = ThreadPoolExecutor(max_workers=3)
        self.ip_cache = {}
        
    async def register(self, websocket: websockets.WebSocketServerProtocol):
        """Yeni bir WebSocket istemcisini kaydet"""
        self.clients.add(websocket)
        logger.info(f"Yeni istemci bağlandı. Toplam istemci: {len(self.clients)}")
        
    async def unregister(self, websocket: websockets.WebSocketServerProtocol):
        """WebSocket istemcisinin kaydını sil"""
        self.clients.remove(websocket)
        logger.info(f"İstemci ayrıldı. Toplam istemci: {len(self.clients)}")
        
    async def get_location_for_ip(self, ip: str) -> Dict[str, float]:
        """IP adresi için coğrafi konum bilgisini getir"""
        if ip in self.ip_cache:
            return self.ip_cache[ip]
            
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'http://ip-api.com/json/{ip}') as response:
                    if response.status == 200:
                        data = await response.json()
                        if data['status'] == 'success':
                            location = {
                                'lat': data['lat'],
                                'lng': data['lon']
                            }
                            self.ip_cache[ip] = location
                            return location
        except Exception as e:
            logger.error(f"IP konum sorgusu hatası: {str(e)}")
            
        return {'lat': 0, 'lng': 0}
        
    async def broadcast_threat(self, threat: ThreatEvent):
        """Tehdidi tüm bağlı istemcilere yayınla"""
        if not self.clients:
            return
            
        message = json.dumps(asdict(threat))
        await asyncio.gather(
            *[client.send(message) for client in self.clients]
        )
        
    async def simulate_threats(self):
        """Test amaçlı tehdit simülasyonu"""
        threat_types = ['ip', 'domain', 'url', 'malware', 'ransomware']
        severity_levels = ['high', 'medium', 'low']
        
        while True:
            try:
                # Rastgele tehdit oluştur
                threat_type = random.choice(threat_types)
                severity = random.choice(severity_levels)
                
                if threat_type == 'ip':
                    indicator = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                elif threat_type == 'domain':
                    domains = ['evil.com', 'malware.org', 'badactor.net', 'phishing.site']
                    indicator = f"malicious-{random.randint(1,999)}.{random.choice(domains)}"
                else:
                    indicator = f"https://malicious-{random.randint(1,999)}.example.com/bad/path"
                
                # Tehdit olayı oluştur
                threat = ThreatEvent(
                    id=f"threat-{random.randint(1000,9999)}",
                    type=threat_type,
                    indicator=indicator,
                    confidence_score=random.randint(50,100),
                    severity=severity,
                    timestamp=datetime.now().isoformat(),
                    location={
                        'lat': random.uniform(-90, 90),
                        'lng': random.uniform(-180, 180)
                    },
                    source="Simülasyon",
                    details={
                        'tags': ['test', 'simulation'],
                        'description': 'Bu bir test tehdit olayıdır'
                    }
                )
                
                # Tehdidi yayınla
                await self.broadcast_threat(threat)
                
                # Rastgele bekleme süresi (2-5 saniye)
                await asyncio.sleep(random.uniform(2, 5))
                
            except Exception as e:
                logger.error(f"Tehdit simülasyonu hatası: {str(e)}")
                await asyncio.sleep(5)
                
    async def start_server(self, host: str = 'localhost', port: int = 8765):
        """WebSocket sunucusunu başlat"""
        async def handler(websocket: websockets.WebSocketServerProtocol, path: str):
            await self.register(websocket)
            try:
                await websocket.wait_closed()
            finally:
                await self.unregister(websocket)
                
        server = await websockets.serve(handler, host, port)
        logger.info(f"WebSocket sunucusu başlatıldı - {host}:{port}")
        
        # Tehdit simülasyonunu başlat
        asyncio.create_task(self.simulate_threats())
        
        await server.wait_closed()
        
    def run(self, host: str = 'localhost', port: int = 8765):
        """Monitörü başlat"""
        asyncio.run(self.start_server(host, port))

if __name__ == '__main__':
    monitor = ThreatMonitor()
    monitor.run() 