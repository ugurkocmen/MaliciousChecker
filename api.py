from flask import Blueprint, jsonify, request
from flask_restx import Api, Resource, fields
from local_analyzer import LocalAnalyzer
from yara_engine import YaraEngine

# API Blueprint oluşturma
api_bp = Blueprint('api', __name__, url_prefix='/api')
api = Api(api_bp, version='1.0', title='Malicious Checker API',
          description='Güvenlik analiz ve tehdit tespit API\'si')

# API namespace'leri
ns_local = api.namespace('local', description='Yerel analiz işlemleri')
ns_yara = api.namespace('yara', description='YARA kural işlemleri')

# Model tanımlamaları
analysis_input = api.model('AnalysisInput', {
    'type': fields.String(required=True, description='Analiz tipi (url, ip, hash, mail)'),
    'value': fields.String(required=True, description='Analiz edilecek değer')
})

analysis_result = api.model('AnalysisResult', {
    'type': fields.String(description='Analiz tipi'),
    'value': fields.String(description='Analiz edilen değer'),
    'timestamp': fields.DateTime(description='Analiz tarihi'),
    'risk_score': fields.Integer(description='Risk skoru'),
    'checks': fields.List(fields.Raw, description='Kontrol sonuçları'),
    'recommendations': fields.List(fields.String, description='Öneriler'),
    'additional_info': fields.Raw(description='Ek bilgiler')
})

yara_rule = api.model('YaraRule', {
    'name': fields.String(required=True, description='Kural adı'),
    'content': fields.String(required=True, description='Kural içeriği')
})

yara_test = api.model('YaraTest', {
    'rule_name': fields.String(required=True, description='Test edilecek kural adı'),
    'test_data': fields.String(required=True, description='Test verisi')
})

# API endpoint'leri
@ns_local.route('/analyze')
class LocalAnalysis(Resource):
    @api.expect(analysis_input)
    @api.marshal_with(analysis_result)
    def post(self):
        """Yerel analiz gerçekleştirir"""
        data = request.json
        analyzer = LocalAnalyzer()
        
        try:
            result = analyzer.analyze(data['type'], data['value'])
            return result
        except Exception as e:
            api.abort(400, str(e))

@ns_yara.route('/rules')
class YaraRules(Resource):
    @api.marshal_list_with(yara_rule)
    def get(self):
        """Tüm YARA kurallarını listeler"""
        engine = YaraEngine()
        return engine.list_rules()

    @api.expect(yara_rule)
    @api.marshal_with(yara_rule)
    def post(self):
        """Yeni bir YARA kuralı oluşturur"""
        data = request.json
        engine = YaraEngine()
        
        try:
            engine.create_rule(data['name'], data['content'])
            return {'name': data['name'], 'content': data['content']}
        except Exception as e:
            api.abort(400, str(e))

@ns_yara.route('/rules/<string:rule_name>')
class YaraRule(Resource):
    @api.marshal_with(yara_rule)
    def get(self, rule_name):
        """Belirli bir YARA kuralını getirir"""
        engine = YaraEngine()
        rule = engine.get_rule(rule_name)
        
        if rule:
            return rule
        api.abort(404, f"Kural bulunamadı: {rule_name}")

    def delete(self, rule_name):
        """Belirli bir YARA kuralını siler"""
        engine = YaraEngine()
        
        try:
            engine.delete_rule(rule_name)
            return {'message': f'Kural silindi: {rule_name}'}
        except Exception as e:
            api.abort(400, str(e))

@ns_yara.route('/test')
class YaraTest(Resource):
    @api.expect(yara_test)
    def post(self):
        """Bir YARA kuralını test eder"""
        data = request.json
        engine = YaraEngine()
        
        try:
            result = engine.test_rule(data['rule_name'], data['test_data'])
            return {'matches': result}
        except Exception as e:
            api.abort(400, str(e)) 