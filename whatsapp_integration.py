# ============================================================
# INTEGRAÇÃO WHATSAPP - EVOLUTION API
# Liga Olímpica de Golfe
# 
# Arquivo: whatsapp_integration.py
# Colocar na mesma pasta do app.py
# ============================================================

import requests
from datetime import datetime

# ============================================================
# CONFIGURAÇÕES
# ============================================================

EVOLUTION_API_URL = "http://159.89.35.66:8080"
EVOLUTION_API_KEY = "liga-golf-api-key-2024"
EVOLUTION_INSTANCE = "liga-golf"
WHATSAPP_GRUPO_LIGA = "120363403838797386@g.us"
WHATSAPP_ENABLED = True


# ============================================================
# CLASSE PRINCIPAL - EVOLUTION API
# ============================================================

class EvolutionAPI:
    """Classe para integração com Evolution API"""
    
    def __init__(self):
        self.base_url = EVOLUTION_API_URL
        self.api_key = EVOLUTION_API_KEY
        self.instance = EVOLUTION_INSTANCE
        self.headers = {
            'Content-Type': 'application/json',
            'apikey': self.api_key
        }
    
    def _fazer_request(self, endpoint, payload):
        """Faz requisição para a Evolution API"""
        url = f"{self.base_url}/message/{endpoint}/{self.instance}"
        
        try:
            response = requests.post(url, json=payload, headers=self.headers, timeout=30)
            response.raise_for_status()
            return {'success': True, 'data': response.json()}
        except requests.exceptions.Timeout:
            print(f"[WhatsApp] Timeout ao enviar mensagem")
            return {'success': False, 'error': 'Timeout'}
        except requests.exceptions.RequestException as e:
            print(f"[WhatsApp] Erro ao enviar mensagem: {e}")
            return {'success': False, 'error': str(e)}
    
    def enviar_texto(self, telefone, mensagem):
        """
        Envia mensagem de texto para um número
        
        Args:
            telefone: Número com DDD (ex: 21999998888)
            mensagem: Texto da mensagem
        """
        numero = self._formatar_numero(telefone)
        
        payload = {
            "number": numero,
            "text": mensagem
        }
        
        return self._fazer_request("sendText", payload)
    
    def enviar_para_grupo(self, grupo_id, mensagem):
        """
        Envia mensagem para um grupo do WhatsApp
        
        Args:
            grupo_id: ID do grupo (ex: 120363xxxxxx@g.us)
            mensagem: Texto da mensagem
        """
        payload = {
            "number": grupo_id,
            "text": mensagem
        }
        
        return self._fazer_request("sendText", payload)
    
    def _formatar_numero(self, telefone):
        """Formata número para padrão internacional"""
        # Remover caracteres especiais
        numero = ''.join(filter(str.isdigit, str(telefone)))
        
        # Adicionar código do Brasil se não tiver
        if len(numero) == 11:  # DDD + número
            numero = f"55{numero}"
        elif len(numero) == 10:  # DDD + número antigo (8 dígitos)
            numero = f"55{numero}"
        
        return numero
    
    def verificar_conexao(self):
        """Verifica se a instância está conectada"""
        url = f"{self.base_url}/instance/connectionState/{self.instance}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            data = response.json()
            return data.get('instance', {}).get('state') == 'open'
        except:
            return False


# ============================================================
# INSTÂNCIA GLOBAL
# ============================================================

whatsapp = EvolutionAPI()


# ============================================================
# FUNÇÕES DE NOTIFICAÇÃO
# ============================================================

def notificar_novo_desafio(challenger, challenged, scheduled_date):
    """
    Envia notificações quando um novo desafio é criado
    
    Args:
        challenger: dict com dados do desafiante (name, position, telefone)
        challenged: dict com dados do desafiado (name, position, telefone)
        scheduled_date: data do desafio (string YYYY-MM-DD)
    """
    if not WHATSAPP_ENABLED:
        print("[WhatsApp] Notificações desabilitadas")
        return
    
    # Formatar data
    try:
        data_formatada = datetime.strptime(scheduled_date, '%Y-%m-%d').strftime('%d/%m/%Y')
    except:
        data_formatada = scheduled_date
    
    # ========================================
    # 1. Mensagem privada para o DESAFIADO
    # ========================================
    telefone_desafiado = challenged.get('telefone') or challenged.get('phone')
    
    if telefone_desafiado:
        msg_privada = f"""🏌️ *NOVO DESAFIO!*

Você foi desafiado por *{challenger['name']}* (#{challenger['position']})

📅 Data proposta: {data_formatada}

Acesse o sistema para aceitar ou propor nova data.

⏰ Você tem 7 dias para responder."""

        resultado = whatsapp.enviar_texto(telefone_desafiado, msg_privada)
        
        if resultado['success']:
            print(f"[WhatsApp] Notificação enviada para {challenged['name']}")
        else:
            print(f"[WhatsApp] Falha ao notificar {challenged['name']}: {resultado.get('error')}")
    else:
        print(f"[WhatsApp] {challenged['name']} não tem telefone cadastrado")
    
    # ========================================
    # 2. Mensagem no GRUPO
    # ========================================
    msg_grupo = f"""🏆 *NOVO DESAFIO CRIADO*

⚔️ *{challenger['name']}* (#{challenger['position']}) 
    desafiou 
    *{challenged['name']}* (#{challenged['position']})

📅 Data: {data_formatada}

Boa sorte aos competidores! 🍀"""

    resultado_grupo = whatsapp.enviar_para_grupo(WHATSAPP_GRUPO_LIGA, msg_grupo)
    
    if resultado_grupo['success']:
        print("[WhatsApp] Mensagem enviada para o grupo")
    else:
        print(f"[WhatsApp] Falha ao enviar para grupo: {resultado_grupo.get('error')}")


def notificar_resultado_desafio(challenger, challenged, resultado, placar=None):
    """
    Envia notificação quando um desafio é concluído
    
    Args:
        challenger: dict com dados do desafiante
        challenged: dict com dados do desafiado  
        resultado: 'challenger_win' ou 'challenged_win'
        placar: string com o placar (opcional)
    """
    if not WHATSAPP_ENABLED:
        return
    
    if resultado == 'challenger_win':
        vencedor = challenger['name']
        perdedor = challenged['name']
        emoji = "🔥"
        texto_extra = f"*{challenger['name']}* sobe no ranking!"
    else:
        vencedor = challenged['name']
        perdedor = challenger['name']
        emoji = "🛡️"
        texto_extra = f"*{challenged['name']}* defendeu sua posição!"
    
    msg_grupo = f"""🏆 *RESULTADO DO DESAFIO*

{emoji} *{vencedor}* venceu *{perdedor}*
{f"📊 Placar: {placar}" if placar else ""}

{texto_extra}

Parabéns ao vencedor! 👏"""

    whatsapp.enviar_para_grupo(WHATSAPP_GRUPO_LIGA, msg_grupo)


def notificar_desafio_aceito(challenger, challenged, scheduled_date):
    """Notifica quando um desafio é aceito"""
    if not WHATSAPP_ENABLED:
        return
    
    try:
        data_formatada = datetime.strptime(scheduled_date, '%Y-%m-%d').strftime('%d/%m/%Y')
    except:
        data_formatada = scheduled_date
    
    # Notificar o desafiante
    telefone_desafiante = challenger.get('telefone') or challenger.get('phone')
    
    if telefone_desafiante:
        msg = f"""✅ *DESAFIO ACEITO!*

*{challenged['name']}* aceitou seu desafio!

📅 Data confirmada: {data_formatada}

Boa partida! 🏌️"""
        
        whatsapp.enviar_texto(telefone_desafiante, msg)
    
    # Notificar no grupo
    msg_grupo = f"""✅ *DESAFIO CONFIRMADO*

*{challenger['name']}* vs *{challenged['name']}*
📅 Data: {data_formatada}

Boa sorte a ambos! 🍀"""

    whatsapp.enviar_para_grupo(WHATSAPP_GRUPO_LIGA, msg_grupo)


def notificar_desafio_cancelado(challenger, challenged, motivo=None):
    """Notifica quando um desafio é cancelado"""
    if not WHATSAPP_ENABLED:
        return
    
    msg_grupo = f"""❌ *DESAFIO CANCELADO*

O desafio entre *{challenger['name']}* e *{challenged['name']}* foi cancelado.
{f"Motivo: {motivo}" if motivo else ""}"""

    whatsapp.enviar_para_grupo(WHATSAPP_GRUPO_LIGA, msg_grupo)

