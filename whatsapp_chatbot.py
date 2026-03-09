# ============================================================
# CHATBOT WHATSAPP - LIGA OLÍMPICA DE GOLFE
# ============================================================
# Adicione este código ao seu app.py
# ============================================================

import re
from datetime import datetime, timedelta
from flask import request, jsonify

# ============================================================
# CONFIGURAÇÃO DO WEBHOOK NA EVOLUTION API
# ============================================================
# Execute este comando no servidor para configurar o webhook:
#
# curl -X POST "http://159.89.35.66:8080/webhook/set/liga-golf" \
#   -H "apikey: liga-golf-api-key-2024" \
#   -H "Content-Type: application/json" \
#   -d '{
#     "url": "https://SEU_DOMINIO/webhook/whatsapp",
#     "webhookByEvents": true,
#     "events": ["MESSAGES_UPSERT"]
#   }'
#
# Substitua SEU_DOMINIO pelo domínio da sua aplicação Flask
# ============================================================


# ============================================================
# FUNÇÕES AUXILIARES
# ============================================================

def normalizar_telefone(telefone):
    """Remove caracteres não numéricos e padroniza o telefone"""
    if not telefone:
        return None
    # Remove tudo que não é número
    apenas_numeros = re.sub(r'\D', '', telefone)
    # Remove 55 do início se tiver (código do Brasil)
    if apenas_numeros.startswith('55') and len(apenas_numeros) > 11:
        apenas_numeros = apenas_numeros[2:]
    return apenas_numeros


def extrair_telefone_do_jid(jid):
    """Extrai número de telefone do JID do WhatsApp (ex: 5521999998888@s.whatsapp.net)"""
    if not jid:
        return None
    # Remove sufixo do WhatsApp
    numero = jid.split('@')[0]
    return normalizar_telefone(numero)


def get_player_by_phone(telefone):
    """Busca jogador pelo número de telefone"""
    telefone_normalizado = normalizar_telefone(telefone)
    if not telefone_normalizado:
        return None
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Busca considerando variações do número (com/sem 55, com/sem 9)
    cursor.execute("""
        SELECT id, name, position, sexo, telefone
        FROM players 
        WHERE REPLACE(REPLACE(REPLACE(telefone, '-', ''), ' ', ''), '+', '') LIKE ?
           OR REPLACE(REPLACE(REPLACE(telefone, '-', ''), ' ', ''), '+', '') LIKE ?
           OR REPLACE(REPLACE(REPLACE(telefone, '-', ''), ' ', ''), '+', '') LIKE ?
    """, (
        f'%{telefone_normalizado}',
        f'%{telefone_normalizado[-9:]}',  # Últimos 9 dígitos
        f'%{telefone_normalizado[-8:]}'   # Últimos 8 dígitos
    ))
    
    player = cursor.fetchone()
    conn.close()
    
    return dict(player) if player else None


def get_possiveis_desafiados(player_id):
    """Retorna lista de jogadores que podem ser desafiados"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Buscar dados do jogador
    cursor.execute("SELECT position, sexo FROM players WHERE id = ?", (player_id,))
    player = cursor.fetchone()
    
    if not player:
        conn.close()
        return []
    
    posicao_atual = player['position']
    sexo = player['sexo'] or 'masculino'
    
    # Calcular posição mínima (até 8 posições acima)
    posicao_minima = max(1, posicao_atual - 8)
    
    # Buscar possíveis desafiados (mesma categoria, posição superior, não bloqueados)
    cursor.execute("""
        SELECT id, name, position
        FROM players
        WHERE position >= ? 
          AND position < ?
          AND (sexo = ? OR sexo IS NULL OR sexo = '')
          AND (bloqueado = 0 OR bloqueado IS NULL)
          AND id != ?
        ORDER BY position ASC
    """, (posicao_minima, posicao_atual, sexo, player_id))
    
    desafiados = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    # Verificar se jogadores já têm desafios pendentes
    desafiados_disponiveis = []
    for d in desafiados:
        if not tem_desafio_ativo(d['id']) and not tem_desafio_ativo(player_id):
            desafiados_disponiveis.append(d)
    
    return desafiados_disponiveis


def tem_desafio_ativo(player_id):
    """Verifica se jogador tem desafio pendente ou aceito"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT COUNT(*) as count
        FROM challenges
        WHERE (challenger_id = ? OR challenged_id = ?)
          AND status IN ('pending', 'accepted')
    """, (player_id, player_id))
    
    result = cursor.fetchone()
    conn.close()
    
    return result['count'] > 0


def get_desafios_pendentes(player_id):
    """Retorna desafios pendentes do jogador (onde ele é o desafiado)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            c.id,
            c.status,
            c.scheduled_date,
            c.created_at,
            challenger.name as challenger_name,
            challenger.position as challenger_position
        FROM challenges c
        JOIN players challenger ON c.challenger_id = challenger.id
        WHERE c.challenged_id = ?
          AND c.status = 'pending'
        ORDER BY c.created_at DESC
    """, (player_id,))
    
    desafios = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return desafios


def get_meus_desafios(player_id):
    """Retorna todos os desafios ativos do jogador"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            c.id,
            c.status,
            c.scheduled_date,
            c.challenger_id,
            c.challenged_id,
            challenger.name as challenger_name,
            challenger.position as challenger_position,
            challenged.name as challenged_name,
            challenged.position as challenged_position
        FROM challenges c
        JOIN players challenger ON c.challenger_id = challenger.id
        JOIN players challenged ON c.challenged_id = challenged.id
        WHERE (c.challenger_id = ? OR c.challenged_id = ?)
          AND c.status IN ('pending', 'accepted')
        ORDER BY c.created_at DESC
    """, (player_id, player_id))
    
    desafios = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return desafios


def aceitar_desafio(challenge_id, player_id):
    """Aceita um desafio pendente"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar se o desafio existe e o jogador é o desafiado
    cursor.execute("""
        SELECT id, challenged_id, status
        FROM challenges
        WHERE id = ? AND challenged_id = ? AND status = 'pending'
    """, (challenge_id, player_id))
    
    challenge = cursor.fetchone()
    
    if not challenge:
        conn.close()
        return False, "Desafio não encontrado ou você não é o desafiado."
    
    # Atualizar status
    cursor.execute("""
        UPDATE challenges
        SET status = 'accepted', updated_at = ?
        WHERE id = ?
    """, (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), challenge_id))
    
    conn.commit()
    conn.close()
    
    return True, "Desafio aceito com sucesso!"


def rejeitar_desafio(challenge_id, player_id):
    """Rejeita um desafio (aplica WO - desafiado perde)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar se o desafio existe e o jogador é o desafiado
    cursor.execute("""
        SELECT c.id, c.challenger_id, c.challenged_id, c.status,
               challenger.position as challenger_pos,
               challenged.position as challenged_pos
        FROM challenges c
        JOIN players challenger ON c.challenger_id = challenger.id
        JOIN players challenged ON c.challenged_id = challenged.id
        WHERE c.id = ? AND c.challenged_id = ? AND c.status = 'pending'
    """, (challenge_id, player_id))
    
    challenge = cursor.fetchone()
    
    if not challenge:
        conn.close()
        return False, "Desafio não encontrado ou você não é o desafiado."
    
    # Aplicar WO - desafiante vence (desafiado rejeitou)
    # O desafiante sobe 1 posição (troca com o desafiado)
    challenger_id = challenge['challenger_id']
    challenged_id = challenge['challenged_id']
    challenger_pos = challenge['challenger_pos']
    challenged_pos = challenge['challenged_pos']
    
    # Trocar posições (desafiante assume posição do desafiado)
    cursor.execute("UPDATE players SET position = ? WHERE id = ?", (challenged_pos, challenger_id))
    cursor.execute("UPDATE players SET position = ? WHERE id = ?", (challenger_pos, challenged_id))
    
    # Atualizar desafio
    cursor.execute("""
        UPDATE challenges
        SET status = 'completed',
            result = 'challenger_win',
            result_type = 'wo_challenged',
            updated_at = ?
        WHERE id = ?
    """, (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), challenge_id))
    
    conn.commit()
    conn.close()
    
    return True, "Desafio rejeitado. WO aplicado - você perdeu a posição."


# ============================================================
# PROCESSADOR DE COMANDOS
# ============================================================

def processar_comando_whatsapp(mensagem, telefone):
    """Processa mensagem recebida e retorna resposta"""
    
    # Normalizar mensagem
    msg = mensagem.lower().strip()
    
    # Buscar jogador pelo telefone
    jogador = get_player_by_phone(telefone)
    
    if not jogador:
        return """❌ *Número não cadastrado*

Seu número de WhatsApp não está vinculado a nenhum jogador da Liga.

Para cadastrar, acesse seu perfil no site e adicione seu número no campo "WhatsApp para Notificações"."""
    
    # ---------------------------------------------------------
    # COMANDO: Meus desafiados / Quem posso desafiar
    # ---------------------------------------------------------
    if any(palavra in msg for palavra in ['desafiado', 'desafiar', 'quem posso', 'possiveis']):
        possiveis = get_possiveis_desafiados(jogador['id'])
        
        if not possiveis:
            return f"""🎯 *Possíveis Desafiados*

Olá, {jogador['name']}!

Você está na posição *{jogador['position']}º*.

No momento não há jogadores disponíveis para desafio. Isso pode ocorrer porque:
• Você já tem um desafio ativo
• Os jogadores acima estão com desafios pendentes
• Os jogadores acima estão bloqueados"""
        
        lista = "\n".join([f"   {p['position']}º - {p['name']}" for p in possiveis])
        
        return f"""🎯 *Possíveis Desafiados*

Olá, {jogador['name']}!
Você está na posição *{jogador['position']}º*.

Você pode desafiar:
{lista}

📱 Para criar um desafio, acesse o site da Liga."""
    
    # ---------------------------------------------------------
    # COMANDO: Minha posição / Ranking
    # ---------------------------------------------------------
    if any(palavra in msg for palavra in ['posição', 'posicao', 'ranking', 'colocação', 'colocacao']):
        return f"""📊 *Sua Posição no Ranking*

Olá, {jogador['name']}!

Você está atualmente na posição *{jogador['position']}º* no ranking da Liga Olímpica de Golfe."""
    
    # ---------------------------------------------------------
    # COMANDO: Aceitar desafio
    # ---------------------------------------------------------
    if 'aceitar' in msg or 'aceito' in msg:
        # Extrair número do desafio se fornecido
        numeros = re.findall(r'\d+', msg)
        
        desafios_pendentes = get_desafios_pendentes(jogador['id'])
        
        if not desafios_pendentes:
            return """✅ *Aceitar Desafio*

Você não tem nenhum desafio pendente para aceitar."""
        
        # Se tem só um desafio pendente e não especificou número
        if len(desafios_pendentes) == 1 and not numeros:
            desafio = desafios_pendentes[0]
            sucesso, mensagem_retorno = aceitar_desafio(desafio['id'], jogador['id'])
            
            if sucesso:
                # Notificar no grupo
                try:
                    notificar_desafio_aceito_bot(desafio['id'])
                except:
                    pass
                
                return f"""✅ *Desafio Aceito!*

Você aceitou o desafio de *{desafio['challenger_name']}* (posição {desafio['challenger_position']}º).

📅 Data agendada: {desafio['scheduled_date']}

Boa sorte! 🏌️"""
            else:
                return f"❌ {mensagem_retorno}"
        
        # Se especificou número do desafio
        if numeros:
            challenge_id = int(numeros[0])
            sucesso, mensagem_retorno = aceitar_desafio(challenge_id, jogador['id'])
            
            if sucesso:
                try:
                    notificar_desafio_aceito_bot(challenge_id)
                except:
                    pass
                return f"✅ *Desafio #{challenge_id} aceito com sucesso!*"
            else:
                return f"❌ {mensagem_retorno}"
        
        # Múltiplos desafios - pedir para especificar
        lista = "\n".join([f"   #{d['id']} - {d['challenger_name']} (posição {d['challenger_position']}º)" for d in desafios_pendentes])
        return f"""✅ *Aceitar Desafio*

Você tem {len(desafios_pendentes)} desafios pendentes:
{lista}

Para aceitar, digite:
*aceitar #[número]*

Exemplo: aceitar #123"""
    
    # ---------------------------------------------------------
    # COMANDO: Rejeitar desafio
    # ---------------------------------------------------------
    if any(palavra in msg for palavra in ['rejeitar', 'rejeito', 'recusar', 'recuso', 'negar', 'nego']):
        # Extrair número do desafio se fornecido
        numeros = re.findall(r'\d+', msg)
        
        desafios_pendentes = get_desafios_pendentes(jogador['id'])
        
        if not desafios_pendentes:
            return """❌ *Rejeitar Desafio*

Você não tem nenhum desafio pendente para rejeitar."""
        
        # Se tem só um desafio pendente e não especificou número
        if len(desafios_pendentes) == 1 and not numeros:
            desafio = desafios_pendentes[0]
            sucesso, mensagem_retorno = rejeitar_desafio(desafio['id'], jogador['id'])
            
            if sucesso:
                return f"""⚠️ *Desafio Rejeitado*

Você rejeitou o desafio de *{desafio['challenger_name']}*.

Como consequência, foi aplicado WO:
• {desafio['challenger_name']} assumiu sua posição
• Você desceu para a posição {desafio['challenger_position']}º"""
            else:
                return f"❌ {mensagem_retorno}"
        
        # Se especificou número do desafio
        if numeros:
            challenge_id = int(numeros[0])
            sucesso, mensagem_retorno = rejeitar_desafio(challenge_id, jogador['id'])
            
            if sucesso:
                return f"⚠️ *Desafio #{challenge_id} rejeitado.* WO aplicado."
            else:
                return f"❌ {mensagem_retorno}"
        
        # Múltiplos desafios - pedir para especificar
        lista = "\n".join([f"   #{d['id']} - {d['challenger_name']} (posição {d['challenger_position']}º)" for d in desafios_pendentes])
        return f"""❌ *Rejeitar Desafio*

⚠️ *ATENÇÃO*: Rejeitar um desafio resulta em WO (você perde a posição)!

Seus desafios pendentes:
{lista}

Para rejeitar, digite:
*rejeitar #[número]*

Exemplo: rejeitar #123"""
    
    # ---------------------------------------------------------
    # COMANDO: Meus desafios
    # ---------------------------------------------------------
    if 'desafio' in msg or 'pendente' in msg:
        desafios = get_meus_desafios(jogador['id'])
        
        if not desafios:
            return f"""📋 *Meus Desafios*

Olá, {jogador['name']}!

Você não tem desafios ativos no momento."""
        
        linhas = []
        for d in desafios:
            status_emoji = "⏳" if d['status'] == 'pending' else "✅"
            status_texto = "Pendente" if d['status'] == 'pending' else "Aceito"
            
            if d['challenger_id'] == jogador['id']:
                # Sou o desafiante
                linhas.append(f"   {status_emoji} #{d['id']} - Você → {d['challenged_name']} ({d['challenged_position']}º) [{status_texto}]")
            else:
                # Sou o desafiado
                linhas.append(f"   {status_emoji} #{d['id']} - {d['challenger_name']} ({d['challenger_position']}º) → Você [{status_texto}]")
        
        lista = "\n".join(linhas)
        
        # Verificar se tem pendentes para responder
        pendentes_para_responder = [d for d in desafios if d['status'] == 'pending' and d['challenged_id'] == jogador['id']]
        
        dica = ""
        if pendentes_para_responder:
            dica = "\n\n💡 *Dica*: Para responder desafios pendentes, digite:\n• *aceitar* ou *aceitar #123*\n• *rejeitar* ou *rejeitar #123*"
        
        return f"""📋 *Meus Desafios*

Olá, {jogador['name']}!

Seus desafios ativos:
{lista}{dica}"""
    
    # ---------------------------------------------------------
    # COMANDO: Ajuda / Menu
    # ---------------------------------------------------------
    return f"""🏌️ *Bot Liga Olímpica de Golfe*

Olá, {jogador['name']}! (Posição: {jogador['position']}º)

*Comandos disponíveis:*

📊 *"minha posição"*
   Ver sua posição atual no ranking

🎯 *"meus desafiados"*
   Ver quem você pode desafiar

📋 *"meus desafios"*
   Ver seus desafios ativos

✅ *"aceitar"* ou *"aceitar #123"*
   Aceitar um desafio pendente

❌ *"rejeitar"* ou *"rejeitar #123"*
   Rejeitar um desafio (aplica WO)

Digite qualquer comando para começar!"""


# ============================================================
# NOTIFICAÇÃO DE DESAFIO ACEITO (VIA BOT)
# ============================================================

def notificar_desafio_aceito_bot(challenge_id):
    """Envia notificação ao grupo quando desafio é aceito via bot"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            challenger.name as challenger_name,
            challenger.position as challenger_position,
            challenged.name as challenged_name,
            challenged.position as challenged_position,
            c.scheduled_date
        FROM challenges c
        JOIN players challenger ON c.challenger_id = challenger.id
        JOIN players challenged ON c.challenged_id = challenged.id
        WHERE c.id = ?
    """, (challenge_id,))
    
    challenge = cursor.fetchone()
    conn.close()
    
    if challenge:
        mensagem = f"""✅ *Desafio Aceito!*

{challenge['challenged_name']} ({challenge['challenged_position']}º) aceitou o desafio de {challenge['challenger_name']} ({challenge['challenger_position']}º)!

📅 Data: {challenge['scheduled_date']}

Boa sorte aos jogadores! 🏌️"""
        
        enviar_mensagem_whatsapp(WHATSAPP_GRUPO_LIGA, mensagem)


# ============================================================
# ROTA DO WEBHOOK
# ============================================================

@app.route('/webhook/whatsapp', methods=['POST'])
def webhook_whatsapp():
    """Recebe mensagens do WhatsApp via Evolution API"""
    try:
        data = request.json
        
        # Log para debug (remover em produção)
        app.logger.info(f"Webhook recebido: {data}")
        
        # Verificar se é uma mensagem válida
        if not data:
            return jsonify({'status': 'no data'}), 200
        
        # Extrair dados da mensagem
        event = data.get('event')
        
        # Só processar mensagens recebidas
        if event != 'messages.upsert':
            return jsonify({'status': 'ignored', 'reason': 'not a message event'}), 200
        
        message_data = data.get('data', {})
        key = message_data.get('key', {})
        
        # Ignorar mensagens enviadas por nós mesmos
        if key.get('fromMe', False):
            return jsonify({'status': 'ignored', 'reason': 'own message'}), 200
        
        # Ignorar mensagens de grupo (só processar mensagens privadas)
        remote_jid = key.get('remoteJid', '')
        if '@g.us' in remote_jid:
            return jsonify({'status': 'ignored', 'reason': 'group message'}), 200
        
        # Extrair texto da mensagem
        message = message_data.get('message', {})
        texto = (
            message.get('conversation') or 
            message.get('extendedTextMessage', {}).get('text') or
            ''
        )
        
        if not texto:
            return jsonify({'status': 'ignored', 'reason': 'no text'}), 200
        
        # Extrair telefone do remetente
        telefone = extrair_telefone_do_jid(remote_jid)
        
        if not telefone:
            return jsonify({'status': 'error', 'reason': 'invalid phone'}), 200
        
        # Processar comando
        resposta = processar_comando_whatsapp(texto, telefone)
        
        # Enviar resposta
        if resposta:
            enviar_mensagem_whatsapp(remote_jid, resposta)
        
        return jsonify({'status': 'ok'}), 200
        
    except Exception as e:
        app.logger.error(f"Erro no webhook WhatsApp: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============================================================
# FUNÇÃO PARA ENVIAR MENSAGEM
# ============================================================

def enviar_mensagem_whatsapp(destinatario, mensagem):
    """Envia mensagem para um número ou grupo"""
    import requests
    
    url = f"{EVOLUTION_API_URL}/message/sendText/{EVOLUTION_INSTANCE}"
    
    headers = {
        "apikey": EVOLUTION_API_KEY,
        "Content-Type": "application/json"
    }
    
    payload = {
        "number": destinatario,
        "text": mensagem
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        return response.status_code == 200 or response.status_code == 201
    except Exception as e:
        print(f"Erro ao enviar WhatsApp: {e}")
        return False


# ============================================================
# CONFIGURAÇÕES (copiar do whatsapp_integration.py)
# ============================================================

EVOLUTION_API_URL = "http://159.89.35.66:8080"
EVOLUTION_API_KEY = "liga-golf-api-key-2024"
EVOLUTION_INSTANCE = "liga-golf"
WHATSAPP_GRUPO_LIGA = "120363403838797386@g.us"