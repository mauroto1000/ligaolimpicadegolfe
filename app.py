from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import sqlite3
from datetime import datetime, timedelta
import os

# Removida a importação do APScheduler
# from apscheduler.schedulers.background import BackgroundScheduler
# import atexit

app = Flask(__name__)
app.secret_key = 'liga_olimpica_golfe_2025'

DATABASE = 'golf_league.db'

# Definição fixa da estrutura da pirâmide: quais posições pertencem a cada nível
# Seguindo o padrão tradicional de pirâmide: 1 posição no topo, depois 2, 3, 4, etc.
PYRAMID_STRUCTURE = {
    'A': [1],                      # Nível A: 1 posição
    'B': [2, 3],                   # Nível B: 2 posições
    'C': [4, 5, 6],                # Nível C: 3 posições
    'D': [7, 8, 9, 10],            # Nível D: 4 posições
    'E': [11, 12, 13, 14, 15],     # Nível E: 5 posições
    'F': [16, 17, 18, 19, 20, 21], # Nível F: 6 posições
    'G': [22, 23, 24, 25, 26, 27, 28], # Nível G: 7 posições
    'H': [29, 30, 31, 32, 33, 34, 35, 36], # Nível H: 8 posições
    'I': [37, 38, 39, 40, 41, 42, 43, 44, 45], # Nível I: 9 posições
    'J': [46, 47, 48, 49, 50, 51, 52, 53, 54, 55], # Nível J: 10 posições
    'K': [56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66] # Nível K: 11 posições
}

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Função para criar a tabela de histórico diário
def create_daily_history_table():
    conn = get_db_connection()
    conn.execute('''
    CREATE TABLE IF NOT EXISTS daily_ranking_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        player_id INTEGER NOT NULL,
        position INTEGER NOT NULL,
        tier TEXT NOT NULL,
        date_recorded DATE NOT NULL,
        FOREIGN KEY (player_id) REFERENCES players(id)
    )
    ''')
    
    # Criar um índice para melhorar a performance das consultas
    conn.execute('''
    CREATE INDEX IF NOT EXISTS idx_daily_history_player_date 
    ON daily_ranking_history (player_id, date_recorded)
    ''')
    
    conn.commit()
    conn.close()
    print("Tabela de histórico diário criada com sucesso.")

# MODIFICAÇÃO: Melhoria na função record_daily_rankings para permitir sobrescrever registros
def record_daily_rankings(force_update=False):
    """
    Registra as posições diárias de todos os jogadores.
    Se force_update=True, registros existentes serão substituídos.
    """
    conn = get_db_connection()
    today = datetime.now().date()
    
    # Verificar se já temos registros para hoje
    existing = conn.execute(
        'SELECT COUNT(*) as count FROM daily_ranking_history WHERE date_recorded = ?', 
        (today.strftime('%Y-%m-%d'),)
    ).fetchone()
    
    if existing and existing['count'] > 0 and not force_update:
        print(f"Já existem registros para {today}. Pulando...")
        conn.close()
        return False
    
    # Se existem registros e force_update=True, remover registros existentes
    if existing and existing['count'] > 0 and force_update:
        conn.execute('DELETE FROM daily_ranking_history WHERE date_recorded = ?', 
                    (today.strftime('%Y-%m-%d'),))
        print(f"Removidos registros existentes de {today} para atualização forçada")
    
    try:
        # Obter todos os jogadores ativos
        players = conn.execute('SELECT id, position, tier FROM players WHERE active = 1 ORDER BY position').fetchall()
        
        # Registrar posição atual de cada jogador
        for player in players:
            conn.execute('''
                INSERT INTO daily_ranking_history 
                (player_id, position, tier, date_recorded)
                VALUES (?, ?, ?, ?)
            ''', (player['id'], player['position'], player['tier'], today.strftime('%Y-%m-%d')))
        
        conn.commit()
        print(f"Registrados {len(players)} jogadores no histórico diário para {today}")
        return True
    except Exception as e:
        conn.rollback()
        print(f"Erro ao registrar histórico diário: {str(e)}")
        return False
    finally:
        conn.close()


def sync_ranking_history_tables(conn=None, specific_date=None):
    """
    Sincroniza as tabelas ranking_history e daily_ranking_history.
    Se uma data específica for fornecida, sincroniza apenas para essa data.
    Caso contrário, sincroniza para a data atual.
    
    Args:
        conn: Conexão com o banco de dados (opcional)
        specific_date: Data específica para sincronização (opcional)
    """
    # Determinar se precisamos criar e fechar a conexão
    connection_provided = conn is not None
    if not connection_provided:
        conn = get_db_connection()
    
    try:
        # Determinar a data para sincronização
        if specific_date:
            target_date = specific_date
        else:
            target_date = datetime.now().date()
        
        target_date_str = target_date.strftime('%Y-%m-%d')
        
        # Verificar se existem registros no daily_ranking_history para a data alvo
        existing = conn.execute(
            'SELECT COUNT(*) as count FROM daily_ranking_history WHERE date_recorded = ?', 
            (target_date_str,)
        ).fetchone()
        
        # Obter todas as alterações de ranking para a data alvo
        ranking_changes = conn.execute('''
            SELECT player_id, new_position, new_tier, change_date 
            FROM ranking_history 
            WHERE date(change_date) = ? 
            ORDER BY change_date DESC
        ''', (target_date_str,)).fetchall()
        
        # Se existem alterações para hoje, vamos usar as informações mais recentes
        # para atualizar ou criar o registro diário
        if ranking_changes:
            # Remover registros existentes para a data alvo
            conn.execute('DELETE FROM daily_ranking_history WHERE date_recorded = ?', 
                       (target_date_str,))
            
            # Mapear as posições mais recentes para cada jogador alterado hoje
            player_latest_positions = {}
            for change in ranking_changes:
                player_id = change['player_id']
                if player_id not in player_latest_positions:
                    player_latest_positions[player_id] = {
                        'position': change['new_position'],
                        'tier': change['new_tier']
                    }
            
            # Obter todos os jogadores ativos
            all_players = conn.execute('SELECT id, position, tier FROM players WHERE active = 1').fetchall()
            
            # Inserir registros diários atualizados
            for player in all_players:
                player_id = player['id']
                
                # Se o jogador teve alteração hoje, use a posição da alteração
                if player_id in player_latest_positions:
                    position = player_latest_positions[player_id]['position']
                    tier = player_latest_positions[player_id]['tier']
                # Caso contrário, use a posição atual
                else:
                    position = player['position']
                    tier = player['tier']
                
                # Inserir registro diário
                conn.execute('''
                    INSERT INTO daily_ranking_history 
                    (player_id, position, tier, date_recorded)
                    VALUES (?, ?, ?, ?)
                ''', (player_id, position, tier, target_date_str))
            
            print(f"Sincronizado histórico diário para {target_date_str} com base em {len(ranking_changes)} alterações")
        # Se não existem alterações para a data alvo e não existem registros diários
        elif not existing or existing['count'] == 0:
            # Registrar snapshot das posições atuais
            record_daily_rankings(force_update=True)
            print(f"Criado novo snapshot para {target_date_str} por não existirem alterações ou registros")
        
        # Se não chegamos aqui, é porque já existem registros diários e não há alterações
        # para a data alvo, então não precisamos fazer nada
        
        if not connection_provided:
            conn.commit()
        
    except Exception as e:
        print(f"Erro ao sincronizar histórico: {str(e)}")
        if not connection_provided:
            conn.rollback()
    finally:
        if not connection_provided:
            conn.close()


@app.route('/force_record_daily', methods=['GET'])
def force_record_daily():
    conn = get_db_connection()
    today = datetime.now().date()
    
    try:
        # Remover registros existentes para hoje
        conn.execute(
            'DELETE FROM daily_ranking_history WHERE date_recorded = ?', 
            (today.strftime('%Y-%m-%d'),)
        )
        
        # Obter todos os jogadores ativos
        players = conn.execute('SELECT id, position, tier FROM players WHERE active = 1 ORDER BY position').fetchall()
        
        # Registrar posição atual de cada jogador
        for player in players:
            conn.execute('''
                INSERT INTO daily_ranking_history 
                (player_id, position, tier, date_recorded)
                VALUES (?, ?, ?, ?)
            ''', (player['id'], player['position'], player['tier'], today.strftime('%Y-%m-%d')))
        
        conn.commit()
        flash(f'Posições atualizadas com sucesso no histórico para {today.strftime("%d/%m/%Y")}!', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao atualizar histórico: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('index'))

# Rota para diagnosticar e corrigir o histórico
@app.route('/fix_history', methods=['GET'])
def fix_history():
    """
    Verifica e corrige problemas no histórico diário:
    - Remove posições duplicadas para a mesma data
    - Garante que não há lacunas nas posições para cada data
    """
    conn = get_db_connection()
    
    try:
        # Buscar todas as datas distintas no histórico
        dates = conn.execute(
            'SELECT DISTINCT date_recorded FROM daily_ranking_history ORDER BY date_recorded'
        ).fetchall()
        
        total_fixed = 0
        
        for date_record in dates:
            date = date_record['date_recorded']
            
            # Verificar posições duplicadas na mesma data
            duplicates = conn.execute('''
                SELECT position, COUNT(*) as count
                FROM daily_ranking_history
                WHERE date_recorded = ?
                GROUP BY position
                HAVING COUNT(*) > 1
            ''', (date,)).fetchall()
            
            # Se encontrar duplicatas, corrigir
            if duplicates:
                for dup in duplicates:
                    position = dup['position']
                    
                    # Buscar jogadores com esta posição duplicada
                    players_with_dup = conn.execute('''
                        SELECT h.id, h.player_id, p.name
                        FROM daily_ranking_history h
                        JOIN players p ON h.player_id = p.id
                        WHERE h.date_recorded = ? AND h.position = ?
                        ORDER BY h.id
                    ''', (date, position)).fetchall()
                    
                    # Manter apenas o primeiro registro (o mais antigo) e remover os outros
                    if len(players_with_dup) > 1:
                        for player in players_with_dup[1:]:
                            conn.execute('DELETE FROM daily_ranking_history WHERE id = ?', (player['id'],))
                            total_fixed += 1
            
            # Verificar se há lacunas nas posições sequenciais para esta data
            positions = conn.execute('''
                SELECT position 
                FROM daily_ranking_history
                WHERE date_recorded = ?
                ORDER BY position
            ''', (date,)).fetchall()
            
            positions_list = [p['position'] for p in positions]
            expected_positions = list(range(1, len(positions_list) + 1))
            
            if positions_list != expected_positions:
                # Há uma discrepância - recalcular posições
                records = conn.execute('''
                    SELECT id, player_id
                    FROM daily_ranking_history
                    WHERE date_recorded = ?
                    ORDER BY position
                ''', (date,)).fetchall()
                
                # Atualizar posições para serem sequenciais
                for i, record in enumerate(records, 1):
                    conn.execute('''
                        UPDATE daily_ranking_history
                        SET position = ?
                        WHERE id = ?
                    ''', (i, record['id']))
                    
                    # Também atualizar o tier com base na nova posição
                    tier = get_tier_from_position(i)
                    conn.execute('''
                        UPDATE daily_ranking_history
                        SET tier = ?
                        WHERE id = ?
                    ''', (tier, record['id']))
                    
                    total_fixed += 1
        
        conn.commit()
        
        if total_fixed > 0:
            flash(f'Histórico corrigido: {total_fixed} problemas resolvidos.', 'success')
        else:
            flash('Nenhum problema encontrado no histórico.', 'info')
            
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao corrigir o histórico: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('ranking_history'))



# Função para determinar o tier com base na posição
def get_tier_from_position(position):
    """
    Determina o nível (tier) com base na posição na pirâmide.
    Segue o padrão tradicional de pirâmide: n posições no nível n.
    """
    # Verificar em cada tier definido na estrutura
    for tier, positions in PYRAMID_STRUCTURE.items():
        if position in positions:
            return tier
    
    # Para posições que excederam a estrutura definida
    # Cálculo automático para tiers adicionais
    
    # Primeiro, determinar o último número do último tier definido
    last_tier_letter = list(PYRAMID_STRUCTURE.keys())[-1]
    last_tier_number = ord(last_tier_letter) - ord('A') + 1  # A=1, B=2, etc.
    last_position = max(PYRAMID_STRUCTURE[last_tier_letter])
    
    # Agora calcular para posições maiores
    current_tier_number = last_tier_number
    current_tier_start = last_position + 1
    
    while True:
        current_tier_number += 1
        current_tier_size = current_tier_number  # Cada tier tem tantas posições quanto seu número
        current_tier_end = current_tier_start + current_tier_size - 1
        
        if position >= current_tier_start and position <= current_tier_end:
            # Converter número do tier de volta para letra (12 = L, 13 = M, etc.)
            return chr(ord('A') + current_tier_number - 1)
        
        current_tier_start = current_tier_end + 1
        
        # Salvaguarda para evitar loop infinito
        if current_tier_number > 100:
            return 'Z'  # Tier final para posições extremamente altas

# Função para atualizar todos os tiers baseado nas posições atuais
def update_all_tiers(conn):
    """
    Atualiza o tier de todos os jogadores com base em suas posições atuais e na estrutura fixa da pirâmide.
    """
    # Buscar todos os jogadores ordenados por posição
    players = conn.execute('SELECT id, position FROM players WHERE active = 1 AND position IS NOT NULL ORDER BY position').fetchall()
    
    # Atualizar o tier de cada jogador com base em sua posição
    for player in players:
        position = player['position']
        correct_tier = get_tier_from_position(position)
        
        # Atualizar o tier no banco de dados
        conn.execute('UPDATE players SET tier = ? WHERE id = ?', (correct_tier, player['id']))
    
    conn.commit()
    print("Todos os tiers atualizados com base nas posições fixas da pirâmide.")

# Função para verificar a estrutura da pirâmide
def verify_pyramid_structure(conn):
    """
    Verifica se todos os jogadores estão no tier correto de acordo com suas posições.
    Retorna uma lista de jogadores com tiers incorretos.
    """
    players = conn.execute('SELECT id, name, position, tier FROM players WHERE active = 1 AND position IS NOT NULL ORDER BY position').fetchall()
    incorrect_players = []
    
    for player in players:
        correct_tier = get_tier_from_position(player['position'])
        if player['tier'] != correct_tier:
            incorrect_players.append({
                'id': player['id'],
                'name': player['name'],
                'position': player['position'],
                'current_tier': player['tier'],
                'correct_tier': correct_tier
            })
    
    return incorrect_players

# Nova função para verificar e corrigir lacunas nas posições
def fix_position_gaps(conn):
    """
    Verifica se há lacunas nas posições dos jogadores e as corrige, 
    garantindo que as posições sejam sequenciais (1, 2, 3, ...).
    """
    # Buscar todos os jogadores ordenados por posição atual
    players = conn.execute('SELECT id, position FROM players WHERE active = 1 AND position IS NOT NULL ORDER BY position').fetchall()
    
    # Verificar e corrigir lacunas
    expected_position = 1
    for player in players:
        if player['position'] != expected_position:
            # Corrigir a posição se não estiver na sequência esperada
            conn.execute('UPDATE players SET position = ? WHERE id = ?', 
                       (expected_position, player['id']))
            print(f"Corrigida posição do jogador ID {player['id']}: {player['position']} -> {expected_position}")
        expected_position += 1
    
    # Não é necessário commitar aqui, pois essa função é chamada dentro de outra
    # que já tem seu próprio commit

# Função aprimorada para ajustar a pirâmide quando ocorrem mudanças de posição
def rebalance_positions_after_challenge(conn, winner_id, loser_id, winner_new_pos, loser_new_pos):
    """
    Ajusta as posições de todos os jogadores após um desafio, mantendo a sequência correta.
    Versão melhorada que lida corretamente com todos os cenários de movimentação.
    """
    # Buscar posições atuais
    winner_data = conn.execute('SELECT position FROM players WHERE id = ?', (winner_id,)).fetchone()
    loser_data = conn.execute('SELECT position FROM players WHERE id = ?', (loser_id,)).fetchone()
    
    if not winner_data or not loser_data:
        print("Erro: Jogador não encontrado")
        return
        
    winner_old_pos = winner_data['position']
    loser_old_pos = loser_data['position']
    
    # Caso 1: Se o vencedor está subindo (posição menor numericamente é melhor)
    if winner_new_pos < winner_old_pos:
        # Primeiro, atualizar todos os jogadores entre as posições (ajustar uma posição para baixo)
        conn.execute('''
            UPDATE players 
            SET position = position + 1 
            WHERE position >= ? AND position < ?
            AND id != ? AND id != ?
            AND active = 1
        ''', (winner_new_pos, winner_old_pos, winner_id, loser_id))
        
        # Em seguida, definir as novas posições para vencedor e perdedor
        conn.execute('UPDATE players SET position = ? WHERE id = ?', (winner_new_pos, winner_id))
        
        # O perdedor só muda de posição se ele for o jogador diretamente desafiado
        if loser_old_pos == winner_new_pos:
            conn.execute('UPDATE players SET position = ? WHERE id = ?', (loser_new_pos, loser_id))
    
    # Caso 2: Caso especial ou ajuste direto de posições
    else:
        # Definir as novas posições diretamente
        conn.execute('UPDATE players SET position = ? WHERE id = ?', (winner_new_pos, winner_id))
        conn.execute('UPDATE players SET position = ? WHERE id = ?', (loser_new_pos, loser_id))
    
    # Verificar se há lacunas nas posições e corrigi-las
    fix_position_gaps(conn)
    
    # Atualizar todos os tiers com base nas novas posições
    update_all_tiers(conn)
    
    conn.commit()
    print("Posições e tiers rebalanceados após o desafio.")

# Função aprimorada para processar o resultado de um desafio
# Adição de código para função existente process_challenge_result

def process_challenge_result(conn, challenge_id, status, result):
    """
    Processa o resultado de um desafio, atualizando posições e tiers conforme necessário.
    Versão melhorada que garante a consistência da pirâmide e registra o histórico diário.
    Agora suporta o status "completed_pending" que finaliza o desafio sem alterar o ranking.
    """
    # Atualizar o status e resultado do desafio
    conn.execute('UPDATE challenges SET status = ?, result = ? WHERE id = ?', 
                (status, result, challenge_id))
    
    # Se for "Concluído (com pendência)", apenas registramos o resultado sem alterar posições
    if status == 'completed_pending':
        conn.commit()
        return
    
    if status == 'completed' and result:
        # Buscar informações detalhadas do desafio
        challenge = conn.execute('''
            SELECT c.*, 
                   p1.id as challenger_id, p1.position as challenger_position, p1.tier as challenger_tier,
                   p2.id as challenged_id, p2.position as challenged_position, p2.tier as challenged_tier
            FROM challenges c
            JOIN players p1 ON c.challenger_id = p1.id
            JOIN players p2 ON c.challenged_id = p2.id
            WHERE c.id = ?
        ''', (challenge_id,)).fetchone()
        
        if not challenge:
            print(f"Erro: Desafio ID {challenge_id} não encontrado")
            conn.rollback()
            return
        
        # Guardar posições e tiers antigos para histórico
        challenger_old_pos = challenge['challenger_position']
        challenger_old_tier = challenge['challenger_tier']
        challenged_old_pos = challenge['challenged_position']
        challenged_old_tier = challenge['challenged_tier']
        
        try:
            if result == 'challenger_win':
                # O desafiante vence e assume a posição do desafiado
                rebalance_positions_after_challenge(
                    conn, 
                    challenge['challenger_id'], 
                    challenge['challenged_id'],
                    challenge['challenged_position'],  # Nova posição do vencedor (desafiante)
                    challenge['challenged_position'] + 1  # Nova posição do perdedor (desafiado)
                )
            elif result == 'challenged_win':
                # Se o desafiado ganhar, as posições permanecem as mesmas
                # Mas ainda registramos no histórico
                pass
            else:
                # Resultado inválido
                print(f"Erro: Resultado inválido: {result}")
                conn.rollback()
                return
            
            # Buscar as novas posições e tiers após o rebalanceamento
            new_challenger = conn.execute('SELECT position, tier FROM players WHERE id = ?', 
                                        (challenge['challenger_id'],)).fetchone()
            new_challenged = conn.execute('SELECT position, tier FROM players WHERE id = ?', 
                                        (challenge['challenged_id'],)).fetchone()
            
            # Verificar se houve mudança nas posições
            if new_challenger['position'] != challenger_old_pos:
                # Registrar no histórico para o desafiante
                conn.execute('''
                    INSERT INTO ranking_history 
                    (player_id, old_position, new_position, old_tier, new_tier, reason, challenge_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (challenge['challenger_id'], challenger_old_pos, new_challenger['position'], 
                     challenger_old_tier, new_challenger['tier'], 
                     'challenge_win' if result == 'challenger_win' else 'no_change', challenge_id))
            
            if new_challenged['position'] != challenged_old_pos:
                # Registrar no histórico para o desafiado
                conn.execute('''
                    INSERT INTO ranking_history 
                    (player_id, old_position, new_position, old_tier, new_tier, reason, challenge_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (challenge['challenged_id'], challenged_old_pos, new_challenged['position'], 
                     challenged_old_tier, new_challenged['tier'], 
                     'challenge_loss' if result == 'challenger_win' else 'no_change', challenge_id))
            
            # Sincronizar as tabelas de histórico para garantir consistência
            sync_ranking_history_tables(conn)
            
        except Exception as e:
            print(f"Erro ao processar resultado do desafio: {e}")
            conn.rollback()
            raise
    
    conn.commit()
    
    # Verificar a integridade da pirâmide após as alterações
    incorrect_players = verify_pyramid_structure(conn)
    if incorrect_players:
        print(f"Atenção: {len(incorrect_players)} jogadores com tiers incorretos após o desafio.")
        # Forçar atualização de todos os tiers
        update_all_tiers(conn)
        conn.commit()
        print("Tiers corrigidos automaticamente.")

def revert_challenge_result(conn, challenge_id):
    """
    Reverte as alterações feitas por um desafio no ranking.
    Restaura as posições anteriores dos jogadores, remove os registros de histórico
    e atualiza o histórico diário.
    """
    # Buscar registros de histórico para este desafio
    history_records = conn.execute('''
        SELECT * FROM ranking_history 
        WHERE challenge_id = ? 
        ORDER BY change_date DESC
    ''', (challenge_id,)).fetchall()
    
    # Para cada registro, restaurar a posição anterior
    for record in history_records:
        player_id = record['player_id']
        old_position = record['old_position']
        old_tier = record['old_tier']
        
        # Restaurar a posição e tier anteriores
        conn.execute('''
            UPDATE players 
            SET position = ?, tier = ? 
            WHERE id = ?
        ''', (old_position, old_tier, player_id))
    
    # Rebalancear todas as posições para garantir que não haja lacunas
    fix_position_gaps(conn)
    update_all_tiers(conn)
    
    # Remover os registros de histórico relacionados a este desafio
    conn.execute('DELETE FROM ranking_history WHERE challenge_id = ?', (challenge_id,))
    
    # Atualizar o desafio para remover o resultado
    conn.execute('UPDATE challenges SET result = NULL WHERE id = ?', (challenge_id,))
    
    # NOVA ADIÇÃO: Sincronizar as tabelas de histórico após reverter um desafio
    sync_ranking_history_tables(conn)
    
    conn.commit()
    print(f"Alterações do desafio ID {challenge_id} foram revertidas com sucesso.")

# Rota para registrar posições diárias manualmente
@app.route('/record_daily_rankings', methods=['GET', 'POST'])
def record_daily_rankings_route():
    if request.method == 'POST':
        senha = request.form.get('senha', '')
        
        if senha != '123':
            flash('Senha incorreta! Operação não autorizada.', 'error')
            return redirect(url_for('index'))
        
        result = record_daily_rankings()
        
        if result:
            flash('Posições registradas com sucesso no histórico diário!', 'success')
        else:
            flash('As posições de hoje já foram registradas anteriormente.', 'info')
        
        return redirect(url_for('index'))
    
    # Para método GET, mostrar o formulário
    return render_template('record_daily_rankings.html')

# Rota para visualizar o histórico de posições de um jogador
@app.route('/player/<int:player_id>/ranking_history')
def player_ranking_history(player_id):
    conn = get_db_connection()
    
    # Verificar se o jogador existe
    player = conn.execute('SELECT * FROM players WHERE id = ?', (player_id,)).fetchone()
    
    if not player:
        conn.close()
        flash('Jogador não encontrado!', 'error')
        return redirect(url_for('index'))
    
    # Obter o período desejado (padrão: últimos 30 dias)
    days = request.args.get('days', 30, type=int)
    
    # Calcular a data limite
    limit_date = (datetime.now() - timedelta(days=days)).date()
    
    # Buscar o histórico diário do jogador
    daily_history = conn.execute('''
        SELECT date_recorded, position, tier
        FROM daily_ranking_history
        WHERE player_id = ? AND date_recorded >= ?
        ORDER BY date_recorded
    ''', (player_id, limit_date.strftime('%Y-%m-%d'))).fetchall()
    
    # Buscar eventos específicos do ranking_history
    specific_changes = conn.execute('''
        SELECT date(change_date) as event_date, old_position, new_position, old_tier, new_tier, reason
        FROM ranking_history
        WHERE player_id = ? AND date(change_date) >= ?
        ORDER BY change_date
    ''', (player_id, limit_date.strftime('%Y-%m-%d'))).fetchall()
    
    # Combinar dados para visualização
    dates = []
    positions = []
    tiers = []
    events = []
    
    # Converter daily_history para um dicionário para fácil acesso
    daily_dict = {item['date_recorded']: {'position': item['position'], 'tier': item['tier']} for item in daily_history}
    
    # Converter specific_changes para um dicionário
    changes_dict = {}
    for change in specific_changes:
        if change['event_date'] not in changes_dict:
            changes_dict[change['event_date']] = []
        changes_dict[change['event_date']].append(change)
    
    # Criar série temporal contínua
    current_date = limit_date
    end_date = datetime.now().date()
    
    while current_date <= end_date:
        current_date_str = current_date.strftime('%Y-%m-%d')
        
        # Adicionar data
        dates.append(current_date_str)
        
        # Verificar se temos um registro diário para esta data
        if current_date_str in daily_dict:
            positions.append(daily_dict[current_date_str]['position'])
            tiers.append(daily_dict[current_date_str]['tier'])
        else:
            # Se não temos registro para esta data, usar valor anterior ou None
            if positions:
                positions.append(positions[-1])
                tiers.append(tiers[-1])
            else:
                positions.append(None)
                tiers.append(None)
        
        # Verificar se temos eventos específicos para esta data
        if current_date_str in changes_dict:
            # Usar o último evento do dia para esta posição
            latest_change = changes_dict[current_date_str][-1]
            positions[-1] = latest_change['new_position']
            tiers[-1] = latest_change['new_tier']
            events.append({
                'date': current_date_str,
                'reason': latest_change['reason'],
                'old_position': latest_change['old_position'],
                'new_position': latest_change['new_position']
            })
        
        current_date += timedelta(days=1)
    
    conn.close()
    
    return render_template('player_ranking_history.html', 
                          player=player, 
                          dates=dates, 
                          positions=positions,
                          tiers=tiers,
                          events=events,
                          days=days)


# API para obter dados filtrados para o gráfico
@app.route('/api/player/<int:player_id>/ranking_history')
def api_player_ranking_history(player_id):
    conn = get_db_connection()
    
    # Obter o período desejado
    days = request.args.get('days', 30, type=int)
    
    # Calcular a data limite
    limit_date = (datetime.now() - timedelta(days=days)).date()
    
    # Buscar o histórico do jogador
    history = conn.execute('''
        SELECT date_recorded, position, tier
        FROM daily_ranking_history
        WHERE player_id = ? AND date_recorded >= ?
        ORDER BY date_recorded
    ''', (player_id, limit_date.strftime('%Y-%m-%d'))).fetchall()
    
    # Prepara os dados para o gráfico
    dates = [item['date_recorded'] for item in history]
    positions = [item['position'] for item in history]
    tiers = [item['tier'] for item in history]
    
    conn.close()
    
    return jsonify({
        'dates': dates,
        'positions': positions,
        'tiers': tiers
    })

@app.route('/deactivate_player/<int:player_id>', methods=['GET', 'POST'])
def deactivate_player(player_id):
    """
    Inativa um jogador e oferece opções para reorganizar ou não o ranking.
    GET: Mostra formulário de confirmação
    POST: Processa a inativação
    """
    conn = get_db_connection()
    
    # Buscar jogador
    player = conn.execute('SELECT * FROM players WHERE id = ?', (player_id,)).fetchone()
    
    if not player:
        conn.close()
        flash('Jogador não encontrado!', 'error')
        return redirect(url_for('index'))
    
    # Para requisição GET, mostrar tela de confirmação
    if request.method == 'GET':
        conn.close()
        return render_template('deactivate_player.html', player=player)
    
    # Para requisição POST, processar a inativação
    senha = request.form.get('senha', '')
    rerank = request.form.get('rerank', 'no') == 'yes'
    
    if senha != '123':
        conn.close()
        flash('Senha incorreta! Operação não autorizada.', 'error')
        return redirect(url_for('player_detail', player_id=player_id))
    
    try:
        current_position = player['position']
        current_tier = player['tier']
        
        # Se rerank=True, inativa e reorganiza ranking
        if rerank:
            # 1. Marcar o jogador como inativo - CORRIGIDO: não definir position/tier como NULL
            conn.execute('''
                UPDATE players
                SET active = 0, 
                    notes = ?
                WHERE id = ?
            ''', (f"Inativado em {datetime.now().strftime('%d/%m/%Y')}. Posição anterior: {current_position} (Tier {current_tier})", 
                  player_id))
            
            # 2. Registrar a inativação no histórico
            conn.execute('''
                INSERT INTO ranking_history 
                (player_id, old_position, new_position, old_tier, new_tier, reason)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (player_id, current_position, current_position, current_tier, current_tier, 'player_inactivated'))
            
            # 3. Ajustar posições de todos os jogadores abaixo
            conn.execute('''
                UPDATE players
                SET position = position - 1
                WHERE position > ? AND active = 1
            ''', (current_position,))
            
            # 4. Removido o trecho que registrava os ajustes de posição no histórico
            # para todos os jogadores afetados pelo reposicionamento
            
            flash_message = 'Jogador inativado com sucesso e ranking reorganizado.'
        else:
            # Apenas inativa o jogador sem reorganizar
            conn.execute('''
                UPDATE players
                SET active = 0, 
                    notes = ?
                WHERE id = ?
            ''', (f"Inativado em {datetime.now().strftime('%d/%m/%Y')}. Mantida posição: {current_position} (Tier {current_tier})", 
                  player_id))
            
            # Registrar a inativação no histórico sem ajuste de posição
            conn.execute('''
                INSERT INTO ranking_history 
                (player_id, old_position, new_position, old_tier, new_tier, reason)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (player_id, current_position, current_position, current_tier, current_tier, 'player_inactivated_nochange'))
            
            flash_message = 'Jogador inativado com sucesso. Posição no ranking mantida (jogador ficará invisível nas visualizações).'
        
        # 5. Cancelar quaisquer desafios pendentes
        conn.execute('''
            UPDATE challenges
            SET status = 'cancelled', result = 'player_inactive'
            WHERE (challenger_id = ? OR challenged_id = ?) AND status IN ('pending', 'accepted')
        ''', (player_id, player_id))
        
        # 6. Atualizar tiers após a reorganização de posições
        update_all_tiers(conn)
        
        conn.commit()
        flash(flash_message, 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao processar operação: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('index'))

@app.route('/reactivate_player/<int:player_id>', methods=['GET', 'POST'])
def reactivate_player(player_id):
    """
    Reativa um jogador inativo, colocando-o na última posição do ranking
    """
    conn = get_db_connection()
    
    # Buscar jogador
    player = conn.execute('SELECT * FROM players WHERE id = ? AND active = 0', (player_id,)).fetchone()
    
    if not player:
        conn.close()
        flash('Jogador não encontrado ou já está ativo!', 'error')
        return redirect(url_for('index'))
    
    # Para requisição GET, mostrar tela de confirmação
    if request.method == 'GET':
        conn.close()
        return render_template('reactivate_player.html', player=player)
    
    # Para requisição POST, processar a reativação
    senha = request.form.get('senha', '')
    
    if senha != '123':
        conn.close()
        flash('Senha incorreta! Operação não autorizada.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Determinar a última posição do ranking
        last_pos = conn.execute('SELECT MAX(position) as max_pos FROM players WHERE active = 1').fetchone()
        new_position = 1 if not last_pos['max_pos'] else last_pos['max_pos'] + 1
        new_tier = get_tier_from_position(new_position)
        
        # Reativar jogador na última posição do ranking
        conn.execute('''
            UPDATE players
            SET active = 1, 
                position = ?,
                tier = ?,
                notes = ?
            WHERE id = ?
        ''', (new_position, new_tier, 
              f"{player['notes'] or ''} | Reativado em {datetime.now().strftime('%d/%m/%Y')}",
              player_id))
        
        # Registrar a reativação no histórico
        conn.execute('''
            INSERT INTO ranking_history 
            (player_id, old_position, new_position, old_tier, new_tier, reason)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (player_id, player['position'], new_position, player['tier'], new_tier, 'player_reactivated'))
        
        conn.commit()
        flash(f'Jogador reativado com sucesso na posição {new_position}.', 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao reativar jogador: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('player_detail', player_id=player_id))

@app.route('/update_player_name/<int:player_id>', methods=['POST'])
def update_player_name(player_id):
    """
    Atualiza o nome de um jogador
    """
    conn = get_db_connection()
    
    # Verificar se o jogador existe
    player = conn.execute('SELECT * FROM players WHERE id = ?', (player_id,)).fetchone()
    
    if not player:
        conn.close()
        flash('Jogador não encontrado!', 'error')
        return redirect(url_for('index'))
    
    # Verificar senha
    senha = request.form.get('senha', '')
    if senha != '123':
        conn.close()
        flash('Senha incorreta! Operação não autorizada.', 'error')
        return redirect(url_for('player_detail', player_id=player_id))
    
    # Obter novo nome
    new_name = request.form.get('new_name', '').strip()
    old_name = player['name']
    
    # Validar novo nome
    if not new_name:
        conn.close()
        flash('O nome não pode estar vazio!', 'error')
        return redirect(url_for('player_detail', player_id=player_id))
    
    # Se o nome não mudou, não fazer nada
    if new_name == old_name:
        conn.close()
        flash('Nenhuma alteração foi realizada.', 'info')
        return redirect(url_for('player_detail', player_id=player_id))
    
    try:
        # Atualizar o nome do jogador
        conn.execute('UPDATE players SET name = ? WHERE id = ?', (new_name, player_id))
        
        # Opcional: Registrar alteração no histórico
        notes = f"Nome alterado de '{old_name}' para '{new_name}' em {datetime.now().strftime('%d/%m/%Y')}"
        
        # Se o jogador já tem notas, adicionar à frente
        if player['notes']:
            notes = f"{player['notes']} | {notes}"
        
        # Atualizar as notas
        conn.execute('UPDATE players SET notes = ? WHERE id = ?', (notes, player_id))
        
        conn.commit()
        flash(f'Nome atualizado com sucesso de "{old_name}" para "{new_name}".', 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao atualizar o nome: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('player_detail', player_id=player_id))

@app.route('/')
def index():
    conn = get_db_connection()
    # Modificado para mostrar apenas jogadores ativos
    players = conn.execute('SELECT * FROM players WHERE active = 1 ORDER BY position').fetchall()
    
    # Buscar jogadores inativos para mostrar em seção separada
    inactive_players = conn.execute('SELECT * FROM players WHERE active = 0 ORDER BY name').fetchall()
    
    conn.close()
    return render_template('index.html', players=players, inactive_players=inactive_players)

@app.route('/pyramid')
def pyramid_redirect():
    """Redireciona a rota antiga para a nova rota da pirâmide"""
    return redirect(url_for('pyramid_dynamic'))

@app.route('/pyramid_dynamic')
def pyramid_dynamic():
    conn = get_db_connection()
    
    # Buscar jogadores ativos
    players = conn.execute('SELECT * FROM players WHERE active = 1 ORDER BY position').fetchall()
    
    # Buscar jogadores com desafios
    challenges = conn.execute('''
        SELECT DISTINCT c.challenger_id, c.challenged_id, c.status, 
               p1.position as challenger_position, p2.position as challenged_position
        FROM challenges c
        JOIN players p1 ON c.challenger_id = p1.id
        JOIN players p2 ON c.challenged_id = p2.id
        WHERE c.status IN ('pending', 'accepted', 'completed_pending')
    ''').fetchall()
    
    # Converter listas para conjuntos para busca eficiente
    players_with_challenges = set()
    players_with_completed_pending = {}
    
    # Mapear desafios por jogador
    player_challenges = {}
    for player in players:
        player_id = player['id']
        player_challenges[player_id] = {
            'challenging_positions': [],
            'challenged_by_positions': []
        }
    
    # Processar desafios
    for challenge in challenges:
        challenger_id = challenge['challenger_id']
        challenged_id = challenge['challenged_id']
        
        # Marcar jogadores envolvidos em desafios
        if challenge['status'] == 'completed_pending':
            players_with_completed_pending[challenger_id] = 'completed_pending'
            players_with_completed_pending[challenged_id] = 'completed_pending'
        else:
            players_with_challenges.add(challenger_id)
            players_with_challenges.add(challenged_id)
        
        # Registrar posições envolvidas nos desafios
        if challenger_id in player_challenges:
            player_challenges[challenger_id]['challenging_positions'].append(challenge['challenged_position'])
        if challenged_id in player_challenges:
            player_challenges[challenged_id]['challenged_by_positions'].append(challenge['challenger_position'])
    
    # Organizar jogadores por tier
    tiers = {}
    for player in players:
        if player['tier'] not in tiers:
            tiers[player['tier']] = []
        
        # Adicionar informações sobre desafios
        player_dict = dict(player)
        player_dict['has_pending_challenge'] = player['id'] in players_with_challenges
        player_dict['challenge_status'] = players_with_completed_pending.get(player['id'], None)
        
        # Adicionar informações sobre as posições envolvidas nos desafios
        player_dict['challenging_positions'] = player_challenges[player['id']]['challenging_positions']
        player_dict['challenged_by_positions'] = player_challenges[player['id']]['challenged_by_positions']
        
        tiers[player['tier']].append(player_dict)
    
    # Ordenar tiers alfabeticamente
    sorted_tiers = sorted(tiers.items())
    
    conn.close()
    return render_template('pyramid_dynamic.html', tiers=sorted_tiers)

# Rota original (mantida para compatibilidade ou redirecionamento)
@app.route('/challenges')
def challenges():
    """Redireciona para a página de calendário de desafios (nova interface principal)"""
    return redirect(url_for('challenges_calendar'))

# Rota para o calendário de desafios
@app.route('/challenges/calendar')
def challenges_calendar():
    conn = get_db_connection()
    # Obter todos os desafios com nomes dos jogadores
    challenges = conn.execute('''
        SELECT c.*, 
               p1.name as challenger_name, p1.id as challenger_id,
               p2.name as challenged_name, p2.id as challenged_id,
               p1.position as challenger_position,
               p2.position as challenged_position,
               p1.tier as challenger_tier,
               p2.tier as challenged_tier
        FROM challenges c
        JOIN players p1 ON c.challenger_id = p1.id
        JOIN players p2 ON c.challenged_id = p2.id
        ORDER BY c.created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('calendar_challenges.html', challenges=challenges)

# Rota para a lista de desafios
@app.route('/challenges/list')
def challenges_list():
    conn = get_db_connection()
    
    # Preparar a consulta base
    query = '''
        SELECT c.*, 
               p1.name as challenger_name, p1.id as challenger_id,
               p2.name as challenged_name, p2.id as challenged_id,
               p1.position as challenger_position,
               p2.position as challenged_position,
               p1.tier as challenger_tier,
               p2.tier as challenged_tier
        FROM challenges c
        JOIN players p1 ON c.challenger_id = p1.id
        JOIN players p2 ON c.challenged_id = p2.id
    '''
    
    # Parâmetros para filtros
    params = []
    where_clauses = []
    
    # Aplicar filtros se fornecidos
    status = request.args.get('status')
    if status:
        where_clauses.append('c.status = ?')
        params.append(status)
    
    player = request.args.get('player')
    if player:
        where_clauses.append('(p1.name LIKE ? OR p2.name LIKE ?)')
        params.append(f'%{player}%')
        params.append(f'%{player}%')
    
    date_from = request.args.get('date_from')
    if date_from:
        where_clauses.append('c.scheduled_date >= ?')
        params.append(date_from)
    
    date_to = request.args.get('date_to')
    if date_to:
        where_clauses.append('c.scheduled_date <= ?')
        params.append(date_to)
    
    # Adicionar cláusulas WHERE se houver filtros
    if where_clauses:
        query += ' WHERE ' + ' AND '.join(where_clauses)
    
    # Adicionar ordenação
    query += ' ORDER BY c.created_at DESC'
    
    # Executar a consulta
    challenges = conn.execute(query, params).fetchall()
    conn.close()
    
    return render_template('challenges_list.html', challenges=challenges)

@app.route('/new_challenge', methods=['GET', 'POST'])
def new_challenge():
    if request.method == 'POST':
        challenger_id = request.form['challenger_id']
        challenged_id = request.form['challenged_id']
        scheduled_date = request.form['scheduled_date']
        
        conn = get_db_connection()
        
        # Verificar se o desafio é válido conforme as regras
        # Verificar se ambos jogadores estão ativos
        challenger = conn.execute('SELECT * FROM players WHERE id = ? AND active = 1', (challenger_id,)).fetchone()
        challenged = conn.execute('SELECT * FROM players WHERE id = ? AND active = 1', (challenged_id,)).fetchone()
        
        if not challenger or not challenged:
            conn.close()
            flash('Um dos jogadores está inativo e não pode participar de desafios.', 'error')
            return redirect(url_for('new_challenge'))
        
        # NOVA REGRA: Verificar se algum dos jogadores já tem desafios pendentes ou aceitos
        pending_challenges = conn.execute('''
            SELECT * FROM challenges 
            WHERE (challenger_id = ? OR challenged_id = ? OR challenger_id = ? OR challenged_id = ?)
            AND status IN ('pending', 'accepted')
        ''', (challenger_id, challenger_id, challenged_id, challenged_id)).fetchall()
        
        error = None
        
        # Se encontrou desafios pendentes ou aceitos
        if pending_challenges:
            # Verificar se o desafio pendente é entre estes mesmos jogadores
            same_players_challenge = False
            for challenge in pending_challenges:
                if ((challenge['challenger_id'] == int(challenger_id) and challenge['challenged_id'] == int(challenged_id)) or
                    (challenge['challenger_id'] == int(challenged_id) and challenge['challenged_id'] == int(challenger_id))):
                    same_players_challenge = True
                    break
            
            if same_players_challenge:
                error = "Já existe um desafio pendente ou aceito entre estes jogadores."
            else:
                error = "Um dos jogadores já está envolvido em um desafio pendente ou aceito. Conclua o desafio atual antes de criar um novo."
        
        # Regras existentes
        if not error:
            # Regra: Desafio apenas uma linha acima
            challenger_tier = challenger['tier']
            challenged_tier = challenged['tier']
            
            # Calcular a diferença de níveis (em termos de "distância alfabética")
            tier_difference = ord(challenger_tier) - ord(challenged_tier)
            
            # Se o tier_difference é negativo, o desafiado está abaixo do desafiante (erro)
            if tier_difference < 0:
                error = "Você só pode desafiar jogadores de níveis acima do seu."
            # Se o tier_difference > 1, o desafiado está mais que uma linha acima (erro)
            elif tier_difference > 1:
                error = "Você só pode desafiar jogadores até uma linha acima da sua."
            # Verificar se o desafiado tem posição melhor (menor numericamente)
            elif challenged['position'] > challenger['position']:
                error = "Você só pode desafiar jogadores em posições melhores que a sua."
        
        if error:
            conn.close()
            flash(error, 'error')
            return redirect(url_for('new_challenge'))
        
        # Inserir o novo desafio
        conn.execute('''
            INSERT INTO challenges (challenger_id, challenged_id, status, scheduled_date)
            VALUES (?, ?, ?, ?)
        ''', (challenger_id, challenged_id, 'pending', scheduled_date))
        
        conn.commit()
        conn.close()
        
        flash('Desafio criado com sucesso!', 'success')
        return redirect(url_for('challenges_calendar'))
        
    # Para requisições GET, mostrar formulário
    conn = get_db_connection()
    
    # Verificar se há um challenger_id na query string
    preselected_challenger_id = request.args.get('challenger_id', None)
    
    # Se temos um desafiante pré-selecionado, obter apenas os jogadores que podem ser desafiados
    if preselected_challenger_id:
        # Buscar informações do desafiante
        challenger = conn.execute('SELECT * FROM players WHERE id = ? AND active = 1', (preselected_challenger_id,)).fetchone()
        
        if challenger:
            # Buscar todos os jogadores para a lista de desafiantes
            all_players = conn.execute('SELECT * FROM players WHERE active = 1 ORDER BY position').fetchall()
            
            # Buscar apenas jogadores que podem ser desafiados (mesmo nível ou um nível acima)
            # e que tenham posição melhor que o desafiante
            eligible_challenged = conn.execute('''
                SELECT * FROM players 
                WHERE active = 1
                AND position < ? 
                AND (tier = ? OR tier = ?)
                ORDER BY position
            ''', (challenger['position'], challenger['tier'], chr(ord(challenger['tier'])-1))).fetchall()
            
            conn.close()
            return render_template('new_challenge.html', 
                                all_players=all_players,
                                eligible_challenged=eligible_challenged,
                                preselected_challenger=preselected_challenger_id,
                                challenger_info=challenger)
    
    # Se não houver um desafiante pré-selecionado ou o desafiante não for encontrado,
    # mostrar todos os jogadores (comportamento padrão)
    players = conn.execute('SELECT * FROM players WHERE active = 1 ORDER BY position').fetchall()
    conn.close()
    
    return render_template('new_challenge.html', 
                         all_players=players, 
                         eligible_challenged=[],
                         preselected_challenger=preselected_challenger_id)

# Alteração na rota delete_challenge
@app.route('/delete_challenge/<int:challenge_id>', methods=['POST'])
def delete_challenge(challenge_id):
    conn = get_db_connection()
    
    # Verificar se o desafio existe
    challenge = conn.execute('SELECT * FROM challenges WHERE id = ?', (challenge_id,)).fetchone()
    
    if not challenge:
        conn.close()
        flash('Desafio não encontrado!', 'error')
        return redirect(url_for('challenges_calendar'))
    
    # Verificar se o desafio está concluído (normal ou com pendência)
    if challenge['status'] == 'completed' or challenge['status'] == 'completed_pending':
        # Verificar se a senha foi fornecida e está correta
        senha = request.form.get('senha', '')
        if senha != '123':
            conn.close()
            flash('Senha incorreta! Desafios concluídos só podem ser excluídos com a senha correta.', 'error')
            return redirect(url_for('challenge_detail', challenge_id=challenge_id))
    
    # Verificar se o desafio já afetou o ranking (apenas para status 'completed', não 'completed_pending')
    if challenge['status'] == 'completed' and challenge['result']:
        # Buscar histórico relacionado a este desafio
        history = conn.execute('SELECT * FROM ranking_history WHERE challenge_id = ?', (challenge_id,)).fetchall()
        
        if history:
            # Agora permitimos excluir, mas primeiro revertemos as alterações do ranking
            try:
                revert_challenge_result(conn, challenge_id)
                flash('Alterações no ranking foram revertidas.', 'info')
            except Exception as e:
                conn.rollback()
                conn.close()
                flash(f'Erro ao reverter alterações no ranking: {str(e)}', 'error')
                return redirect(url_for('challenge_detail', challenge_id=challenge_id))
    
    # Excluir o desafio
    conn.execute('DELETE FROM challenges WHERE id = ?', (challenge_id,))
    conn.commit()
    conn.close()
    
    flash('Desafio excluído com sucesso!', 'success')
    return redirect(url_for('challenges_calendar'))

# Alteração na rota edit_challenge
@app.route('/edit_challenge/<int:challenge_id>', methods=['GET', 'POST'])
def edit_challenge(challenge_id):
    conn = get_db_connection()
    
    # Obter o desafio
    challenge = conn.execute('''
        SELECT c.*, 
               p1.name as challenger_name, p1.position as challenger_position,
               p2.name as challenged_name, p2.position as challenged_position
        FROM challenges c
        JOIN players p1 ON c.challenger_id = p1.id
        JOIN players p2 ON c.challenged_id = p2.id
        WHERE c.id = ?
    ''', (challenge_id,)).fetchone()
    
    if not challenge:
        conn.close()
        flash('Desafio não encontrado!', 'error')
        return redirect(url_for('challenges_calendar'))
    
    # Verificar se o desafio já afetou o ranking
    ranking_affected = False
    if challenge['status'] == 'completed' and challenge['result']:
        # Buscar histórico relacionado a este desafio
        history = conn.execute('SELECT * FROM ranking_history WHERE challenge_id = ?', (challenge_id,)).fetchone()
        if history:
            ranking_affected = True
    
    if request.method == 'POST':
        # Se o desafio está concluído (normal ou com pendência), verificar a senha
        if challenge['status'] == 'completed' or challenge['status'] == 'completed_pending':
            senha = request.form.get('senha', '')
            if senha != '123':
                conn.close()
                flash('Senha incorreta! Desafios concluídos só podem ser editados com a senha correta.', 'error')
                return redirect(url_for('challenge_detail', challenge_id=challenge_id))
        
        scheduled_date = request.form['scheduled_date']
        status = request.form.get('status', challenge['status'])
        result = request.form.get('result', challenge['result'])
        
        # Se estamos alterando um desafio que já afetou o ranking
        if ranking_affected and (status != 'completed' or result != challenge['result']):
            try:
                # Reverter as alterações no ranking
                revert_challenge_result(conn, challenge_id)
                flash('Alterações no ranking foram revertidas.', 'info')
                
                # Se o novo status for completed, processar o novo resultado
                if status == 'completed' and result:
                    process_challenge_result(conn, challenge_id, status, result)
                    flash('Ranking atualizado com o novo resultado.', 'success')
                # Se o novo status for completed_pending, processar sem alterar o ranking
                elif status == 'completed_pending' and result:
                    process_challenge_result(conn, challenge_id, status, result)
                    flash('Desafio marcado como Concluído (com pendência). O ranking não foi alterado.', 'success')
                else:
                    # Apenas atualizar o status e resultado
                    conn.execute('UPDATE challenges SET status = ?, result = ? WHERE id = ?', 
                               (status, result, challenge_id))
                    conn.commit()
            except Exception as e:
                conn.rollback()
                flash(f'Erro ao reverter alterações: {str(e)}', 'error')
                conn.close()
                return redirect(url_for('challenge_detail', challenge_id=challenge_id))
        else:
            # Atualizar o desafio normalmente
            conn.execute('''
                UPDATE challenges 
                SET scheduled_date = ?, status = ?, result = ?
                WHERE id = ?
            ''', (scheduled_date, status, result, challenge_id))
            conn.commit()
        
        conn.close()
        flash('Desafio atualizado com sucesso!', 'success')
        return redirect(url_for('challenge_detail', challenge_id=challenge_id))
    
    conn.close()
    return render_template('edit_challenge.html', challenge=challenge, ranking_affected=ranking_affected)

# Alteração na rota update_challenge (opcional, caso a atualização de status também deva ter restrição)
# Modificação na rota update_challenge
@app.route('/update_challenge/<int:challenge_id>', methods=['POST'])
def update_challenge(challenge_id):
    status = request.form['status']
    result = request.form.get('result', None)
    senha = request.form.get('senha', '')
    
    conn = get_db_connection()
    
    # Verificar se o desafio existe
    challenge = conn.execute('SELECT * FROM challenges WHERE id = ?', (challenge_id,)).fetchone()
    
    if not challenge:
        conn.close()
        flash('Desafio não encontrado!', 'error')
        return redirect(url_for('challenges_calendar'))
    
    # Se o desafio está concluído e estamos modificando-o, verificar a senha
    if challenge and (challenge['status'] == 'completed' or challenge['status'] == 'completed_pending'):
        if senha != '123':
            conn.close()
            flash('Senha incorreta! Desafios concluídos só podem ser modificados com a senha correta.', 'error')
            return redirect(url_for('challenge_detail', challenge_id=challenge_id))
    
    # Para qualquer mudança de status para 'completed' ou 'completed_pending', também requer senha
    if (status == 'completed' or status == 'completed_pending') and challenge['status'] != 'completed' and challenge['status'] != 'completed_pending':
        if senha != '123':
            conn.close()
            flash('Senha incorreta! Para marcar um desafio como concluído, é necessário informar a senha.', 'error')
            return redirect(url_for('challenge_detail', challenge_id=challenge_id))
    
    # Processar o desafio conforme o status
    if status == 'completed' and result:
        # Processar o resultado do desafio (alterando a pirâmide)
        process_challenge_result(conn, challenge_id, status, result)
        flash('Status do desafio atualizado para Concluído e ranking atualizado.', 'success')
    elif status == 'completed_pending' and result:
        # Processar como concluído com pendência (sem alterar a pirâmide)
        process_challenge_result(conn, challenge_id, status, result)
        flash('Status do desafio atualizado para Concluído (com pendência). O ranking não foi alterado.', 'success')
    else:
        # Apenas atualizar o status
        conn.execute('UPDATE challenges SET status = ? WHERE id = ?', (status, challenge_id))
        conn.commit()
        flash('Status do desafio atualizado com sucesso!', 'success')
    
    conn.close()
    
    return redirect(url_for('challenge_detail', challenge_id=challenge_id))

@app.route('/history')
def history():
    conn = get_db_connection()
    history = conn.execute('''
        SELECT rh.*, p.name as player_name
        FROM ranking_history rh
        JOIN players p ON rh.player_id = p.id
        ORDER BY rh.change_date DESC
    ''').fetchall()
    conn.close()
    return render_template('history.html', history=history)

@app.route('/player/<int:player_id>')
def player_detail(player_id):
    conn = get_db_connection()
    player = conn.execute('SELECT * FROM players WHERE id = ?', (player_id,)).fetchone()
    
    if not player:
        conn.close()
        flash('Jogador não encontrado!', 'error')
        return redirect(url_for('index'))
    
    # Garanta que a posição seja um inteiro válido
    player_position = player['position'] if player['position'] is not None else 0
    player_tier = player['tier'] if player['tier'] is not None else 'Z'
    
    # Buscar desafios do jogador
    challenges_as_challenger = conn.execute('''
        SELECT c.*, p.name as opponent_name, p.position as opponent_position
        FROM challenges c
        JOIN players p ON c.challenged_id = p.id
        WHERE c.challenger_id = ?
        ORDER BY c.created_at DESC
    ''', (player_id,)).fetchall()
    
    challenges_as_challenged = conn.execute('''
        SELECT c.*, p.name as opponent_name, p.position as opponent_position
        FROM challenges c
        JOIN players p ON c.challenger_id = p.id
        WHERE c.challenged_id = ?
        ORDER BY c.created_at DESC
    ''', (player_id,)).fetchall()
    
    # Buscar histórico de ranking
    history = conn.execute('''
        SELECT rh.*, c.id as challenge_id
        FROM ranking_history rh
        LEFT JOIN challenges c ON rh.challenge_id = c.id
        WHERE rh.player_id = ?
        ORDER BY rh.change_date DESC
    ''', (player_id,)).fetchall()
    
    # Buscar possíveis jogadores para desafiar (apenas se o jogador estiver ativo)
    potential_challenges = []
    if player['active'] == 1 and player_position > 0:  # Verificar se a posição é válida
        try:
            # Calcular o tier anterior (um nível acima)
            prev_tier = chr(ord(player_tier) - 1) if ord(player_tier) > ord('A') else player_tier
            
            potential_challenges = conn.execute('''
                SELECT p.*
                FROM players p
                WHERE p.position < ? 
                  AND (p.tier = ? OR p.tier = ?)
                  AND p.active = 1
                ORDER BY p.position DESC
            ''', (player_position, player_tier, prev_tier)).fetchall()
        except Exception as e:
            print(f"Erro ao buscar desafios potenciais: {str(e)}")
    
    conn.close()
    
    return render_template('player_detail.html', 
                         player=player, 
                         challenges_as_challenger=challenges_as_challenger,
                         challenges_as_challenged=challenges_as_challenged,
                         history=history,
                         potential_challenges=potential_challenges)

@app.route('/challenge_detail/<int:challenge_id>')
def challenge_detail(challenge_id):
    conn = get_db_connection()
    challenge = conn.execute('''
        SELECT c.*, 
               p1.name as challenger_name, p1.id as challenger_id, p1.position as challenger_position, p1.hcp_index as challenger_hcp,
               p2.name as challenged_name, p2.id as challenged_id, p2.position as challenged_position, p2.hcp_index as challenged_hcp
        FROM challenges c
        JOIN players p1 ON c.challenger_id = p1.id
        JOIN players p2 ON c.challenged_id = p2.id
        WHERE c.id = ?
    ''', (challenge_id,)).fetchone()
    conn.close()
    
    if not challenge:
        flash('Desafio não encontrado!', 'error')
        return redirect(url_for('challenges_calendar'))
        
    return render_template('challenge_detail.html', challenge=challenge)

# Rota aprimorada para verificar e corrigir completamente a estrutura da pirâmide
@app.route('/fix_pyramid', methods=['GET'])
def fix_pyramid():
    conn = get_db_connection()
    
    try:
        # Passo 1: Corrigir qualquer lacuna nas posições
        players_before = conn.execute('SELECT id, position FROM players WHERE active = 1 ORDER BY position').fetchall()
        fix_position_gaps(conn)
        
        # Passo 2: Verificar se há jogadores com tiers incorretos
        incorrect_players = verify_pyramid_structure(conn)
        
        # Passo 3: Atualizar todos os tiers para corrigir a estrutura
        if incorrect_players:
            update_all_tiers(conn)
            
        # Verificação final
        players_after = conn.execute('SELECT id, position FROM players WHERE active = 1 ORDER BY position').fetchall()
        final_check = verify_pyramid_structure(conn)
        
        # Calcular quantas posições foram corrigidas
        positions_fixed = sum(1 for a, b in zip(players_before, players_after) 
                             if a['position'] != b['position'])
        
        if positions_fixed > 0 or incorrect_players:
            flash(f'Estrutura da pirâmide corrigida: {positions_fixed} posições e {len(incorrect_players)} tiers atualizados.', 'success')
        else:
            flash('A estrutura da pirâmide já está correta!', 'info')
        
        # Se ainda houver problemas, alertar
        if final_check:
            flash(f'Atenção: Ainda há {len(final_check)} tiers que podem estar incorretos.', 'warning')
        
        conn.commit()
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao corrigir a pirâmide: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('pyramid_dynamic'))

# Função para verificação da integridade da pirâmide (sem o scheduler)
def check_pyramid_integrity():
    """
    Executa uma verificação manual da integridade da pirâmide.
    Pode ser chamada a partir de rotas específicas quando necessário.
    """
    print("Executando verificação manual da integridade da pirâmide...")
    conn = get_db_connection()
    try:
        # Verificar lacunas nas posições
        players = conn.execute('SELECT id, position FROM players WHERE active = 1 AND position IS NOT NULL ORDER BY position').fetchall()
        expected_position = 1
        positions_fixed = 0
        
        for player in players:
            if player['position'] != expected_position:
                conn.execute('UPDATE players SET position = ? WHERE id = ?', 
                           (expected_position, player['id']))
                positions_fixed += 1
            expected_position += 1
        
        # Verificar tiers incorretos
        incorrect_players = verify_pyramid_structure(conn)
        
        if incorrect_players or positions_fixed > 0:
            # Corrigir tiers se necessário
            update_all_tiers(conn)
            print(f"Correção: {positions_fixed} posições e {len(incorrect_players)} tiers ajustados.")
            conn.commit()
        else:
            print("Verificação: Estrutura da pirâmide está correta.")
    
    except Exception as e:
        print(f"Erro na verificação da pirâmide: {e}")
        conn.rollback()
    finally:
        conn.close()

# Rota adicional para verificação manual da integridade da pirâmide
@app.route('/check_pyramid')
def check_pyramid_route():
    """Rota para executar a verificação da pirâmide sob demanda."""
    check_pyramid_integrity()
    flash('Verificação da integridade da pirâmide concluída.', 'info')
    return redirect(url_for('pyramid_dynamic'))

# Rota para verificar o status de um jogador (útil para diagnóstico)
@app.route('/check_player/<int:player_id>')
def check_player(player_id):
    conn = get_db_connection()
    player = conn.execute('SELECT * FROM players WHERE id = ?', (player_id,)).fetchone()
    conn.close()
    
    if not player:
        return f"Jogador ID {player_id} não encontrado"
    
    return f"Jogador: {player['name']}, Active: {player['active']}, Position: {player['position']}, Notes: {player['notes']}"

# Rota para adicionar colunas (útil para atualização do banco de dados)
@app.route('/add_columns')
def add_columns():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar se as colunas existem
    columns_info = cursor.execute('PRAGMA table_info(players)').fetchall()
    column_names = [col[1] for col in columns_info]
    
    changes = []
    
    if 'active' not in column_names:
        cursor.execute('ALTER TABLE players ADD COLUMN active INTEGER DEFAULT 1')
        changes.append("Coluna 'active' adicionada")
    
    if 'notes' not in column_names:
        cursor.execute('ALTER TABLE players ADD COLUMN notes TEXT')
        changes.append("Coluna 'notes' adicionada")
    
    conn.commit()
    conn.close()
    
    if changes:
        return f"Alterações realizadas: {', '.join(changes)}"
    else:
        return "Nenhuma alteração necessária."

@app.route('/add_player', methods=['GET', 'POST'])
def add_player():
    """
    Adiciona um novo jogador ao sistema, colocando-o na última posição do ranking.
    GET: Mostra formulário para adicionar jogador
    POST: Processa a adição do jogador
    """
    if request.method == 'POST':
        # Obter dados do formulário
        name = request.form.get('name', '').strip()
        hcp_index = request.form.get('hcp_index', '').strip()  # Garante que não seja None
        email = request.form.get('email', '').strip()
        notes = request.form.get('notes', '').strip()
        senha = request.form.get('senha', '')
        
        # Validar campos obrigatórios
        if not name:
            flash('Nome é obrigatório!', 'error')
            return redirect(url_for('add_player'))
        
        # Validar senha
        if senha != '123':
            flash('Senha incorreta! Operação não autorizada.', 'error')
            return redirect(url_for('add_player'))
        
        conn = get_db_connection()
        try:
            # Verificar se o jogador já existe
            existing_player = conn.execute('SELECT * FROM players WHERE name = ?', (name,)).fetchone()
            if existing_player:
                if existing_player['active'] == 0:
                    # Se o jogador existe mas está inativo, sugerir reativação
                    flash(f'Jogador "{name}" já existe mas está inativo. Considere reativá-lo na página de detalhes.', 'warning')
                    conn.close()
                    return redirect(url_for('player_detail', player_id=existing_player['id']))
                else:
                    # Se o jogador já existe e está ativo, informar erro
                    flash(f'Jogador "{name}" já existe no sistema!', 'error')
                    conn.close()
                    return redirect(url_for('add_player'))
            
            # Determinar a última posição do ranking
            last_pos_result = conn.execute('SELECT MAX(position) as max_pos FROM players WHERE active = 1').fetchone()
            last_pos = last_pos_result['max_pos'] if last_pos_result and last_pos_result['max_pos'] is not None else 0
            new_position = last_pos + 1
            
            # Garantir que a posição seja um inteiro válido
            if not isinstance(new_position, int) or new_position <= 0:
                new_position = 1
            
            # Determinar o tier com base na posição
            new_tier = get_tier_from_position(new_position)
            
            # Converter hcp_index para float se fornecido, ou None se vazio
            hcp_index_val = None
            if hcp_index:
                try:
                    hcp_index_val = float(hcp_index.replace(',', '.'))
                except ValueError:
                    # Se não for um número válido, deixar como None
                    pass
            
            # Verificar quais colunas existem na tabela
            columns_info = conn.execute('PRAGMA table_info(players)').fetchall()
            column_names = [col[1] for col in columns_info]
            
            # Construir a query dinamicamente com base nas colunas existentes
            columns = ['name', 'active', 'position', 'tier']
            values = [name, 1, new_position, new_tier]
            
            if 'hcp_index' in column_names:
                columns.append('hcp_index')
                values.append(hcp_index_val)
            
            if 'email' in column_names and email:
                columns.append('email')
                values.append(email)
            
            if 'notes' in column_names and notes:
                columns.append('notes')
                values.append(notes)
            
            # Construir a string SQL
            columns_str = ', '.join(columns)
            placeholders = ', '.join(['?'] * len(values))
            
            # Inserir o novo jogador
            cursor = conn.execute(f'''
                INSERT INTO players ({columns_str})
                VALUES ({placeholders})
            ''', values)
            
            player_id = cursor.lastrowid
            
            # Registrar no histórico - Usando 0 em vez de None para old_position e old_tier
            conn.execute('''
                INSERT INTO ranking_history 
                (player_id, old_position, new_position, old_tier, new_tier, reason)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (player_id, 0, new_position, "NEW", new_tier, 'player_added'))
            
            conn.commit()
            flash(f'Jogador "{name}" adicionado com sucesso na posição {new_position} (Tier {new_tier})!', 'success')
            return redirect(url_for('player_detail', player_id=player_id))
            
        except Exception as e:
            conn.rollback()
            flash(f'Erro ao adicionar jogador: {str(e)}', 'error')
        finally:
            conn.close()
        
        return redirect(url_for('index'))
    
    # Para requisição GET, mostrar formulário
    return render_template('add_player.html')


@app.route('/update_player_contact/<int:player_id>', methods=['POST'])
def update_player_contact(player_id):
    """
    Atualiza o contato (email/telefone) de um jogador
    """
    conn = get_db_connection()
    
    # Verificar se o jogador existe
    player = conn.execute('SELECT * FROM players WHERE id = ?', (player_id,)).fetchone()
    
    if not player:
        conn.close()
        flash('Jogador não encontrado!', 'error')
        return redirect(url_for('index'))
    
    # Verificar senha
    senha = request.form.get('senha', '')
    if senha != '123':
        conn.close()
        flash('Senha incorreta! Operação não autorizada.', 'error')
        return redirect(url_for('player_detail', player_id=player_id))
    
    # Obter novo contato
    new_contact = request.form.get('new_contact', '').strip()
    old_contact = player['email']
    
    # Se o contato não mudou, não fazer nada
    if new_contact == old_contact:
        conn.close()
        flash('Nenhuma alteração foi realizada.', 'info')
        return redirect(url_for('player_detail', player_id=player_id))
    
    try:
        # Atualizar o contato do jogador
        conn.execute('UPDATE players SET email = ? WHERE id = ?', (new_contact, player_id))
        
        # Opcional: Registrar alteração nas notas
        notes = f"Contato alterado de '{old_contact or 'não informado'}' para '{new_contact or 'não informado'}' em {datetime.now().strftime('%d/%m/%Y')}"
        
        # Se o jogador já tem notas, adicionar à frente
        if player['notes']:
            notes = f"{player['notes']} | {notes}"
        
        # Atualizar as notas
        conn.execute('UPDATE players SET notes = ? WHERE id = ?', (notes, player_id))
        
        conn.commit()
        flash(f'Contato atualizado com sucesso.', 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao atualizar o contato: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('player_detail', player_id=player_id))

@app.route('/update_player_hcp/<int:player_id>', methods=['POST'])
def update_player_hcp(player_id):
    """
    Atualiza o HCP Index de um jogador e calcula automaticamente o HCP para diferentes tees
    """
    conn = get_db_connection()
    
    # Verificar se o jogador existe
    player = conn.execute('SELECT * FROM players WHERE id = ?', (player_id,)).fetchone()
    
    if not player:
        conn.close()
        flash('Jogador não encontrado!', 'error')
        return redirect(url_for('index'))
    
    # Verificar senha
    senha = request.form.get('senha', '')
    if senha != '123':
        conn.close()
        flash('Senha incorreta! Operação não autorizada.', 'error')
        return redirect(url_for('player_detail', player_id=player_id))
    
    # Obter novo HCP
    new_hcp = request.form.get('new_hcp', '').strip()
    old_hcp = str(player['hcp_index']) if player['hcp_index'] is not None else ''
    
    # Se o HCP não mudou, não fazer nada
    if new_hcp == old_hcp:
        conn.close()
        flash('Nenhuma alteração foi realizada.', 'info')
        return redirect(url_for('player_detail', player_id=player_id))
    
    try:
        # Converter o novo HCP para float se não estiver vazio
        hcp_value = None
        if new_hcp:
            try:
                hcp_value = float(new_hcp.replace(',', '.'))
            except ValueError:
                conn.close()
                flash('Valor de HCP inválido. Use apenas números.', 'error')
                return redirect(url_for('player_detail', player_id=player_id))
        
        # Atualizar o HCP do jogador
        conn.execute('UPDATE players SET hcp_index = ? WHERE id = ?', (hcp_value, player_id))
        
        # Calcular e atualizar o HCP OGC Tee Branco se o HCP Index foi fornecido
        if hcp_value is not None:
            # Função para determinar o HCP OGC Tee Branco com base no HCP Index
            def get_hcp_ogc_white(hcp):
                # Para handicaps "plus" (valores negativos no banco)
                if hcp <= -0.3:
                    if -5.0 <= hcp <= -4.8: return '+7'
                    elif -4.7 <= hcp <= -3.9: return '+6'
                    elif -3.8 <= hcp <= -3.1: return '+5'
                    elif -3.0 <= hcp <= -2.2: return '+4'
                    elif -2.1 <= hcp <= -1.3: return '+3'
                    elif -1.2 <= hcp <= -0.4: return '+2'
                    elif -0.3 <= hcp <= 0.5: return '+1'
                
                # Para handicaps regulares (valores positivos no banco)
                if 0.6 <= hcp <= 1.4: return '0'
                elif 1.5 <= hcp <= 2.2: return '1'
                elif 2.3 <= hcp <= 3.1: return '2'
                elif 3.2 <= hcp <= 4.0: return '3'
                elif 4.1 <= hcp <= 4.9: return '4'
                elif 5.0 <= hcp <= 5.8: return '5'
                elif 5.9 <= hcp <= 6.7: return '6'
                elif 6.8 <= hcp <= 7.5: return '7'
                elif 7.6 <= hcp <= 8.4: return '8'
                elif 8.5 <= hcp <= 9.3: return '9'
                elif 9.4 <= hcp <= 10.2: return '10'
                elif 10.3 <= hcp <= 11.1: return '11'
                elif 11.2 <= hcp <= 12.0: return '12'
                elif 12.1 <= hcp <= 12.8: return '13'
                elif 12.9 <= hcp <= 13.7: return '14'
                elif 13.8 <= hcp <= 14.6: return '15'
                elif 14.7 <= hcp <= 15.5: return '16'
                elif 15.6 <= hcp <= 16.4: return '17'
                elif 16.5 <= hcp <= 17.3: return '18'
                elif 17.4 <= hcp <= 18.1: return '19'
                elif 18.2 <= hcp <= 19.0: return '20'
                elif 19.1 <= hcp <= 19.9: return '21'
                elif 20.0 <= hcp <= 20.8: return '22'
                elif 20.9 <= hcp <= 21.7: return '23'
                elif 21.8 <= hcp <= 22.5: return '24'
                elif 22.6 <= hcp <= 23.4: return '25'
                elif 23.5 <= hcp <= 24.3: return '26'
                elif 24.4 <= hcp <= 25.2: return '27'
                elif 25.3 <= hcp <= 26.1: return '28'
                elif 26.2 <= hcp <= 27.0: return '29'
                elif 27.1 <= hcp <= 27.8: return '30'
                elif 27.9 <= hcp <= 28.7: return '31'
                elif 28.8 <= hcp <= 29.6: return '32'
                elif 29.7 <= hcp <= 30.5: return '33'
                elif 30.6 <= hcp <= 31.4: return '34'
                elif 31.5 <= hcp <= 32.3: return '35'
                elif 32.4 <= hcp <= 33.1: return '36'
                elif 33.2 <= hcp <= 34.0: return '37'
                elif 34.1 <= hcp <= 34.9: return '38'
                elif 35.0 <= hcp <= 35.8: return '39'
                elif 35.9 <= hcp <= 36.7: return '40'
                elif 36.8 <= hcp <= 37.6: return '41'
                elif 37.7 <= hcp <= 38.4: return '42'
                elif 38.5 <= hcp <= 39.3: return '43'
                elif 39.4 <= hcp <= 40.2: return '44'
                elif 40.3 <= hcp <= 41.1: return '45'
                elif 41.2 <= hcp <= 42.0: return '46'
                elif 42.1 <= hcp <= 42.9: return '47'
                elif 43.0 <= hcp <= 43.7: return '48'
                elif 43.8 <= hcp <= 44.6: return '49'
                elif 44.7 <= hcp <= 45.5: return '50'
                elif 45.6 <= hcp <= 46.4: return '51'
                elif 46.5 <= hcp <= 47.3: return '52'
                elif 47.4 <= hcp <= 48.2: return '53'
                elif 48.3 <= hcp <= 49.0: return '54'
                elif 49.1 <= hcp <= 49.9: return '55'
                elif 50.0 <= hcp <= 50.8: return '56'
                elif 50.9 <= hcp <= 51.7: return '57'
                elif 51.8 <= hcp <= 52.6: return '58'
                elif 52.7 <= hcp <= 53.4: return '59'
                elif hcp >= 53.5: return '60'
                
                # Caso não encontre correspondência
                return 'N/A'
            
            # Calcular o HCP OGC Tee Branco
            hcp_ogc_white = get_hcp_ogc_white(hcp_value)
            
            # Atualizar o HCP OGC Tee Branco
            conn.execute('UPDATE players SET hcp_ogc_white = ? WHERE id = ?', (hcp_ogc_white, player_id))
        else:
            # Se o HCP Index foi removido, remover também o HCP OGC Tee Branco
            conn.execute('UPDATE players SET hcp_ogc_white = NULL WHERE id = ?', (player_id,))
        
        # Calcular o HCP OGC Tee Azul
        if hcp_value is not None:
            # Fórmula: Handicap Index × (Slope Rating ÷ 113) + (Course Rating - Par)
            # Para o Tee Azul: Course Rating = 71.4, Slope Rating = 131, Par = 71
            if hcp_value < 0:  # Handicap "plus"
                # Adiciona um sinal '+' para handicaps plus
                hcp_ogc_azul = '+' + str(round(abs(hcp_value) * (131.0 / 113.0) + (71.4 - 71.0)))
            else:
                hcp_ogc_azul = str(round(hcp_value * (131.0 / 113.0) + (71.4 - 71.0)))
            
            # Atualizar o HCP OGC Tee Azul
            conn.execute('UPDATE players SET hcp_ogc_azul = ? WHERE id = ?', (hcp_ogc_azul, player_id))
        else:
            # Se o HCP Index foi removido, remover também o HCP OGC Tee Azul
            conn.execute('UPDATE players SET hcp_ogc_azul = NULL WHERE id = ?', (player_id,))
        
        # Calcular o HCP OGC Tee Preto
        if hcp_value is not None:
            # Fórmula: Handicap Index × (Slope Rating ÷ 113) + (Course Rating - Par)
            # Para o Tee Preto: Course Rating = 73.9, Slope Rating = 144, Par = 71
            if hcp_value < 0:  # Handicap "plus"
                # Adiciona um sinal '+' para handicaps plus
                hcp_ogc_preto = '+' + str(round(abs(hcp_value) * (144.0 / 113.0) + (73.9 - 71.0)))
            else:
                hcp_ogc_preto = str(round(hcp_value * (144.0 / 113.0) + (73.9 - 71.0)))
            
            # Atualizar o HCP OGC Tee Preto
            conn.execute('UPDATE players SET hcp_ogc_preto = ? WHERE id = ?', (hcp_ogc_preto, player_id))
        else:
            # Se o HCP Index foi removido, remover também o HCP OGC Tee Preto
            conn.execute('UPDATE players SET hcp_ogc_preto = NULL WHERE id = ?', (player_id,))
        
        # Calcular o HCP OGC Tee Vermelho
        if hcp_value is not None:
            # Fórmula: Handicap Index × (Slope Rating ÷ 113) + (Course Rating - Par)
            # Para o Tee Vermelho: Course Rating = 68.1, Slope Rating = 125, Par = 71
            if hcp_value < 0:  # Handicap "plus"
                # Adiciona um sinal '+' para handicaps plus
                hcp_ogc_vermelho = '+' + str(round(abs(hcp_value) * (125.0 / 113.0) + (68.1 - 71.0)))
            else:
                hcp_ogc_vermelho = str(round(hcp_value * (125.0 / 113.0) + (68.1 - 71.0)))
            
            # Atualizar o HCP OGC Tee Vermelho
            conn.execute('UPDATE players SET hcp_ogc_vermelho = ? WHERE id = ?', (hcp_ogc_vermelho, player_id))
        else:
            # Se o HCP Index foi removido, remover também o HCP OGC Tee Vermelho
            conn.execute('UPDATE players SET hcp_ogc_vermelho = NULL WHERE id = ?', (player_id,))
        
        # Calcular o HCP OGC Tee Amarelo
        if hcp_value is not None:
            # Fórmula: Handicap Index × (Slope Rating ÷ 113) + (Course Rating - Par)
            # Para o Tee Amarelo: Course Rating = 65.3, Slope Rating = 118, Par = 71
            if hcp_value < 0:  # Handicap "plus"
                # Adiciona um sinal '+' para handicaps plus
                hcp_ogc_amarelo = '+' + str(round(abs(hcp_value) * (118.0 / 113.0) + (65.3 - 71.0)))
            else:
                hcp_ogc_amarelo = str(round(hcp_value * (118.0 / 113.0) + (65.3 - 71.0)))
            
            # Atualizar o HCP OGC Tee Amarelo
            conn.execute('UPDATE players SET hcp_ogc_amarelo = ? WHERE id = ?', (hcp_ogc_amarelo, player_id))
        else:
            # Se o HCP Index foi removido, remover também o HCP OGC Tee Amarelo
            conn.execute('UPDATE players SET hcp_ogc_amarelo = NULL WHERE id = ?', (player_id,))
        
        # Opcional: Registrar alteração nas notas
        notes = f"HCP Index alterado de '{old_hcp or 'não informado'}' para '{new_hcp or 'não informado'}' em {datetime.now().strftime('%d/%m/%Y')}"
        
        # Se o jogador já tem notas, adicionar à frente
        if player['notes']:
            notes = f"{player['notes']} | {notes}"
        
        # Atualizar as notas
        conn.execute('UPDATE players SET notes = ? WHERE id = ?', (notes, player_id))
        
        conn.commit()
        flash(f'HCP Index atualizado com sucesso.', 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao atualizar o HCP: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('player_detail', player_id=player_id))


@app.route('/ranking_history')
def ranking_history():
    """Mostra o histórico de todas as posições em um gráfico"""
    conn = get_db_connection()
    
    # Verificar se foi fornecido um intervalo de datas personalizado
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Se intervalo personalizado não foi fornecido, usar período em dias
    if not (start_date and end_date):
        # Obter o período desejado (padrão: últimos 30 dias)
        days = request.args.get('days', 30, type=int)
        
        # Calcular a data limite
        limit_date = (datetime.now() - timedelta(days=days)).date()
        end_date = datetime.now().date().strftime('%Y-%m-%d')
    else:
        # Usar intervalo de datas personalizado
        limit_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        days = None  # Não usamos days quando temos start_date e end_date
    
    # Buscar as datas disponíveis no histórico
    dates = conn.execute('''
        SELECT DISTINCT date_recorded 
        FROM daily_ranking_history 
        WHERE date_recorded >= ?
        ORDER BY date_recorded
    ''', (limit_date.strftime('%Y-%m-%d'),)).fetchall()
    
    date_list = [d['date_recorded'] for d in dates]
    
    # Buscar os jogadores ativos
    players = conn.execute('''
        SELECT id, name, position 
        FROM players 
        WHERE active = 1 
        ORDER BY position
    ''').fetchall()
    
    # Criar uma lista combinada de players para o template
    players_list = [{'id': p['id'], 'name': p['name']} for p in players]
    
    conn.close()
    
    return render_template('ranking_history.html', 
                           days=days, 
                           dates=date_list,
                           players=players_list,
                           start_date=start_date,
                           end_date=end_date)


@app.route('/api/ranking_history_data')
def api_ranking_history_data():
    """API para obter os dados de histórico para o gráfico"""
    conn = get_db_connection()
    
    # Verificar se foi fornecido um intervalo de datas personalizado
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Se intervalo personalizado não foi fornecido, usar período em dias
    if not (start_date and end_date):
        # Obter os parâmetros
        days = request.args.get('days', 30, type=int)
        
        # Calcular a data limite
        limit_date = (datetime.now() - timedelta(days=days)).date()
        end_date = datetime.now().date().strftime('%Y-%m-%d')
    else:
        # Usar intervalo de datas personalizado
        limit_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date().strftime('%Y-%m-%d')
    
    # Converter limit_date para string no formato correto para SQL
    limit_date_str = limit_date.strftime('%Y-%m-%d')
    
    # Obter os IDs dos jogadores selecionados
    player_ids = request.args.getlist('player_ids[]', type=int)
    
    # Limitar o número de jogadores para performance
    if len(player_ids) > 30:
        player_ids = player_ids[:30]
    
    # Buscar as datas disponíveis no histórico
    date_query = '''
        SELECT DISTINCT date_recorded 
        FROM daily_ranking_history 
        WHERE date_recorded >= ? AND date_recorded <= ?
        ORDER BY date_recorded
    '''
    dates = conn.execute(date_query, (limit_date_str, end_date)).fetchall()
    
    date_list = [d['date_recorded'] for d in dates]
    
    # Preparar dados de cada jogador
    players_data = []
    
    for player_id in player_ids:
        # Buscar informações do jogador
        player = conn.execute('SELECT name FROM players WHERE id = ?', (player_id,)).fetchone()
        
        if not player:
            continue
        
        # Buscar histórico do jogador
        history_query = '''
            SELECT date_recorded, position 
            FROM daily_ranking_history 
            WHERE player_id = ? AND date_recorded >= ? AND date_recorded <= ?
            ORDER BY date_recorded
        '''
        history = conn.execute(history_query, (player_id, limit_date_str, end_date)).fetchall()
        
        # Criar um dicionário com as posições por data
        positions_by_date = {h['date_recorded']: h['position'] for h in history}
        
        # Montar a série temporal completa, mantendo a última posição conhecida para datas sem registro
        positions_series = []
        last_known_position = None
        
        for date in date_list:
            if date in positions_by_date:
                position = positions_by_date[date]
                last_known_position = position
            else:
                position = last_known_position
            
            if position is not None:
                positions_series.append(position)
            else:
                positions_series.append(None)  # Usar None para datas sem posição
        
        # Adicionar dados deste jogador
        players_data.append({
            'name': player['name'],
            'positions': positions_series
        })
    
    conn.close()
    
    return jsonify({
        'dates': date_list,
        'players': players_data
    })


@app.route('/sync_history', methods=['GET'])
def sync_history_route():
    """
    Sincroniza manualmente as tabelas de histórico para a data atual.
    """
    try:
        sync_ranking_history_tables()
        flash('Histórico sincronizado com sucesso!', 'success')
    except Exception as e:
        flash(f'Erro ao sincronizar histórico: {str(e)}', 'error')
    
    return redirect(url_for('ranking_history'))

# Atualização da parte relacionada à inicialização da aplicação

# Atualização da parte relacionada à inicialização da aplicação

if __name__ == '__main__':
    # Verificar se o banco de dados existe, caso contrário, importar dados
    if not os.path.exists(DATABASE):
        print("Banco de dados não encontrado. Executando script de importação...")
        import import_data
        import_data.create_database()
        import_data.import_players_data(import_data.cursor)
    
    # Verificar se as colunas active e notes existem na tabela players
    conn = get_db_connection()
    cursor = conn.cursor()
    
    columns_info = cursor.execute('PRAGMA table_info(players)').fetchall()
    column_names = [col[1] for col in columns_info]
    
    if 'active' not in column_names:
        print("Adicionando coluna 'active' à tabela players...")
        cursor.execute('ALTER TABLE players ADD COLUMN active INTEGER DEFAULT 1')
    
    if 'notes' not in column_names:
        print("Adicionando coluna 'notes' à tabela players...")
        cursor.execute('ALTER TABLE players ADD COLUMN notes TEXT')
    
    conn.commit()
    conn.close()
    
    # Criar a tabela de histórico diário se não existir
    create_daily_history_table()
    
    # Verificar e corrigir a estrutura da pirâmide
    print("Realizando verificação inicial da pirâmide...")
    conn = get_db_connection()
    fix_position_gaps(conn)
    update_all_tiers(conn)
    conn.commit()
    conn.close()
    
    # Sincronizar o histórico diário com o histórico de ranking
    print("Sincronizando histórico para o dia atual...")
    sync_ranking_history_tables()
    
    # Criar pasta de templates se não existir
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    # Criar pasta static se não existir
    if not os.path.exists('static'):
        os.makedirs('static')
    
    # Modificação: adicionado argumento host='0.0.0.0' para permitir acesso externo
    app.run(debug=True, host='0.0.0.0')