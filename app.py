from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import sqlite3
from datetime import datetime
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
    players = conn.execute('SELECT id, position FROM players ORDER BY position').fetchall()
    
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
    players = conn.execute('SELECT id, name, position, tier FROM players ORDER BY position').fetchall()
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
    players = conn.execute('SELECT id, position FROM players ORDER BY position').fetchall()
    
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
def process_challenge_result(conn, challenge_id, status, result):
    """
    Processa o resultado de um desafio, atualizando posições e tiers conforme necessário.
    Versão melhorada que garante a consistência da pirâmide.
    """
    # Atualizar o status e resultado do desafio
    conn.execute('UPDATE challenges SET status = ?, result = ? WHERE id = ?', 
                (status, result, challenge_id))
    
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

# Função para reverter os efeitos de um desafio no ranking
def revert_challenge_result(conn, challenge_id):
    """
    Reverte as alterações feitas por um desafio no ranking.
    Restaura as posições anteriores dos jogadores e remove os registros de histórico.
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
    
    conn.commit()
    print(f"Alterações do desafio ID {challenge_id} foram revertidas com sucesso.")

@app.route('/')
def index():
    conn = get_db_connection()
    # Obter todos os jogadores ordenados por posição
    players = conn.execute('SELECT * FROM players ORDER BY position').fetchall()
    conn.close()
    return render_template('index.html', players=players)

@app.route('/pyramid')
def pyramid_redirect():
    """Redireciona a rota antiga para a nova rota da pirâmide"""
    return redirect(url_for('pyramid_dynamic'))

@app.route('/pyramid_dynamic')
def pyramid_dynamic():
    conn = get_db_connection()
    players = conn.execute('SELECT * FROM players ORDER BY position').fetchall()
    conn.close()
    
    # Organizar jogadores por tier
    tiers = {}
    for player in players:
        if player['tier'] not in tiers:
            tiers[player['tier']] = []
        tiers[player['tier']].append(player)
    
    # Ordenar tiers alfabeticamente (A, B, C, ...)
    sorted_tiers = sorted(tiers.items())
    
    return render_template('pyramid_dynamic.html', tiers=sorted_tiers)

# Rota original (mantida para compatibilidade ou redirecionamento)
@app.route('/challenges')
def challenges():
    """Redireciona para a página de calendário de desafios (nova interface principal)"""
    return redirect(url_for('challenges_calendar'))

# Nova rota para o calendário de desafios
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

# Nova rota para a lista de desafios
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
        challenger = conn.execute('SELECT * FROM players WHERE id = ?', (challenger_id,)).fetchone()
        challenged = conn.execute('SELECT * FROM players WHERE id = ?', (challenged_id,)).fetchone()
        
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
            challenger_tier_value = ord(challenger['tier'])
            challenged_tier_value = ord(challenged['tier'])
            
            if challenged_tier_value > challenger_tier_value:
                error = "Você só pode desafiar jogadores de níveis acima do seu."
            elif challenger_tier_value - challenged_tier_value > 1:
                error = "Você só pode desafiar jogadores até uma linha acima da sua."
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
    players = conn.execute('SELECT * FROM players ORDER BY position').fetchall()
    
    # Verificar se há um challenger_id na query string
    preselected_challenger = request.args.get('challenger_id', None)
    
    conn.close()
    return render_template('new_challenge.html', players=players, preselected_challenger=preselected_challenger)

# Modifique estas funções no arquivo principal

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
    
    # Verificar se o desafio está concluído
    if challenge['status'] == 'completed':
        # Verificar se a senha foi fornecida e está correta
        senha = request.form.get('senha', '')
        if senha != '123':
            conn.close()
            flash('Senha incorreta! Desafios concluídos só podem ser excluídos com a senha correta.', 'error')
            return redirect(url_for('challenge_detail', challenge_id=challenge_id))
    
    # Verificar se o desafio já afetou o ranking
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
    
    # Verificar se o desafio já afetou o ranking (mantemos a verificação, mas adicionamos suporte para reverter)
    ranking_affected = False
    if challenge['status'] == 'completed' and challenge['result']:
        # Buscar histórico relacionado a este desafio
        history = conn.execute('SELECT * FROM ranking_history WHERE challenge_id = ?', (challenge_id,)).fetchone()
        if history:
            ranking_affected = True
    
    if request.method == 'POST':
        # Se o desafio está concluído, verificar a senha
        if challenge['status'] == 'completed':
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
                
                # Se o novo status ainda for completed, processar o novo resultado
                if status == 'completed' and result:
                    process_challenge_result(conn, challenge_id, status, result)
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
@app.route('/update_challenge/<int:challenge_id>', methods=['POST'])
def update_challenge(challenge_id):
    status = request.form['status']
    result = request.form.get('result', None)
    
    conn = get_db_connection()
    
    # Verificar se o desafio existe
    challenge = conn.execute('SELECT * FROM challenges WHERE id = ?', (challenge_id,)).fetchone()
    
    # Se o desafio está concluído e estamos modificando-o, verificar a senha
    if challenge and challenge['status'] == 'completed':
        senha = request.form.get('senha', '')
        if senha != '123':
            conn.close()
            flash('Senha incorreta! Desafios concluídos só podem ser modificados com a senha correta.', 'error')
            return redirect(url_for('challenge_detail', challenge_id=challenge_id))
    
    if status == 'completed' and result:
        # Processar o resultado do desafio com a nova função
        process_challenge_result(conn, challenge_id, status, result)
    else:
        # Apenas atualizar o status
        conn.execute('UPDATE challenges SET status = ? WHERE id = ?', (status, challenge_id))
        conn.commit()
    
    conn.close()
    
    flash('Status do desafio atualizado com sucesso!', 'success')
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
    
    # Buscar possíveis jogadores para desafiar
    potential_challenges = conn.execute('''
        SELECT p.*
        FROM players p
        WHERE p.position < ? 
          AND (p.tier = ? OR p.tier = ?)
        ORDER BY p.position DESC
    ''', (player['position'], player['tier'], chr(ord(player['tier'])-1))).fetchall()
    
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
        players_before = conn.execute('SELECT id, position FROM players ORDER BY position').fetchall()
        fix_position_gaps(conn)
        
        # Passo 2: Verificar se há jogadores com tiers incorretos
        incorrect_players = verify_pyramid_structure(conn)
        
        # Passo 3: Atualizar todos os tiers para corrigir a estrutura
        if incorrect_players:
            update_all_tiers(conn)
            
        # Verificação final
        players_after = conn.execute('SELECT id, position FROM players ORDER BY position').fetchall()
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
        players = conn.execute('SELECT id, position FROM players ORDER BY position').fetchall()
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

if __name__ == '__main__':
    # Verificar se o banco de dados existe, caso contrário, importar dados
    if not os.path.exists(DATABASE):
        print("Banco de dados não encontrado. Executando script de importação...")
        import import_data
        import_data.create_database()
        import_data.import_players_data(import_data.cursor)
    
    # Criar pasta de templates se não existir
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    # Criar pasta static se não existir
    if not os.path.exists('static'):
        os.makedirs('static')
    
    # Executar uma verificação inicial da pirâmide
    print("Realizando verificação inicial da pirâmide...")
    conn = get_db_connection()
    fix_position_gaps(conn)
    update_all_tiers(conn)
    conn.commit()
    conn.close()
    
    app.run(debug=True)