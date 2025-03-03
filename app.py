from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'liga_olimpica_golfe_2025'

DATABASE = 'golf_league.db'

# Definição fixa da estrutura da pirâmide: quais posições pertencem a cada nível
PYRAMID_STRUCTURE = {
    'A': [1],                  # Nível A: posição 1
    'B': [2, 3],               # Nível B: posições 2-3
    'C': [4, 5],               # Nível C: posições 4-5
    'D': [6, 7, 8, 9],         # Nível D: posições 6-9
    'E': [10, 11, 12, 13, 14], # Nível E: posições 10-14
    'F': [15, 16, 17, 18, 19, 20],
    'G': [21, 22, 23, 24, 25, 26, 27],
    'H': [28, 29, 30, 31, 32, 33, 34, 35],
    'I': [36, 37, 38, 39, 40, 41, 42, 43, 44],
    'J': [45, 46, 47, 48, 49, 50, 51, 52, 53, 54],
    'K': [55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65]
}

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Função simplificada para determinar o tier com base na posição usando a estrutura fixa
def get_tier_from_position(position):
    """
    Determina o nível (tier) com base na posição fixa na pirâmide.
    """
    for tier, positions in PYRAMID_STRUCTURE.items():
        if position in positions:
            return tier
    
    # Para posições não mapeadas (caso necessário expandir)
    if position <= 75:
        return 'L'
    return 'M'

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

# Função para ajustar a pirâmide quando ocorrem mudanças de posição
def rebalance_positions_after_challenge(conn, winner_id, loser_id, winner_new_pos, loser_new_pos):
    """
    Ajusta as posições de todos os jogadores após um desafio, mantendo a sequência correta.
    """
    # Buscar posições atuais
    winner_old_pos = conn.execute('SELECT position FROM players WHERE id = ?', (winner_id,)).fetchone()['position']
    
    # Se o vencedor está subindo (posição menor é melhor)
    if winner_new_pos < winner_old_pos:
        # Mover todos os jogadores entre a nova posição do vencedor e sua antiga posição (exclusive) uma posição para baixo
        conn.execute('''
            UPDATE players 
            SET position = position + 1 
            WHERE position >= ? AND position < ?
        ''', (winner_new_pos, winner_old_pos))
        
        # Definir a nova posição do vencedor
        conn.execute('UPDATE players SET position = ? WHERE id = ?', (winner_new_pos, winner_id))
    else:
        # Caso contrário, apenas defina as novas posições
        conn.execute('UPDATE players SET position = ? WHERE id = ?', (winner_new_pos, winner_id))
        conn.execute('UPDATE players SET position = ? WHERE id = ?', (loser_new_pos, loser_id))
    
    # Atualizar todos os tiers com base nas novas posições
    update_all_tiers(conn)
    
    conn.commit()
    print("Posições e tiers rebalanceados após o desafio.")

# Função para processar o resultado de um desafio
def process_challenge_result(conn, challenge_id, status, result):
    """
    Processa o resultado de um desafio, atualizando posições e tiers conforme necessário.
    """
    # Atualizar o status e resultado do desafio
    conn.execute('UPDATE challenges SET status = ?, result = ? WHERE id = ?', 
                (status, result, challenge_id))
    
    if status == 'completed' and result:
        # Buscar informações do desafio
        challenge = conn.execute('''
            SELECT c.*, 
                   p1.id as challenger_id, p1.position as challenger_position, p1.tier as challenger_tier,
                   p2.id as challenged_id, p2.position as challenged_position, p2.tier as challenged_tier
            FROM challenges c
            JOIN players p1 ON c.challenger_id = p1.id
            JOIN players p2 ON c.challenged_id = p2.id
            WHERE c.id = ?
        ''', (challenge_id,)).fetchone()
        
        # Guardar posições antigas para histórico
        challenger_old_pos = challenge['challenger_position']
        challenger_old_tier = challenge['challenger_tier']
        challenged_old_pos = challenge['challenged_position']
        challenged_old_tier = challenge['challenged_tier']
        
        if result == 'challenger_win':
            # O desafiante vence e assume a posição do desafiado
            # O desafiado e todos entre eles são movidos uma posição para baixo
            rebalance_positions_after_challenge(
                conn, 
                challenge['challenger_id'], 
                challenge['challenged_id'],
                challenge['challenged_position'],  # Nova posição do vencedor
                challenge['challenged_position'] + 1  # Nova posição do perdedor
            )
            
            # Buscar as novas posições e tiers após o rebalanceamento
            new_challenger = conn.execute('SELECT position, tier FROM players WHERE id = ?', 
                                        (challenge['challenger_id'],)).fetchone()
            new_challenged = conn.execute('SELECT position, tier FROM players WHERE id = ?', 
                                        (challenge['challenged_id'],)).fetchone()
            
            # Registrar no histórico
            conn.execute('''
                INSERT INTO ranking_history 
                (player_id, old_position, new_position, old_tier, new_tier, reason, challenge_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (challenge['challenger_id'], challenger_old_pos, new_challenger['position'], 
                 challenger_old_tier, new_challenger['tier'], 'challenge_win', challenge_id))
            
            conn.execute('''
                INSERT INTO ranking_history 
                (player_id, old_position, new_position, old_tier, new_tier, reason, challenge_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (challenge['challenged_id'], challenged_old_pos, new_challenged['position'], 
                 challenged_old_tier, new_challenged['tier'], 'challenge_loss', challenge_id))
    
    conn.commit()

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

@app.route('/challenges')
def challenges():
    conn = get_db_connection()
    # Obter todos os desafios com nomes dos jogadores
    challenges = conn.execute('''
        SELECT c.*, 
               p1.name as challenger_name, 
               p2.name as challenged_name,
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
    return render_template('challenges.html', challenges=challenges)

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
        
        error = None
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
        return redirect(url_for('challenges'))
        
    # Para requisições GET, mostrar formulário
    conn = get_db_connection()
    players = conn.execute('SELECT * FROM players ORDER BY position').fetchall()
    
    # Verificar se há um challenger_id na query string
    preselected_challenger = request.args.get('challenger_id', None)
    
    conn.close()
    return render_template('new_challenge.html', players=players, preselected_challenger=preselected_challenger)

@app.route('/update_challenge/<int:challenge_id>', methods=['POST'])
def update_challenge(challenge_id):
    status = request.form['status']
    result = request.form.get('result', None)
    
    conn = get_db_connection()
    
    if status == 'completed' and result:
        # Processar o resultado do desafio com a nova função
        process_challenge_result(conn, challenge_id, status, result)
    else:
        # Apenas atualizar o status
        conn.execute('UPDATE challenges SET status = ? WHERE id = ?', (status, challenge_id))
        conn.commit()
    
    conn.close()
    
    flash('Status do desafio atualizado com sucesso!', 'success')
    return redirect(url_for('challenges'))

@app.route('/delete_challenge/<int:challenge_id>', methods=['POST'])
def delete_challenge(challenge_id):
    conn = get_db_connection()
    
    # Verificar se o desafio existe
    challenge = conn.execute('SELECT * FROM challenges WHERE id = ?', (challenge_id,)).fetchone()
    
    if not challenge:
        conn.close()
        flash('Desafio não encontrado!', 'error')
        return redirect(url_for('challenges'))
    
    # Verificar se o desafio já afetou o ranking
    if challenge['status'] == 'completed' and challenge['result']:
        # Buscar histórico relacionado a este desafio
        history = conn.execute('SELECT * FROM ranking_history WHERE challenge_id = ?', (challenge_id,)).fetchone()
        
        if history:
            conn.close()
            flash('Este desafio já afetou o ranking e não pode ser excluído!', 'error')
            return redirect(url_for('challenge_detail', challenge_id=challenge_id))
    
    # Excluir o desafio
    conn.execute('DELETE FROM challenges WHERE id = ?', (challenge_id,))
    conn.commit()
    conn.close()
    
    flash('Desafio excluído com sucesso!', 'success')
    return redirect(url_for('challenges'))

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
        return redirect(url_for('challenges'))
    
    # Verificar se o desafio já afetou o ranking
    if challenge['status'] == 'completed' and challenge['result']:
        # Buscar histórico relacionado a este desafio
        history = conn.execute('SELECT * FROM ranking_history WHERE challenge_id = ?', (challenge_id,)).fetchone()
        
        if history:
            conn.close()
            flash('Este desafio já afetou o ranking e não pode ser editado!', 'error')
            return redirect(url_for('challenge_detail', challenge_id=challenge_id))
    
    if request.method == 'POST':
        scheduled_date = request.form['scheduled_date']
        
        # Atualizar o desafio
        conn.execute('''
            UPDATE challenges 
            SET scheduled_date = ?
            WHERE id = ?
        ''', (scheduled_date, challenge_id))
        
        conn.commit()
        conn.close()
        
        flash('Desafio atualizado com sucesso!', 'success')
        return redirect(url_for('challenge_detail', challenge_id=challenge_id))
    
    conn.close()
    return render_template('edit_challenge.html', challenge=challenge)

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
        return redirect(url_for('challenges'))
        
    return render_template('challenge_detail.html', challenge=challenge)

# Rota manual para verificar e corrigir a estrutura da pirâmide
@app.route('/fix_pyramid', methods=['GET'])
def fix_pyramid():
    conn = get_db_connection()
    
    # Verificar se há jogadores com tiers incorretos
    incorrect_players = verify_pyramid_structure(conn)
    
    if incorrect_players:
        # Atualizar todos os tiers para corrigir a estrutura
        update_all_tiers(conn)
        flash(f'Estrutura da pirâmide corrigida. {len(incorrect_players)} jogadores atualizados.', 'success')
    else:
        flash('A estrutura da pirâmide já está correta!', 'info')
    
    conn.close()
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
    
    app.run(debug=True)