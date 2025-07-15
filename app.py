from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import sqlite3
from datetime import datetime, timedelta
import os
from functools import wraps
import hashlib
from werkzeug.utils import secure_filename  # Adicione esta linha
import json

# Adicionando session config
app = Flask(__name__)
app.secret_key = 'liga_olimpica_golfe_2025'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)  # Sessão válida por 24 horas

DATABASE = 'golf_league.db'

# Função para obter conexão com o banco de dados
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Função decoradora para verificar autenticação
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, faça login para acessar esta página.', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Configurações para upload de arquivos
UPLOAD_FOLDER = 'static/profile_photos'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Certifique-se de que a pasta existe
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Adicionar configuração à aplicação
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Limitar tamanho para 5MB

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_profile_photo/<int:player_id>', methods=['POST'])
@login_required
def upload_profile_photo(player_id):
    try:
        # Verificar se é o próprio jogador ou um admin
        if not (session.get('user_id') == player_id or session.get('is_admin', False)):
            flash('Acesso negado. Você só pode alterar sua própria foto de perfil.', 'error')
            return redirect(url_for('player_detail', player_id=player_id))
        
        # Verificar se o arquivo foi enviado
        if 'profile_photo' not in request.files:
            flash('Nenhum arquivo enviado.', 'error')
            return redirect(url_for('player_detail', player_id=player_id))
        
        file = request.files['profile_photo']
        
        # Se usuário não selecionar um arquivo, o navegador envia um arquivo vazio
        if file.filename == '':
            flash('Nenhum arquivo selecionado.', 'error')
            return redirect(url_for('player_detail', player_id=player_id))
        
        if file and allowed_file(file.filename):
            # Criar nome de arquivo seguro e único
            filename = secure_filename(f"player_{player_id}_{int(datetime.now().timestamp())}.{file.filename.rsplit('.', 1)[1].lower()}")
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Salvar o arquivo
            file.save(file_path)
            
            # Atualizar o banco de dados
            conn = get_db_connection()
            
            # Obter o caminho da foto anterior (se existir)
            old_photo = conn.execute('SELECT profile_photo FROM players WHERE id = ?', 
                                  (player_id,)).fetchone()
            
            # Atualizar para o novo caminho
            conn.execute('UPDATE players SET profile_photo = ? WHERE id = ?', 
                        (filename, player_id))
            conn.commit()
            
            # Remover a foto antiga se existir
            if old_photo and old_photo['profile_photo']:
                try:
                    old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], old_photo['profile_photo'])
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)
                except Exception as e:
                    print(f"Erro ao remover arquivo antigo: {e}")
            
            conn.close()
            
            flash('Foto de perfil atualizada com sucesso!', 'success')
            return redirect(url_for('player_detail', player_id=player_id))
        else:
            flash('Tipo de arquivo não permitido. Use apenas JPG, PNG ou GIF.', 'error')
            return redirect(url_for('player_detail', player_id=player_id))
    
    except Exception as e:
        # Imprimir o erro no console do servidor para depuração
        import traceback
        print(f"Erro no upload de foto: {str(e)}")
        print(traceback.format_exc())
        flash(f'Erro ao processar o upload: {str(e)}', 'error')
        return redirect(url_for('player_detail', player_id=player_id))



@app.route('/remove_profile_photo/<int:player_id>', methods=['POST'])
@login_required
def remove_profile_photo(player_id):
    # Verificar se é o próprio jogador ou um admin
    if not (session.get('user_id') == player_id or session.get('is_admin', False)):
        flash('Acesso negado. Você só pode remover sua própria foto de perfil.', 'error')
        return redirect(url_for('player_detail', player_id=player_id))
    
    conn = get_db_connection()
    
    # Obter o caminho da foto
    photo = conn.execute('SELECT profile_photo FROM players WHERE id = ?', 
                      (player_id,)).fetchone()
    
    if photo and photo['profile_photo']:
        # Remover do banco de dados
        conn.execute('UPDATE players SET profile_photo = NULL WHERE id = ?', (player_id,))
        conn.commit()
        
        # Remover arquivo físico
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], photo['profile_photo'])
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"Erro ao remover arquivo: {e}")
    
    conn.close()
    
    flash('Foto de perfil removida com sucesso!', 'success')
    return redirect(url_for('player_detail', player_id=player_id))




# Função para obter a data atual para uso nos templates
@app.context_processor
def utility_processor():
    def now():
        return datetime.now()
    return dict(now=now)

# Registrando a biblioteca datetime para que esteja disponível nos templates
@app.context_processor
def utility_processor_datetime():
    return dict(datetime=datetime)


# Após a linha onde você cria a aplicação Flask:
# app = Flask(__name__)

# Filtro para formatar data e hora
@app.template_filter('datetime')
def format_datetime(value, format='%d/%m/%Y %H:%M'):
    """Formata uma string de data para exibição."""
    if value is None:
        return ""
    
    try:
        if isinstance(value, str):
            dt = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        else:
            dt = value
        return dt.strftime(format)
    except:
        return value

@app.template_filter('country_code')
def country_code_filter(country_name):
    """
    Converte o nome do país para o código ISO de 2 letras usado para exibir bandeiras.
    """
    # Mapeamento de nomes de países para códigos ISO de 2 letras
    country_mapping = {
        'Brasil': 'br',
        'Argentina': 'ar',
        'Portugal': 'pt',
        'Estados Unidos': 'us',
        'Espanha': 'es',
        'Itália': 'it',
        'França': 'fr',
        'Alemanha': 'de',
        'Reino Unido': 'gb',
        'Inglaterra': 'gb-eng',
        'Escócia': 'gb-sct',
        'País de Gales': 'gb-wls',
        'Irlanda do Norte': 'gb-nir',
        'Japão': 'jp',
        'Coreia do Sul': 'kr',
        'China': 'cn',
        'Austrália': 'au',
        'Canadá': 'ca',
        'México': 'mx',
        'Chile': 'cl',
        'Colômbia': 'co',
        'Uruguai': 'uy',
        'Paraguai': 'py',
        'Peru': 'pe',
        'Venezuela': 've',  # ← ADICIONE ESTA LINHA
        'África do Sul': 'za',
        'Suíça': 'ch',
        'Suécia': 'se',
        'Noruega': 'no',
        'Dinamarca': 'dk',
        'Holanda': 'nl',
        'Países Baixos': 'nl',
        'Bélgica': 'be',
        'Irlanda': 'ie',
        'Nova Zelândia': 'nz',
        'Índia': 'in',
        'Rússia': 'ru',
        'Polônia': 'pl',
        'Áustria': 'at',
        'Grécia': 'gr',
        'Turquia': 'tr'
    }
    
    # Retorna o código ISO ou o nome do país em minúsculas como fallback
    return country_mapping.get(country_name, country_name.lower())

# Adicione este código perto do início do seu arquivo app.py, após a definição da aplicação Flask

# Filtro para formatar data e hora
@app.template_filter('datetime')
def format_datetime(value, format='%d/%m/%Y %H:%M'):
    """Formata uma string de data para exibição."""
    if value is None:
        return ""
    
    try:
        if isinstance(value, str):
            dt = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        else:
            dt = value
        return dt.strftime(format)
    except:
        return value

# Função decoradora para verificar autenticação
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, faça login para acessar esta página.', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Função para obter conexão com o banco de dados
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Função auxiliar para gerar hash de senha
def hash_password(password):
    """
    Método consistente de hash para senhas usando SHA-256.
    Garante que o mesmo password sempre produza o mesmo hash.
    """
    # Garante que a senha é uma string
    if not isinstance(password, str):
        password = str(password)
    
    # Codifica a senha para bytes e aplica o hash
    encoded_password = password.encode('utf-8')
    hashed = hashlib.sha256(encoded_password).hexdigest()
    
    return hashed

# Função para criar tabela de usuários e campos de senha na tabela players
def create_authentication_tables():
    conn = get_db_connection()
    
    # Adicionar coluna de senha à tabela players se não existir
    columns_info = conn.execute('PRAGMA table_info(players)').fetchall()
    column_names = [col[1] for col in columns_info]
    
    if 'password' not in column_names:
        conn.execute('ALTER TABLE players ADD COLUMN password TEXT')
        print("Coluna 'password' adicionada à tabela players.")
    
    if 'last_login' not in column_names:
        conn.execute('ALTER TABLE players ADD COLUMN last_login DATETIME')
        print("Coluna 'last_login' adicionada à tabela players.")
    
    if 'reset_token' not in column_names:
        conn.execute('ALTER TABLE players ADD COLUMN reset_token TEXT')
        print("Coluna 'reset_token' adicionada à tabela players.")
    
    if 'reset_token_expiry' not in column_names:
        conn.execute('ALTER TABLE players ADD COLUMN reset_token_expiry DATETIME')
        print("Coluna 'reset_token_expiry' adicionada à tabela players.")
    
    # Verificar se a tabela admins existe
    tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='admins'").fetchall()
    
    # Se a tabela não existir ou se precisar recriar por falta de estrutura correta
    if not tables:
        print("Criando tabela de administradores...")
        # Tabela para administradores
        conn.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            name TEXT NOT NULL,
            email TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        )
        ''')
        
        # Criar admin padrão (username: admin, senha: 123)
        conn.execute('INSERT INTO admins (username, password, name) VALUES (?, ?, ?)', 
                    ('admin', hash_password('123'), 'Administrador'))
        print("Administrador padrão criado (usuário: admin, senha: 123).")
    else:
        # Verificar se a estrutura da tabela está correta
        admin_columns = conn.execute('PRAGMA table_info(admins)').fetchall()
        admin_column_names = [col[1] for col in admin_columns]
        
        # Se a coluna username não existir, recriar a tabela
        if 'username' not in admin_column_names:
            print("Reestruturando tabela de administradores...")
            # Fazer backup dos dados existentes, se houver
            try:
                admin_data = conn.execute('SELECT * FROM admins').fetchall()
            except:
                admin_data = []
            
            # Dropar e recriar a tabela com a estrutura correta
            conn.execute('DROP TABLE IF EXISTS admins')
            conn.execute('''
            CREATE TABLE admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                name TEXT NOT NULL,
                email TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME
            )
            ''')
            
            # Recriar admin padrão
            conn.execute('INSERT INTO admins (username, password, name) VALUES (?, ?, ?)', 
                        ('admin', hash_password('123'), 'Administrador'))
            print("Administrador padrão recriado (usuário: admin, senha: 123).")
    
    # Verificar se já temos algum admin padrão
    try:
        admin = conn.execute('SELECT * FROM admins WHERE username = ?', ('admin',)).fetchone()
        if not admin:
            # Criar admin padrão (username: admin, senha: 123)
            conn.execute('INSERT INTO admins (username, password, name) VALUES (?, ?, ?)', 
                        ('admin', hash_password('123'), 'Administrador'))
            print("Administrador padrão criado (usuário: admin, senha: 123).")
    except Exception as e:
        print(f"Erro ao verificar admin: {e}")
    
    # Definir senhas iniciais para todos os jogadores se a senha estiver vazia
    players = conn.execute('SELECT id, name, password FROM players WHERE active = 1').fetchall()
    for player in players:
        if not player['password']:
            # Senha inicial: 3 primeiras letras do nome em minúsculas
            default_password = player['name'].strip().lower()[:3]
            hashed_password = hash_password(default_password)
            
            conn.execute('UPDATE players SET password = ? WHERE id = ?', 
                       (hashed_password, player['id']))
            print(f"Senha inicial definida para o jogador {player['name']}")
    
    conn.commit()
    conn.close()
    print("Tabelas de autenticação verificadas com sucesso.")


def create_system_settings_table():
    conn = get_db_connection()
    conn.execute('''
    CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Inserir configuração padrão para desafios
    conn.execute('''
    INSERT OR IGNORE INTO system_settings (key, value)
    VALUES ('challenges_locked', 'false')
    ''')
    
    conn.commit()
    conn.close()
    print("Tabela de configurações do sistema criada/verificada com sucesso.")



# Rota de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Se o usuário já está logado, redirecionar para o dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        player_code = request.form.get('player_code', '').strip()  # Não converter para uppercase
        password = request.form.get('password', '')
        
        conn = get_db_connection()
        
        # SOLUÇÃO MELHORADA: 
        # 1. Verificar na tabela de administradores primeiro
        admin = conn.execute('SELECT * FROM admins WHERE username = ?', (player_code,)).fetchone()
        
        if admin:
            # É um administrador, verificar a senha
            if admin['password'] == hash_password(password):
                # Login bem-sucedido como administrador
                conn.execute('UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (admin['id'],))
                conn.commit()
                
                # Guardar ID do admin na sessão
                session['user_id'] = f"admin_{admin['id']}"
                session['username'] = admin['username']
                session['is_admin'] = True
                session.permanent = True
                
                flash(f'Bem-vindo, {admin["name"]}!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                print(f"Senha incorreta para admin: {player_code}")
                flash('Credenciais inválidas. Tente novamente.', 'error')
        else:
            # 2. Se não for admin, verificar se é jogador
            player_code_upper = player_code.upper()  # Converter para uppercase para busca de jogador
            
            player = conn.execute('''
                SELECT * FROM players 
                WHERE player_code = ? AND active = 1
            ''', (player_code_upper,)).fetchone()
            
            if player and player['password'] == hash_password(password):
                # Login bem-sucedido como jogador
                conn.execute('UPDATE players SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (player['id'],))
                conn.commit()
                
                # Guardar ID do jogador na sessão
                session['user_id'] = player['id']
                session['player_code'] = player['player_code']
                session['is_admin'] = False
                session.permanent = True
                
                flash(f'Bem-vindo, {player["name"]}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Credenciais inválidas. Tente novamente.', 'error')
        
        conn.close()
    
    return render_template('login.html')





# Rota de logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Você foi desconectado com sucesso.', 'success')
    return redirect(url_for('login'))

# Rota para troca de senha
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validar dados do formulário
        if not old_password or not new_password or not confirm_password:
            flash('Todos os campos são obrigatórios.', 'error')
            return redirect(url_for('change_password'))
        
        if new_password != confirm_password:
            flash('A nova senha e a confirmação não coincidem.', 'error')
            return redirect(url_for('change_password'))
        
        if len(new_password) < 3:
            flash('A nova senha deve ter pelo menos 3 caracteres.', 'error')
            return redirect(url_for('change_password'))
        
        # Verificar se a senha antiga está correta
        conn = get_db_connection()
        
        # Verificar se é um admin ou um jogador
        if session.get('is_admin', False):
            admin_id = session['user_id'].split('_')[1]
            user = conn.execute('SELECT * FROM admins WHERE id = ?', (admin_id,)).fetchone()
            user_type = 'admin'
        else:
            user = conn.execute('SELECT * FROM players WHERE id = ?', (session['user_id'],)).fetchone()
            user_type = 'player'
        
        if not user or user['password'] != hash_password(old_password):
            conn.close()
            flash('Senha atual incorreta.', 'error')
            return redirect(url_for('change_password'))
        
        # Atualizar a senha
        hashed_password = hash_password(new_password)
        
        if user_type == 'admin':
            conn.execute('UPDATE admins SET password = ? WHERE id = ?', 
                       (hashed_password, admin_id))
        else:
            conn.execute('UPDATE players SET password = ? WHERE id = ?', 
                       (hashed_password, session['user_id']))
        
        conn.commit()
        conn.close()
        
        flash('Senha alterada com sucesso!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

# Rota para solicitar reset de senha
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        player_code = request.form.get('player_code', '').strip().upper()
        
        if not player_code:
            flash('Por favor, informe seu código de jogador.', 'error')
            return redirect(url_for('forgot_password'))
        
        conn = get_db_connection()
        
        # Verificar se é um administrador pelo formato do código (admin ou admin_xyz)
        is_admin_code = player_code.lower() == 'admin' or player_code.lower().startswith('admin_')
        
        if is_admin_code:
            # Extrai o username do admin
            admin_username = player_code.split('_')[1] if '_' in player_code else 'admin'
            
            # Buscar admin pelo username
            admin = conn.execute('SELECT * FROM admins WHERE username = ?', (admin_username,)).fetchone()
            
            if admin:
                # Resetar a senha do admin para o próprio username
                new_password = admin_username
                hashed_password = hash_password(new_password)
                
                conn.execute('UPDATE admins SET password = ? WHERE id = ?', 
                           (hashed_password, admin['id']))
                
                conn.commit()
                conn.close()
                
                flash(f'Senha de administrador redefinida com sucesso. A nova senha é igual ao nome de usuário. Por favor, faça login e altere sua senha.', 'success')
                return redirect(url_for('login'))
            else:
                conn.close()
                flash('Administrador não encontrado.', 'error')
                return redirect(url_for('forgot_password'))
        else:
            # Buscar jogador pelo player_code
            player = conn.execute('''
                SELECT * FROM players 
                WHERE player_code = ? AND active = 1
            ''', (player_code,)).fetchone()
            
            if not player:
                conn.close()
                flash('Jogador não encontrado.', 'error')
                return redirect(url_for('forgot_password'))
            
            # Para fins de simplicidade, vamos resetar a senha para as 3 primeiras letras do nome
            default_password = player['name'].strip().lower()[:3]
            hashed_password = hash_password(default_password)
            
            # Atualizar a senha no banco de dados
            conn.execute('UPDATE players SET password = ? WHERE id = ?', 
                        (hashed_password, player['id']))
            
            conn.commit()
            conn.close()
            
            flash(f'A senha foi redefinida para as 3 primeiras letras do seu nome em minúsculas. Por favor, faça login e altere sua senha.', 'success')
            return redirect(url_for('login'))
    
    # Mostrar a página de "esqueci minha senha"
    return render_template('forgot_password.html')




# Rota para redefinir senha com token
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Verificar se o token é válido
    conn = get_db_connection()
    player = conn.execute('''
        SELECT * FROM players 
        WHERE reset_token = ? AND datetime(reset_token_expiry) > datetime('now')
    ''', (token,)).fetchone()
    
    if not player:
        conn.close()
        flash('Link de redefinição de senha inválido ou expirado.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not new_password or not confirm_password:
            flash('Todos os campos são obrigatórios.', 'error')
            return redirect(url_for('reset_password', token=token))
        
        if new_password != confirm_password:
            flash('A nova senha e a confirmação não coincidem.', 'error')
            return redirect(url_for('reset_password', token=token))
        
        if len(new_password) < 3:
            flash('A nova senha deve ter pelo menos 3 caracteres.', 'error')
            return redirect(url_for('reset_password', token=token))
        
        # Atualizar a senha e limpar o token
        hashed_password = hash_password(new_password)
        conn.execute('''
            UPDATE players 
            SET password = ?, reset_token = NULL, reset_token_expiry = NULL 
            WHERE id = ?
        ''', (hashed_password, player['id']))
        
        conn.commit()
        conn.close()
        
        flash('Senha redefinida com sucesso! Faça login com sua nova senha.', 'success')
        return redirect(url_for('login'))
    
    conn.close()
    return render_template('reset_password.html', token=token)

# Dashboard do jogador
# 2. Modificação na rota dashboard para melhorar os alertas para desafiados
@app.route('/dashboard')
@login_required
def dashboard():
    # Se for admin, redirecionar para o dashboard de admin
    if session.get('is_admin', False):
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    
    # Buscar informações do jogador
    player = conn.execute('SELECT * FROM players WHERE id = ?', (session['user_id'],)).fetchone()
    
    if not player:
        session.clear()
        conn.close()
        flash('Sua conta não foi encontrada. Por favor, faça login novamente.', 'error')
        return redirect(url_for('login'))
    
    # Buscar desafios pendentes
    challenges_as_challenger = conn.execute('''
        SELECT c.*, p.name as opponent_name, p.position as opponent_position
        FROM challenges c
        JOIN players p ON c.challenged_id = p.id
        WHERE c.challenger_id = ? AND c.status IN ('pending', 'accepted')
        ORDER BY c.scheduled_date
    ''', (session['user_id'],)).fetchall()
    
    # Buscar desafios onde o usuário é o desafiado e verificar prazos
    challenges_as_challenged = conn.execute('''
        SELECT c.*, p.name as opponent_name, p.position as opponent_position, c.response_deadline
        FROM challenges c
        JOIN players p ON c.challenger_id = p.id
        WHERE c.challenged_id = ? AND c.status IN ('pending', 'accepted')
        ORDER BY c.scheduled_date
    ''', (session['user_id'],)).fetchall()
    
    # Calcular dias restantes para cada desafio
    challenges_as_challenged_list = []
    for challenge in challenges_as_challenged:
        challenge_dict = dict(challenge)
        if challenge_dict['status'] == 'pending' and challenge_dict['response_deadline']:
            try:
                # Extrair apenas a data (sem o horário)
                deadline_obj = datetime.strptime(challenge_dict['response_deadline'], '%Y-%m-%d %H:%M:%S')
                deadline_date = deadline_obj.date()
                today_date = datetime.now().date()
                
                # Calcular diferença em dias
                days_remaining = (deadline_date - today_date).days
                
                # Adicionar ao dicionário
                challenge_dict['days_remaining'] = days_remaining
                challenge_dict['deadline_date'] = deadline_date.strftime('%Y-%m-%d')
            except Exception as e:
                print(f"Erro ao processar prazo de resposta: {str(e)}")
                challenge_dict['days_remaining'] = None
        challenges_as_challenged_list.append(challenge_dict)
    
    # Próximos 10 jogadores acima e abaixo na classificação
    players_above = conn.execute('''
        SELECT * FROM players 
        WHERE position < ? AND active = 1
        ORDER BY position DESC
        LIMIT 10
    ''', (player['position'],)).fetchall()
    
    players_below = conn.execute('''
        SELECT * FROM players 
        WHERE position > ? AND active = 1
        ORDER BY position
        LIMIT 10
    ''', (player['position'],)).fetchall()
    
    # Buscar jogadores que podem ser desafiados
    potential_challenges = []
    if player['active'] == 1 and player['position']:
        # Calcular o tier anterior (um nível acima)
        tier = player['tier']
        prev_tier = chr(ord(tier) - 1) if ord(tier) > ord('A') else tier
        
        potential_challenges = conn.execute('''
            SELECT p.*
            FROM players p
            WHERE p.position < ? 
              AND (p.tier = ? OR p.tier = ?)
              AND p.active = 1
              AND p.id NOT IN (
                SELECT challenged_id FROM challenges 
                WHERE challenger_id = ? AND status IN ('pending', 'accepted')
              )
              AND p.id NOT IN (
                SELECT challenger_id FROM challenges 
                WHERE challenged_id = ? AND status IN ('pending', 'accepted')
              )
            ORDER BY p.position DESC
        ''', (player['position'], tier, prev_tier, player['id'], player['id'])).fetchall()
    
    conn.close()
    
    # Adicionar verificação para desafios pendentes e mostrar alertas
    for challenge in challenges_as_challenged_list:
        if challenge['status'] == 'pending' and 'days_remaining' in challenge:
            days_remaining = challenge['days_remaining']
            if days_remaining is not None:
                if days_remaining < 0:
                    # Prazo expirado
                    flash(f'ATENÇÃO: Você foi desafiado por {challenge["opponent_name"]}. O prazo para aceitar, rejeitar ou propor nova data EXPIROU! Acesse <a href="{url_for("challenge_detail", challenge_id=challenge["id"])}">aqui</a> para responder.', 'danger')
                elif days_remaining == 0:
                    # Vence hoje
                    flash(f'ATENÇÃO: Você foi desafiado por {challenge["opponent_name"]}! O prazo para aceitar, rejeitar ou propor nova data vence HOJE. Acesse <a href="{url_for("challenge_detail", challenge_id=challenge["id"])}">aqui</a> para responder.', 'warning')
                elif days_remaining <= 2:
                    # Próximo do vencimento (2 dias ou menos)
                    flash(f'ATENÇÃO: Você foi desafiado por {challenge["opponent_name"]}! Você tem {days_remaining} dias para aceitar, rejeitar ou propor nova data dentro de 7 dias a partir de hoje. Acesse <a href="{url_for("challenge_detail", challenge_id=challenge["id"])}">aqui</a> para responder.', 'warning')
                else:
                    # Demais casos, ainda no prazo
                    flash(f'Você foi desafiado por {challenge["opponent_name"]}! Você tem {days_remaining} dias para aceitar, rejeitar ou propor nova data dentro de 7 dias a partir de hoje. Acesse <a href="{url_for("challenge_detail", challenge_id=challenge["id"])}">aqui</a> para responder.', 'info')
    
    return render_template('dashboard.html', 
                          player=player,
                          challenges_as_challenger=challenges_as_challenger,
                          challenges_as_challenged=challenges_as_challenged_list,
                          players_above=players_above,
                          players_below=players_below,
                          potential_challenges=potential_challenges)


# Dashboard do administrador
@app.route('/admin')
@login_required
def admin_dashboard():
    if not session.get('is_admin', False):
        flash('Acesso restrito a administradores.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    
    # Estatísticas gerais
    stats = {}
    
    # Total de jogadores ativos
    active_players = conn.execute('SELECT COUNT(*) as count FROM players WHERE active = 1').fetchone()
    stats['active_players'] = active_players['count']
    
    # Total de desafios pendentes
    pending_challenges = conn.execute('SELECT COUNT(*) as count FROM challenges WHERE status IN ("pending", "accepted")').fetchone()
    stats['pending_challenges'] = pending_challenges['count']
    
    # Verificar se a tabela system_settings existe
    table_exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='system_settings'").fetchone()
    challenges_locked = False
    
    if table_exists:
        # Verificar se os desafios estão bloqueados
        setting = conn.execute('SELECT value FROM system_settings WHERE key = ?', ('challenges_locked',)).fetchone()
        challenges_locked = setting and setting['value'] == 'true'
    else:
        # Criar a tabela se não existir
        conn.execute('''
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Inserir configuração padrão para desafios
        conn.execute('''
        INSERT OR IGNORE INTO system_settings (key, value)
        VALUES ('challenges_locked', 'false')
        ''')
        conn.commit()
    
    # Desafios recentes
    recent_challenges = conn.execute('''
        SELECT c.*, 
               p1.name as challenger_name, 
               p2.name as challenged_name
        FROM challenges c
        JOIN players p1 ON c.challenger_id = p1.id
        JOIN players p2 ON c.challenged_id = p2.id
        ORDER BY c.created_at DESC
        LIMIT 10
    ''').fetchall()
    
    # Jogadores que nunca fizeram login
    never_logged = conn.execute('''
        SELECT * FROM players
        WHERE last_login IS NULL AND active = 1
        ORDER BY name
    ''').fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html', 
                          stats=stats,
                          recent_challenges=recent_challenges,
                          never_logged=never_logged,
                          challenges_locked=challenges_locked)




# Inicialização da aplicação
if __name__ == '__main__':
    # Verificar se o banco de dados existe, caso contrário, importar dados
    if not os.path.exists(DATABASE):
        print("Banco de dados não encontrado. Executando script de importação...")
        import import_data
        import_data.create_database()
        import_data.import_players_data(import_data.cursor)
    
    # Criar tabelas de autenticação
    create_authentication_tables()

# NOVA ESTRUTURA DA PIRAMIDE
PYRAMID_STRUCTURE = {
    'C': [1, 2, 3, 4],                       # Nível A: 4 posições
    'D': [5, 6, 7, 8, 9, 10],                # Nível B: 6 posições
    'E': [11, 12, 13, 14, 15, 16, 17, 18],   # Nível C: 8 posições
    'F': [19, 20, 21, 22, 23, 24, 25, 26, 27, 28], # Nível D: 10 posições
    'G': [29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40], # Nível E: 12 posições
    'H': [41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54], # Nível F: 14 posições
    'I': [55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70], # Nível G: 16 posições
    'J': [71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88], # Nível H: 18 posições
    # Se precisar continuar com mais níveis, basta adicionar seguindo o mesmo padrão
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


def create_business_table():
    try:
        conn = get_db_connection()
        
        # Verificar se a tabela já existe
        table_exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='businesses'").fetchone()
        
        if not table_exists:
            conn.execute('''
            CREATE TABLE IF NOT EXISTS businesses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                player_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                image_path TEXT,
                contact_info TEXT,
                active INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (player_id) REFERENCES players(id)
            )
            ''')
            
            # Criar pasta para imagens de negócios
            business_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'business_images')
            os.makedirs(business_upload_folder, exist_ok=True)
            
            print("Tabela de negócios criada com sucesso e pasta de imagens verificada.")
        else:
            print("Tabela de negócios já existe.")
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"ERRO ao criar tabela de negócios: {str(e)}")
        return False


# Função para criar tabela de histórico de handicap
def create_hcp_history_table():
    conn = get_db_connection()
    conn.execute('''
    CREATE TABLE IF NOT EXISTS hcp_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        player_id INTEGER NOT NULL,
        old_hcp REAL,
        new_hcp REAL NOT NULL,
        modified_by TEXT NOT NULL,
        notes TEXT,
        change_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (player_id) REFERENCES players(id)
    )
    ''')
    
    # Criar um índice para melhorar a performance das consultas
    conn.execute('''
    CREATE INDEX IF NOT EXISTS idx_hcp_history_player_date 
    ON hcp_history (player_id, change_date)
    ''')
    
    conn.commit()
    conn.close()
    print("Tabela de histórico de handicap criada com sucesso.")

# Função para registrar alterações de handicap
def record_hcp_change(player_id, old_hcp, new_hcp, modified_by, notes=None):
    """
    Registra alterações no handicap de um jogador.
    
    Args:
        player_id: ID do jogador
        old_hcp: Handicap anterior (pode ser None)
        new_hcp: Novo handicap
        modified_by: Quem modificou ('admin', 'player', etc)
        notes: Observações sobre a alteração (opcional)
    """
    conn = get_db_connection()
    
    try:
        conn.execute('''
            INSERT INTO hcp_history 
            (player_id, old_hcp, new_hcp, modified_by, notes)
            VALUES (?, ?, ?, ?, ?)
        ''', (player_id, old_hcp, new_hcp, modified_by, notes))
        
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Erro ao registrar alteração de handicap: {str(e)}")
    finally:
        conn.close()



"""
Copie esta função corrigida para substituir a existente no seu arquivo app.py
"""

@app.route('/player/<int:player_id>/hcp_history')
def player_hcp_history(player_id):
    """
    Exibe o histórico de handicap de um jogador específico.
    Versão corrigida para tratamento de erros.
    """
    try:
        conn = get_db_connection()
        
        # Verificar se o jogador existe
        player = conn.execute('SELECT * FROM players WHERE id = ?', (player_id,)).fetchone()
        
        if not player:
            conn.close()
            flash('Jogador não encontrado!', 'error')
            return redirect(url_for('index'))
        
        # Verificar se a tabela hcp_history existe
        table_exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hcp_history'").fetchone()
        
        if not table_exists:
            # Criar a tabela se não existir
            conn.execute('''
            CREATE TABLE IF NOT EXISTS hcp_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                player_id INTEGER NOT NULL,
                old_hcp REAL,
                new_hcp REAL NOT NULL,
                modified_by TEXT NOT NULL,
                notes TEXT,
                change_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (player_id) REFERENCES players(id)
            )
            ''')
            conn.commit()
        
        # Buscar histórico de handicap do jogador
        history = conn.execute('''
            SELECT hcp_history.*, players.name as player_name
            FROM hcp_history 
            JOIN players ON hcp_history.player_id = players.id
            WHERE player_id = ?
            ORDER BY change_date DESC
        ''', (player_id,)).fetchall()
        
        conn.close()
        
        # Converter os dados de Row para dict para evitar problemas
        history_list = []
        for item in history:
            # Copia os valores para um dicionário, garantindo tratamento adequado
            item_dict = {}
            for key in item.keys():
                item_dict[key] = item[key]
            history_list.append(item_dict)
        
        return render_template('player_hcp_history.html', 
                              player=player,
                              history=history_list)  # Enviar a lista convertida
    
    except Exception as e:
        # Tratar qualquer exceção para exibir uma mensagem útil ao usuário
        import traceback
        error_details = traceback.format_exc()
        
        # Registrar o erro para debug
        print(f"Erro ao acessar histórico de HCP: {str(e)}")
        print(error_details)
        
        # Mostrar mensagem amigável ao usuário
        flash(f'Erro ao carregar o histórico de handicap: {str(e)}', 'error')
        return redirect(url_for('player_detail', player_id=player_id))


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
    Nova versão que começa do tier C.
    """
    # Verificar em cada tier definido na estrutura
    for tier, positions in PYRAMID_STRUCTURE.items():
        if position in positions:
            return tier
    
    # Para posições que excederam a estrutura definida
    # Cálculo automático para tiers adicionais
    
    # Primeiro, determinar a posição inicial do próximo tier após os definidos
    last_tier_letter = list(PYRAMID_STRUCTURE.keys())[-1]
    last_tier_positions = PYRAMID_STRUCTURE[last_tier_letter]
    next_position = max(last_tier_positions) + 1
    
    # Cálculo do tamanho do próximo tier (2 a mais que o anterior)
    tier_index = ord(last_tier_letter) - ord('C')  # C=0, D=1, etc. (modificado para começar de C)
    next_tier_size = 4 + (2 * tier_index) + 2  # 4 + (2*tier_index) é o tamanho do último tier, +2 para o próximo
    
    # Calcular em qual tier a posição se encaixa
    tier_letter = last_tier_letter
    current_position = next_position
    current_tier_size = next_tier_size
    
    while current_position <= position:
        # Avançar para o próximo tier
        tier_letter = chr(ord(tier_letter) + 1)
        current_position += current_tier_size
        current_tier_size += 2  # Cada tier tem 2 posições a mais que o anterior
    
    # Voltar um tier, pois fomos longe demais
    return chr(ord(tier_letter) - 1)

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
    Versão atualizada que inclui a regra: quando o desafiante perde, ele troca de posição com o jogador abaixo.
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
        challenger_id = challenge['challenger_id']
        challenger_old_pos = challenge['challenger_position']
        challenger_old_tier = challenge['challenger_tier']
        challenged_id = challenge['challenged_id']
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
                # NOVA REGRA: Se o desafiado ganhar, o desafiante troca de posição com quem está uma posição abaixo
                
                # Primeiro, verificar se existe alguém uma posição abaixo do desafiante
                player_below = conn.execute('''
                    SELECT id, position FROM players 
                    WHERE position = ? AND active = 1
                ''', (challenger_old_pos + 1,)).fetchone()
                
                if player_below:
                    # Se existe um jogador abaixo, trocar as posições
                    player_below_id = player_below['id']
                    
                    # Atualizando para a nova regra: desafiante troca com quem está abaixo
                    conn.execute('UPDATE players SET position = ? WHERE id = ?', 
                               (challenger_old_pos + 1, challenger_id))
                    conn.execute('UPDATE players SET position = ? WHERE id = ?', 
                               (challenger_old_pos, player_below_id))
                    
                    # Registrar a mudança no histórico para o desafiante que perdeu
                    conn.execute('''
                        INSERT INTO ranking_history 
                        (player_id, old_position, new_position, old_tier, new_tier, reason, challenge_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (challenger_id, challenger_old_pos, challenger_old_pos + 1, 
                         challenger_old_tier, get_tier_from_position(challenger_old_pos + 1), 
                         'challenge_loss_demotion', challenge_id))
                    
                    # E também para o jogador que subiu uma posição
                    conn.execute('''
                        INSERT INTO ranking_history 
                        (player_id, old_position, new_position, old_tier, new_tier, reason, challenge_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (player_below_id, challenger_old_pos + 1, challenger_old_pos, 
                         get_tier_from_position(challenger_old_pos + 1), get_tier_from_position(challenger_old_pos), 
                         'player_promoted_due_to_challenge', challenge_id))
                else:
                    # Se não houver ninguém abaixo, não há troca de posição
                    print(f"Não há jogador abaixo da posição {challenger_old_pos} para trocar")
            else:
                # Resultado inválido
                print(f"Erro: Resultado inválido: {result}")
                conn.rollback()
                return
            
            # Verificar se houve mudança nas posições
            new_challenger = conn.execute('SELECT position, tier FROM players WHERE id = ?', 
                                        (challenger_id,)).fetchone()
            new_challenged = conn.execute('SELECT position, tier FROM players WHERE id = ?', 
                                        (challenged_id,)).fetchone()
            
            # O registro no histórico para o desafiante já foi feito, se necessário
            # O registro para o desafiado também já foi feito se ele perdeu
            
            # Atualizar todos os tiers após qualquer alteração
            update_all_tiers(conn)
            
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


@app.route('/delete_player/<int:player_id>', methods=['GET', 'POST'])
def delete_player(player_id):
    """
    Exclui permanentemente um jogador do sistema.
    O jogador deve estar inativo para ser excluído.
    GET: Mostra formulário de confirmação
    POST: Processa a exclusão
    """
    conn = get_db_connection()
    
    # Buscar jogador
    player = conn.execute('SELECT * FROM players WHERE id = ?', (player_id,)).fetchone()
    
    if not player:
        conn.close()
        flash('Jogador não encontrado!', 'error')
        return redirect(url_for('index'))
    
    # Verificar se o jogador está inativo (requisito para exclusão)
    if player['active'] == 1:
        conn.close()
        flash('O jogador deve estar inativo antes de ser excluído. Por favor, inative o jogador primeiro.', 'error')
        return redirect(url_for('player_detail', player_id=player_id))
    
    # Para requisição GET, mostrar tela de confirmação
    if request.method == 'GET':
        # Verificar se existem desafios associados ao jogador
        challenges_count = conn.execute('''
            SELECT COUNT(*) AS count FROM challenges 
            WHERE challenger_id = ? OR challenged_id = ?
        ''', (player_id, player_id)).fetchone()['count']
        
        # Verificar se existem registros de histórico
        history_count = conn.execute('''
            SELECT COUNT(*) AS count FROM ranking_history 
            WHERE player_id = ?
        ''', (player_id,)).fetchone()['count']
        
        daily_history_count = conn.execute('''
            SELECT COUNT(*) AS count FROM daily_ranking_history 
            WHERE player_id = ?
        ''', (player_id,)).fetchone()['count']
        
        conn.close()
        
        return render_template('delete_player.html', 
                              player=player, 
                              challenges_count=challenges_count,
                              history_count=history_count + daily_history_count)
    
    # Para requisição POST, processar a exclusão
    senha = request.form.get('senha', '')
    confirm_delete = request.form.get('confirm_delete', 'no') == 'yes'
    
    if senha != '123':
        conn.close()
        flash('Senha incorreta! Operação não autorizada.', 'error')
        return redirect(url_for('player_detail', player_id=player_id))
    
    if not confirm_delete:
        conn.close()
        flash('Você precisa confirmar a exclusão marcando a caixa de confirmação.', 'error')
        return redirect(url_for('delete_player', player_id=player_id))
    
    try:
        # 1. Excluir registros relacionados na tabela daily_ranking_history
        conn.execute('DELETE FROM daily_ranking_history WHERE player_id = ?', (player_id,))
        
        # 2. Excluir registros relacionados na tabela ranking_history
        conn.execute('DELETE FROM ranking_history WHERE player_id = ?', (player_id,))
        
        # 3. Excluir ou atualizar desafios relacionados
        # Como os desafios possuem foreign keys, podemos definir a estratégia:
        # Opção 1: Excluir todos os desafios relacionados
        conn.execute('''
            DELETE FROM challenges 
            WHERE challenger_id = ? OR challenged_id = ?
        ''', (player_id, player_id))
        
        # 4. Finalmente, excluir o jogador
        conn.execute('DELETE FROM players WHERE id = ?', (player_id,))
        
        conn.commit()
        flash(f'Jogador "{player["name"]}" foi excluído permanentemente.', 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao excluir jogador: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('index'))


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

@app.route('/update_player_country/<int:player_id>', methods=['POST'])
def update_player_country(player_id):
    """
    Atualiza o país do jogador
    """
    conn = get_db_connection()
    
    try:
        # Verificar se o jogador existe
        player = conn.execute('SELECT * FROM players WHERE id = ?', (player_id,)).fetchone()
        
        if not player:
            conn.close()
            flash('Jogador não encontrado!', 'error')
            return redirect(url_for('index'))
        
        # Verificar se é o próprio usuário editando seu perfil
        is_own_profile = False
        user_id = session.get('user_id')
        
        # Verificar se é um admin (o ID pode ser no formato 'admin_1')
        if isinstance(user_id, str) and user_id.startswith('admin_'):
            is_own_profile = False
        elif isinstance(user_id, int):
            is_own_profile = user_id == player_id
        elif isinstance(user_id, str) and user_id.isdigit():
            is_own_profile = int(user_id) == player_id
        
        # Verificar senha apenas para administradores
        if not is_own_profile:
            senha = request.form.get('senha', '')
            if senha != '123':
                conn.close()
                flash('Senha incorreta! Operação não autorizada.', 'error')
                return redirect(url_for('player_detail', player_id=player_id))
        
        # Obter novo país
        new_country = request.form.get('new_country', '').strip()
        
        # Verificar se a coluna 'country' existe no objeto player
        try:
            old_country = player['country']
        except (KeyError, IndexError):
            # Se a coluna não existe, considerar como None
            old_country = None
        
        # Se o país não mudou, não fazer nada
        if new_country == old_country:
            conn.close()
            flash('Nenhuma alteração foi realizada.', 'info')
            return redirect(url_for('player_detail', player_id=player_id))
        
        # Verificar se a coluna 'country' existe na tabela players
        columns_info = conn.execute('PRAGMA table_info(players)').fetchall()
        column_names = [col[1] for col in columns_info]
        
        if 'country' not in column_names:
            # Se a coluna não existe, criar ela
            conn.execute('ALTER TABLE players ADD COLUMN country TEXT DEFAULT NULL')
            conn.commit()
            print("Coluna 'country' adicionada à tabela players.")
        
        # Atualizar o país do jogador
        conn.execute('UPDATE players SET country = ? WHERE id = ?', (new_country, player_id))
        
        # Opcional: Registrar alteração nas notas
        old_country_display = old_country if old_country else 'não informado'
        new_country_display = new_country if new_country else 'não informado'
        
        notes = f"País alterado de '{old_country_display}' para '{new_country_display}' em {datetime.now().strftime('%d/%m/%Y')}"
        
        # Se o jogador já tem notas, adicionar à frente
        if player['notes']:
            notes = f"{player['notes']} | {notes}"
        
        # Atualizar as notas
        conn.execute('UPDATE players SET notes = ? WHERE id = ?', (notes, player_id))
        
        conn.commit()
        flash(f'País atualizado com sucesso para "{new_country_display}"', 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao atualizar o país: {str(e)}', 'error')
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
        SELECT DISTINCT c.challenger_id, c.challenged_id, c.status, c.scheduled_date,
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
    
    # Buscar todos os desafios aceitos e pendentes para mostrar datas ou indicadores
    challenges_for_display = conn.execute('''
        SELECT id, challenger_id, challenged_id, status, scheduled_date
        FROM challenges
        WHERE status IN ('accepted', 'pending')
    ''').fetchall()
    
    conn.close()
    return render_template('pyramid_dynamic.html', 
                          tiers=sorted_tiers, 
                          challenges=challenges_for_display)

# Rota original (mantida para compatibilidade ou redirecionamento)
# Altere estas rotas no seu arquivo app.py:

@app.route('/challenges')
def challenges():
    """Redireciona para a página de lista de desafios (nova interface principal)"""
    return redirect(url_for('challenges_list'))

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

# Rota para a lista de desafios (agora a padrão)
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

# 1. Modificação na rota new_challenge para validar a data do desafio (máximo 7 dias)
# Substitua a rota new_challenge existente por esta versão modificada

# Substitua a rota new_challenge existente por esta versão modificada

@app.route('/new_challenge', methods=['GET', 'POST'])
@login_required
def new_challenge():
    # Verificar se os desafios estão bloqueados
    conn = get_db_connection()
    setting = conn.execute('SELECT value FROM system_settings WHERE key = ?', ('challenges_locked',)).fetchone()
    challenges_locked = setting and setting['value'] == 'true'
    
    # Se os desafios estão bloqueados e o usuário não é admin, bloquear
    is_admin = session.get('is_admin', False)
    # NOVA VERIFICAÇÃO: Identificar se é o admin principal
    is_main_admin = is_admin and session.get('username') == 'admin'
    
    if challenges_locked and not is_admin:
        conn.close()
        flash('A criação de desafios está temporariamente bloqueada pelo administrador.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        challenger_id = request.form['challenger_id']
        challenged_id = request.form['challenged_id']
        scheduled_date = request.form['scheduled_date']
        
        # Validação da data do desafio (não pode ser no passado e deve estar dentro de 7 dias)
        try:
            scheduled_date_obj = datetime.strptime(scheduled_date, '%Y-%m-%d').date()
            today_date = datetime.now().date()
            max_date = today_date + timedelta(days=7)
            
            if scheduled_date_obj > max_date:
                conn.close()
                flash(f'A data do desafio não pode ser superior a 7 dias a partir de hoje. Data máxima permitida: {max_date.strftime("%d/%m/%Y")}', 'error')
                return redirect(url_for('new_challenge', challenger_id=challenger_id))
            
            if scheduled_date_obj < today_date:
                conn.close()
                flash('A data do desafio não pode ser anterior à data atual.', 'error')
                return redirect(url_for('new_challenge', challenger_id=challenger_id))
        except ValueError:
            conn.close()
            flash('Formato de data inválido.', 'error')
            return redirect(url_for('new_challenge', challenger_id=challenger_id))
        
        # Verificar se ambos jogadores estão ativos
        challenger = conn.execute('SELECT * FROM players WHERE id = ? AND active = 1', (challenger_id,)).fetchone()
        challenged = conn.execute('SELECT * FROM players WHERE id = ? AND active = 1', (challenged_id,)).fetchone()
        
        if not challenger or not challenged:
            conn.close()
            flash('Um dos jogadores está inativo e não pode participar de desafios.', 'error')
            return redirect(url_for('new_challenge'))
        
        # Regras aplicáveis a todos os usuários, incluindo administradores
        error = None
        
        # Verificar se algum dos jogadores já tem desafios pendentes ou aceitos
        pending_challenges = conn.execute('''
            SELECT * FROM challenges 
            WHERE (challenger_id = ? OR challenged_id = ? OR challenger_id = ? OR challenged_id = ?)
            AND status IN ('pending', 'accepted')
        ''', (challenger_id, challenger_id, challenged_id, challenged_id)).fetchall()
        
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
        
        # MODIFICAÇÃO PRINCIPAL: Aplicar regras de tier e posição APENAS para o admin principal
        if not error and not is_main_admin:
            challenger_tier = challenger['tier']
            challenged_tier = challenged['tier']
            
            # Verificar níveis especiais A ou B
            if challenged_tier in ['A', 'B']:
                error = "Não é possível desafiar jogadores dos níveis A ou B. Esses níveis são reservados para os vencedores do play-off."
            else:
                # Calcular diferença de níveis
                tier_difference = ord(challenger_tier) - ord(challenged_tier)
                
                # Verificar restrições de tier
                if tier_difference < 0:
                    error = "Você só pode desafiar jogadores de níveis acima do seu."
                elif tier_difference > 1:
                    error = "Você só pode desafiar jogadores até uma linha acima da sua."
                # Verificar posição
                elif challenged['position'] > challenger['position']:
                    error = "Você só pode desafiar jogadores em posições melhores que a sua."
        
        # Se for admin principal, mostrar uma mensagem informativa no log
        if is_main_admin and not error:
            print(f"Admin principal criando desafio sem restrições: {challenger['name']} (Pos {challenger['position']}, Tier {challenger['tier']}) vs {challenged['name']} (Pos {challenged['position']}, Tier {challenged['tier']})")
        
        if error:
            conn.close()
            flash(error, 'error')
            return redirect(url_for('new_challenge'))
        
        # Processamento do desafio (tudo em ordem para criar)
        current_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        response_deadline = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
        
        # Inserir o novo desafio
        conn.execute('''
            INSERT INTO challenges (challenger_id, challenged_id, status, scheduled_date, created_at, response_deadline)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (challenger_id, challenged_id, 'pending', scheduled_date, current_datetime, response_deadline))
        
        # Obter o ID do desafio recém-criado
        challenge_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        
        # Registrar a criação do desafio no log
        try:
            # Verificar se a tabela de logs existe
            table_exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='challenge_logs'").fetchone()
            
            if not table_exists:
                # Criar a tabela se não existir
                conn.execute('''
                    CREATE TABLE challenge_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        challenge_id INTEGER,
                        user_id TEXT NOT NULL,
                        modified_by TEXT NOT NULL,
                        old_status TEXT,
                        new_status TEXT,
                        old_result TEXT,
                        new_result TEXT,
                        notes TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
            
            # Determinar quem está criando o desafio
            creator_type = "Admin Principal" if is_main_admin else "Admin" if is_admin else "Jogador"
            
            # Adicionar nota especial se for admin principal criando sem restrições
            notes = f"Desafio criado. Marcado para {scheduled_date}"
            if is_main_admin:
                notes += " (Criado pelo admin principal sem restrições de tier/posição)"
            
            # Inserir o log de criação
            conn.execute('''
                INSERT INTO challenge_logs 
                (challenge_id, user_id, modified_by, old_status, new_status, old_result, new_result, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                challenge_id, 
                session.get('user_id', 'unknown'),
                creator_type,
                None,
                'pending',
                None,
                None,
                notes,
                current_datetime
            ))
            
        except Exception as e:
            print(f"Erro ao registrar log de criação: {e}")
            # Continuar mesmo se o log falhar
        
        conn.commit()
        conn.close()
        
        # Mensagem de sucesso diferenciada para admin principal
        if is_main_admin:
            flash('Desafio criado com sucesso pelo administrador principal (sem restrições)! O desafiado terá 7 dias para responder.', 'success')
        else:
            flash('Desafio criado com sucesso! O desafiado terá 7 dias para responder ou propor uma nova data.', 'success')
        
        return redirect(url_for('challenges_calendar'))
    
    # Para requisições GET, mostrar formulário
    preselected_challenger_id = None
    all_players = []
    eligible_challenged = []
    
    if is_main_admin:
        # MODIFICAÇÃO: Apenas o admin principal vê TODOS os jogadores ativos como possíveis desafiados
        all_players = conn.execute('SELECT * FROM players WHERE active = 1 ORDER BY position').fetchall()
        
        # Verificar se há um desafiante pré-selecionado na query string
        preselected_challenger_id = request.args.get('challenger_id')
        
        # Se há um desafiante pré-selecionado, buscar TODOS os outros jogadores ativos
        if preselected_challenger_id:
            try:
                preselected_challenger_id = int(preselected_challenger_id)
                challenger = conn.execute('SELECT * FROM players WHERE id = ? AND active = 1', 
                                         (preselected_challenger_id,)).fetchone()
                
                if challenger:
                    # Para admin principal, mostrar TODOS os jogadores ativos exceto o próprio desafiante
                    eligible_challenged = conn.execute('''
                        SELECT * FROM players 
                        WHERE active = 1
                        AND id != ?
                        ORDER BY position
                    ''', (preselected_challenger_id,)).fetchall()
                    
                    # Verificar jogadores com desafios pendentes
                    players_with_challenges = set()
                    pending_challenges = conn.execute('''
                        SELECT challenger_id, challenged_id 
                        FROM challenges 
                        WHERE status IN ('pending', 'accepted')
                    ''').fetchall()
                    
                    for challenge in pending_challenges:
                        players_with_challenges.add(challenge['challenger_id'])
                        players_with_challenges.add(challenge['challenged_id'])
                    
                    # Verificar se o desafiante já tem desafios pendentes
                    if preselected_challenger_id in players_with_challenges:
                        flash('Este jogador já está envolvido em um desafio pendente ou aceito.', 'warning')
                    
                    # Filtrar jogadores com desafios pendentes (mantém esta restrição mesmo para admin principal)
                    eligible_challenged = [player for player in eligible_challenged 
                                          if player['id'] not in players_with_challenges]
            except (ValueError, TypeError):
                preselected_challenger_id = None
    elif is_admin:
        # Outros admins seguem as regras normais, mas podem selecionar qualquer jogador como desafiante
        all_players = conn.execute('SELECT * FROM players WHERE active = 1 ORDER BY position').fetchall()
        
        # Verificar se há um desafiante pré-selecionado na query string
        preselected_challenger_id = request.args.get('challenger_id')
        
        # Se há um desafiante pré-selecionado, aplicar regras normais de tier
        if preselected_challenger_id:
            try:
                preselected_challenger_id = int(preselected_challenger_id)
                challenger = conn.execute('SELECT * FROM players WHERE id = ? AND active = 1', 
                                         (preselected_challenger_id,)).fetchone()
                
                if challenger:
                    # Para outros admins, aplicar regras normais de tier
                    tier = challenger['tier']
                    prev_tier = chr(ord(tier) - 1) if ord(tier) > ord('C') else tier
                    
                    eligible_challenged = conn.execute('''
                        SELECT * FROM players 
                        WHERE active = 1
                        AND position < ? 
                        AND (tier = ? OR tier = ?)
                        AND tier NOT IN ('A', 'B')
                        ORDER BY position
                    ''', (challenger['position'], tier, prev_tier)).fetchall()
                    
                    # Verificar jogadores com desafios pendentes
                    players_with_challenges = set()
                    pending_challenges = conn.execute('''
                        SELECT challenger_id, challenged_id 
                        FROM challenges 
                        WHERE status IN ('pending', 'accepted')
                    ''').fetchall()
                    
                    for challenge in pending_challenges:
                        players_with_challenges.add(challenge['challenger_id'])
                        players_with_challenges.add(challenge['challenged_id'])
                    
                    # Verificar se o desafiante já tem desafios pendentes
                    if preselected_challenger_id in players_with_challenges:
                        flash('Este jogador já está envolvido em um desafio pendente ou aceito.', 'warning')
                    
                    # Filtrar jogadores com desafios pendentes
                    eligible_challenged = [player for player in eligible_challenged 
                                          if player['id'] not in players_with_challenges]
            except (ValueError, TypeError):
                preselected_challenger_id = None
    else:
        # Para jogadores normais, manter lógica atual
        if 'user_id' in session and not is_admin:
            preselected_challenger_id = session['user_id']
        else:
            temp_id = request.args.get('challenger_id')
            if temp_id:
                try:
                    preselected_challenger_id = int(temp_id)
                except (ValueError, TypeError):
                    preselected_challenger_id = None
        
        # Buscar jogadores com desafios pendentes
        challenges = conn.execute('''
            SELECT DISTINCT c.challenger_id, c.challenged_id, c.status, c.scheduled_date,
                p1.position as challenger_position, p2.position as challenged_position
            FROM challenges c
            JOIN players p1 ON c.challenger_id = p1.id
            JOIN players p2 ON c.challenged_id = p2.id
            WHERE c.status IN ('pending', 'accepted')
        ''').fetchall()

        players_with_challenges = set()
        for challenge in challenges:
            challenger_id = challenge['challenger_id']
            challenged_id = challenge['challenged_id']
            players_with_challenges.add(challenger_id)
            players_with_challenges.add(challenged_id)
        
        if preselected_challenger_id:
            if preselected_challenger_id in players_with_challenges:
                conn.close()
                flash('Este jogador já está envolvido em um desafio pendente ou aceito.', 'warning')
                return redirect(url_for('challenges_calendar'))
            
            challenger = conn.execute('SELECT * FROM players WHERE id = ? AND active = 1', 
                                     (preselected_challenger_id,)).fetchone()
            
            if challenger:
                all_players = conn.execute('SELECT * FROM players WHERE active = 1 ORDER BY position').fetchall()
                
                eligible_challenged = conn.execute('''
                    SELECT * FROM players 
                    WHERE active = 1
                    AND position < ? 
                    AND (tier = ? OR tier = ?)
                    AND tier NOT IN ('A', 'B')
                    ORDER BY position
                ''', (challenger['position'], challenger['tier'], chr(ord(challenger['tier'])-1))).fetchall()
                
                eligible_challenged = [player for player in eligible_challenged 
                                      if player['id'] not in players_with_challenges]
        else:
            all_players = conn.execute('SELECT * FROM players WHERE active = 1 ORDER BY position').fetchall()
            all_players = [player for player in all_players 
                          if player['id'] not in players_with_challenges]
    
    # Adicionar data atual formatada para o campo de data
    today_date = datetime.now().strftime('%Y-%m-%d')
    
    # Se temos um desafiante pré-selecionado e informações dele
    challenger_info = None
    if preselected_challenger_id:
        challenger_info = conn.execute('SELECT * FROM players WHERE id = ? AND active = 1', 
                                      (preselected_challenger_id,)).fetchone()
    
    conn.close()
    
    return render_template('new_challenge.html', 
                          all_players=all_players, 
                          eligible_challenged=eligible_challenged,
                          preselected_challenger=preselected_challenger_id,
                          challenger_info=challenger_info,
                          today_date=today_date,
                          is_admin=is_admin,
                          is_main_admin=is_main_admin,
                          challenges_locked=challenges_locked)


@app.route('/admin/toggle_challenges', methods=['GET', 'POST'])
@login_required
def toggle_challenges():
    # Verificar se é um administrador
    if not session.get('is_admin', False):
        flash('Acesso restrito a administradores.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        action = request.form.get('action')
        senha = request.form.get('senha', '')
        
        if senha != '123':
            conn.close()
            flash('Senha incorreta! Operação não autorizada.', 'error')
            return redirect(url_for('toggle_challenges'))
        
        if action == 'lock':
            conn.execute('UPDATE system_settings SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?', 
                       ('true', 'challenges_locked'))
            conn.commit()
            flash('Criação de desafios BLOQUEADA com sucesso!', 'success')
        elif action == 'unlock':
            conn.execute('UPDATE system_settings SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?', 
                       ('false', 'challenges_locked'))
            conn.commit()
            flash('Criação de desafios LIBERADA com sucesso!', 'success')
    
    # Obter status atual
    setting = conn.execute('SELECT value, updated_at FROM system_settings WHERE key = ?', ('challenges_locked',)).fetchone()
    is_locked = setting and setting['value'] == 'true'
    updated_at = setting['updated_at'] if setting else None
    
    conn.close()
    
    return render_template('toggle_challenges.html', is_locked=is_locked, updated_at=updated_at)



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
    
    # Verificar se é um admin
    is_admin = session.get('is_admin', False)
    if not is_admin:
        conn.close()
        flash('Apenas administradores podem excluir desafios.', 'error')
        return redirect(url_for('challenge_detail', challenge_id=challenge_id))
    
    # Obter o motivo da exclusão
    admin_delete_reason = request.form.get('admin_delete_reason', '')
    
    # Registrar a ação de exclusão em um log
    try:
        # Verificar se a tabela de logs existe
        table_exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='challenge_logs'").fetchone()
        
        if not table_exists:
            # Criar a tabela se não existir
            conn.execute('''
                CREATE TABLE challenge_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    challenge_id INTEGER,
                    user_id TEXT NOT NULL,
                    modified_by TEXT NOT NULL,
                    old_status TEXT,
                    new_status TEXT,
                    old_result TEXT,
                    new_result TEXT,
                    notes TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
        
        # Inserir o log de exclusão
        current_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        conn.execute('''
            INSERT INTO challenge_logs 
            (challenge_id, user_id, modified_by, old_status, new_status, old_result, new_result, notes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            challenge_id, 
            session.get('user_id', 'unknown'),
            "Admin",
            challenge['status'],
            "DELETED",
            challenge['result'],
            None,
            f"Desafio excluído. Motivo: {admin_delete_reason}",
            current_datetime
        ))
        
    except Exception as e:
        print(f"Erro ao registrar log de exclusão: {e}")
        # Continuar mesmo se o log falhar
    
    # Verificar se o desafio já afetou o ranking
    if challenge['status'] == 'completed' and challenge['result']:
        # Buscar histórico relacionado a este desafio
        history = conn.execute('SELECT * FROM ranking_history WHERE challenge_id = ?', (challenge_id,)).fetchall()
        
        if history:
            # Reverter as alterações no ranking
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
    admin_notes = request.form.get('admin_notes', '')
    is_admin_action = request.form.get('modified_by_admin') == 'true'
    
    conn = get_db_connection()
    
    # Verificar se o desafio existe
    challenge = conn.execute('SELECT * FROM challenges WHERE id = ?', (challenge_id,)).fetchone()
    
    if not challenge:
        conn.close()
        flash('Desafio não encontrado!', 'error')
        return redirect(url_for('challenges_calendar'))
    
    # Verificar permissões
    is_admin = session.get('is_admin', False)
    is_challenger = challenge['challenger_id'] == session.get('user_id')
    is_challenged = challenge['challenged_id'] == session.get('user_id')
    
    # Registrar quem fez a alteração para fins de auditoria
    modified_by = "Admin" if is_admin else "Desafiante" if is_challenger else "Desafiado" if is_challenged else "Desconhecido"
    current_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Verificar se a alteração é permitida
    if not (is_admin or is_challenger or is_challenged):
        conn.close()
        flash('Você não tem permissão para modificar este desafio.', 'error')
        return redirect(url_for('challenge_detail', challenge_id=challenge_id))
    
    # Verificações específicas por status
    if status == 'accepted' and not (is_admin or is_challenged):
        conn.close()
        flash('Apenas o desafiado ou um administrador pode aceitar um desafio.', 'error')
        return redirect(url_for('challenge_detail', challenge_id=challenge_id))
    
    # Para qualquer mudança de status para 'completed', apenas admin ou participantes podem fazer
    if status == 'completed':
        if not (is_admin or is_challenger or is_challenged):
            conn.close()
            flash('Apenas participantes do desafio ou administradores podem marcar um desafio como concluído.', 'error')
            return redirect(url_for('challenge_detail', challenge_id=challenge_id))
    
    # Criar log da alteração
    log_message = f"Status alterado de '{challenge['status']}' para '{status}'"
    if result:
        log_message += f", resultado: '{result}'"
    if admin_notes:
        log_message += f", observações: '{admin_notes}'"
    
    # Armazenar log em uma tabela de histórico de alterações
    try:
        # Verificar se a tabela challenge_logs existe
        table_exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='challenge_logs'").fetchone()
        
        if not table_exists:
            # Criar a tabela se não existir
            conn.execute('''
                CREATE TABLE challenge_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    challenge_id INTEGER NOT NULL,
                    user_id TEXT NOT NULL,
                    modified_by TEXT NOT NULL,
                    old_status TEXT,
                    new_status TEXT,
                    old_result TEXT,
                    new_result TEXT,
                    notes TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (challenge_id) REFERENCES challenges(id)
                )
            ''')
            print("Tabela challenge_logs criada com sucesso.")
        
        # Inserir o log
        conn.execute('''
            INSERT INTO challenge_logs 
            (challenge_id, user_id, modified_by, old_status, new_status, old_result, new_result, notes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            challenge_id, 
            session.get('user_id', 'unknown'),
            modified_by,
            challenge['status'],
            status,
            challenge['result'],
            result,
            admin_notes,
            current_datetime
        ))
        
    except Exception as e:
        print(f"Erro ao registrar log: {e}")
        # Continuar mesmo se o log falhar
    
    # Processar o desafio conforme o status
    if status == 'completed' and result:
        # Processar o resultado do desafio (alterando a pirâmide)
        process_challenge_result(conn, challenge_id, status, result)
        flash('Status do desafio atualizado para Concluído e ranking atualizado.', 'success')
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
    
    # Determinar explicitamente se o usuário está vendo seu próprio perfil
    # Método muito mais robusto para verificar se é o próprio jogador
    is_own_profile = False
    is_admin = session.get('is_admin', False)
    
    try:
        user_id = session.get('user_id')
        
        # Verificar se é um admin (o ID pode ser no formato 'admin_1')
        if isinstance(user_id, str) and user_id.startswith('admin_'):
            is_own_profile = False
        elif isinstance(user_id, int):
            is_own_profile = user_id == player_id
        elif isinstance(user_id, str) and user_id.isdigit():
            is_own_profile = int(user_id) == player_id
    except (ValueError, TypeError, AttributeError):
        is_own_profile = False
    
    # Log para depuração - remova depois que o problema for resolvido
    print(f"Acesso ao perfil - player_id: {player_id}, user_id: {session.get('user_id')}, is_own_profile: {is_own_profile}, is_admin: {is_admin}")
    
    conn.close()
    
    return render_template('player_detail.html', 
                         player=player, 
                         challenges_as_challenger=challenges_as_challenger,
                         challenges_as_challenged=challenges_as_challenged,
                         history=history,
                         potential_challenges=potential_challenges,
                         is_own_profile=is_own_profile,  # Passar explicitamente
                         is_admin=is_admin)  # Passar explicitamente

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
    
    # Cálculo de dias restantes para resposta
    days_remaining = None
    expired = False
    
    if challenge['status'] == 'pending' and challenge['response_deadline']:
        # Converter a string de data para objeto datetime e extrair só a data
        try:
            deadline_obj = datetime.strptime(challenge['response_deadline'], '%Y-%m-%d %H:%M:%S')
            deadline_date = deadline_obj.date()
            today_date = datetime.now().date()
            
            # Calcular diferença em dias (considerando apenas datas, sem horários)
            delta = (deadline_date - today_date).days
            days_remaining = delta
            
            # Se negativo ou zero, o prazo expirou
            expired = days_remaining < 0
            
            # Ajustar para exibição se for negativo
            if expired:
                days_remaining = abs(days_remaining)
        except Exception as e:
            print(f"Erro ao calcular dias restantes: {str(e)}")
            days_remaining = None
    
    return render_template('challenge_detail.html', 
                          challenge=challenge, 
                          days_remaining=days_remaining,
                          expired=expired)

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

# Função para gerar automaticamente um novo player_code
def generate_player_code(conn):
    """
    Gera um novo código de jogador único no formato 'LOG1' + número sequencial de 2 dígitos
    baseado no maior código existente no banco de dados.
    
    Args:
        conn: Conexão com o banco de dados
    
    Returns:
        str: Novo código de jogador no formato 'LOG100', 'LOG101', etc.
    """
    # Buscar o maior código de jogador atual
    result = conn.execute('''
        SELECT player_code FROM players 
        WHERE player_code LIKE 'LOG1%' 
        ORDER BY CAST(SUBSTR(player_code, 5) AS INTEGER) DESC
        LIMIT 1
    ''').fetchone()
    
    if result and result['player_code']:
        # Se existir algum código, extrair o número e incrementar
        current_code = result['player_code']
        try:
            # Remover o prefixo 'LOG1' e converter para inteiro
            # Tratar apenas caracteres numéricos após o prefixo
            numeric_part = ''.join(filter(str.isdigit, current_code[4:]))
            if numeric_part:
                current_number = int(numeric_part)
                # Incrementar o número e gerar o novo código com 2 dígitos
                new_number = current_number + 1
            else:
                # Se não houver parte numérica válida, começar do 0
                new_number = 0
            
            new_code = f"LOG1{new_number:02d}"  # Formata como 2 dígitos (00, 01, etc.)
        except (ValueError, IndexError):
            # Caso haja algum problema ao extrair o número, começar do 0
            new_code = "LOG100"
    else:
        # Se não existir nenhum código, começar do 0
        new_code = "LOG100"
    
    # Verificar se o código já existe (para evitar duplicatas)
    existing = conn.execute('SELECT COUNT(*) as count FROM players WHERE player_code = ?', 
                           (new_code,)).fetchone()
    
    if existing and existing['count'] > 0:
        # Se já existe, incrementar até encontrar um código disponível
        base_number = int(new_code[4:])
        while True:
            base_number += 1
            test_code = f"LOG1{base_number:02d}"
            check = conn.execute('SELECT COUNT(*) as count FROM players WHERE player_code = ?', 
                               (test_code,)).fetchone()
            if not check or check['count'] == 0:
                return test_code
    
    return new_code


@app.route('/add_player', methods=['GET', 'POST'])
def add_player():
    """
    Adiciona um novo jogador ao sistema, colocando-o na última posição do ranking.
    Agora inclui a seleção de país/nacionalidade.
    
    GET: Mostra formulário para adicionar jogador
    POST: Processa a adição do jogador
    """
    if request.method == 'POST':
        # Obter dados do formulário
        name = request.form.get('name', '').strip()
        hcp_index = request.form.get('hcp_index', '').strip()
        email = request.form.get('email', '').strip()
        country = request.form.get('country', 'Brasil').strip()  # Nova linha: obter país do formulário
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
            
            # Gerar automaticamente um novo player_code
            player_code = generate_player_code(conn)
            
            # Determinar a última posição do ranking
            last_pos_result = conn.execute('SELECT MAX(position) as max_pos FROM players WHERE active = 1').fetchone()
            last_pos = last_pos_result['max_pos'] if last_pos_result and last_pos_result['max_pos'] is not None else 0
            new_position = last_pos + 1
            
            # Garantir que a posição seja um inteiro válido
            if not isinstance(new_position, int) or new_position <= 0:
                new_position = 1
            
            # Determinar o tier com base na posição
            new_tier = get_tier_from_position(new_position)
            
            # Converter hcp_index para float se fornecido, ou 0 se vazio
            hcp_index_val = 0  # Valor padrão quando vazio
            if hcp_index:
                try:
                    hcp_index_val = float(hcp_index.replace(',', '.'))
                except ValueError:
                    # Se não for um número válido, deixar como 0
                    pass
            
            # Verificar quais colunas existem na tabela
            columns_info = conn.execute('PRAGMA table_info(players)').fetchall()
            column_names = [col[1] for col in columns_info]
            
            # Construir a query dinamicamente com base nas colunas existentes
            columns = ['name', 'active', 'position', 'tier', 'player_code']
            values = [name, 1, new_position, new_tier, player_code]
            
            if 'hcp_index' in column_names:
                columns.append('hcp_index')
                values.append(hcp_index_val)
            
            if 'email' in column_names and email:
                columns.append('email')
                values.append(email)
            
            if 'country' in column_names:  # Nova verificação para coluna de país
                columns.append('country')
                values.append(country)
            
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
            flash(f'Jogador "{name}" adicionado com sucesso na posição {new_position} (Tier {new_tier}) com código {player_code}!', 'success')
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
        
        # Atualizar o HCP do jogador com a data atual
        conn.execute('UPDATE players SET hcp_index = ?, hcp_last_update = CURRENT_TIMESTAMP WHERE id = ?', (hcp_value, player_id))
        
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


# Função para verificar e criar tabela de histórico diário
def create_daily_history_table():
    # código existente...
    print("Tabela de histórico diário criada com sucesso.")

# Função para verificar e adicionar a coluna response_deadline na tabela challenges
# Função para verificar e adicionar a coluna response_deadline na tabela challenges
def add_response_deadline_column():
    conn = get_db_connection()
    
    # Verificar se a coluna response_deadline existe
    columns_info = conn.execute('PRAGMA table_info(challenges)').fetchall()
    column_names = [col[1] for col in columns_info]
    
    if 'response_deadline' not in column_names:
        # Adicionar coluna de prazo de resposta
        conn.execute('ALTER TABLE challenges ADD COLUMN response_deadline DATETIME')
        print("Coluna 'response_deadline' adicionada à tabela challenges.")
        
        # Definir prazo de resposta para desafios existentes (7 dias após a criação, até 23:59:59)
        conn.execute('''
            UPDATE challenges 
            SET response_deadline = date(created_at, '+7 days') || ' 23:59:59'
            WHERE status = 'pending' AND response_deadline IS NULL
        ''')
        print("Prazo de resposta definido para desafios pendentes existentes.")
    
    conn.commit()
    conn.close()


# Adicione esta nova rota ao seu arquivo app.py

@app.route('/admin/challenge_logs')
@login_required
def admin_challenge_logs():
    # Verificar se é um administrador
    if not session.get('is_admin', False):
        flash('Acesso restrito a administradores.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    
    # Consulta básica, sem JOINs para começo
    try:
        # Verificar se a tabela de logs existe
        table_exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='challenge_logs'").fetchone()
        
        if not table_exists:
            # Criar a tabela se não existir
            conn.execute('''
                CREATE TABLE challenge_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    challenge_id INTEGER,
                    user_id TEXT NOT NULL,
                    modified_by TEXT NOT NULL,
                    old_status TEXT,
                    new_status TEXT,
                    old_result TEXT,
                    new_result TEXT,
                    notes TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()
            
        # Consulta simplificada
        logs = conn.execute('SELECT * FROM challenge_logs ORDER BY created_at DESC LIMIT 100').fetchall()
        
    except Exception as e:
        logs = []
        flash(f'Erro ao carregar logs: {str(e)}', 'error')
    
    conn.close()
    
    return render_template('admin_challenge_logs.html', logs=logs, users=[])


@app.route('/privacy-policy')
def privacy_policy():
    """Página de Política de Privacidade e LGPD"""
    return render_template('privacy_policy.html')


@app.route('/data-export')
@login_required
def data_export():
    """Permite que o usuário baixe seus dados pessoais"""
    # Apenas usuário logado pode acessar seus próprios dados
    user_id = session.get('user_id')
    
    conn = get_db_connection()
    
    # Obter dados do jogador
    player_data = conn.execute('SELECT * FROM players WHERE id = ?', (user_id,)).fetchone()
    
    # Obter histórico de desafios
    challenges_as_challenger = conn.execute('''
        SELECT * FROM challenges WHERE challenger_id = ?
    ''', (user_id,)).fetchall()
    
    challenges_as_challenged = conn.execute('''
        SELECT * FROM challenges WHERE challenged_id = ?
    ''', (user_id,)).fetchall()
    
    # Obter histórico de rankings
    ranking_history = conn.execute('''
        SELECT * FROM ranking_history WHERE player_id = ?
    ''', (user_id,)).fetchall()
    
    conn.close()
    
    # Converter para formato JSON
    data = {
        'player_info': dict(player_data) if player_data else None,
        'challenges_as_challenger': [dict(row) for row in challenges_as_challenger],
        'challenges_as_challenged': [dict(row) for row in challenges_as_challenged],
        'ranking_history': [dict(row) for row in ranking_history]
    }
    
    # Criar resposta para download
    response = make_response(json.dumps(data, default=str, indent=4))
    response.headers["Content-Disposition"] = f"attachment; filename=data_export_{user_id}.json"
    response.headers["Content-Type"] = "application/json"
    
    return response

@app.route('/request-data-deletion', methods=['GET', 'POST'])
@login_required
def request_data_deletion():
    """Solicitar exclusão de dados pessoais"""
    if request.method == 'POST':
        # Implementação para lidar com a solicitação
        # Talvez envie um e-mail para o administrador ou marque o usuário
        # para exclusão futura
        
        flash('Sua solicitação de exclusão de dados foi recebida. Entraremos em contato em até 15 dias úteis.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('request_data_deletion.html')



# Adicione esta nova rota ao seu arquivo app.py

# Adicione esta nova rota ao arquivo app.py

@app.route('/player/update_self_hcp', methods=['POST'])
@login_required
def update_self_hcp():
    """
    Permite que um jogador atualize seu próprio HCP Index sem necessidade de senha
    """
    # Obter o ID do jogador autenticado
    player_id = session.get('user_id')
    if not player_id or session.get('is_admin', False):
        flash('Acesso não autorizado.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    
    # Verificar se o jogador existe e está ativo
    player = conn.execute('SELECT * FROM players WHERE id = ? AND active = 1', (player_id,)).fetchone()
    
    if not player:
        conn.close()
        flash('Jogador não encontrado ou inativo!', 'error')
        return redirect(url_for('dashboard'))
    
    # Obter novo HCP do formulário
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
        
        # Atualizar o HCP do jogador com a data atual
        conn.execute('UPDATE players SET hcp_index = ?, hcp_last_update = CURRENT_TIMESTAMP WHERE id = ?', (hcp_value, player_id))
        
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
        
        # Registrar a atualização no log de alterações
        now = datetime.now().strftime('%d/%m/%Y')
        log_message = f"HCP Index atualizado pelo próprio jogador de '{old_hcp or 'não informado'}' para '{new_hcp or 'não informado'}' em {now}"
        
        # Atualizar notas se a coluna existir
        if player['notes']:
            notes = f"{player['notes']} | {log_message}"
        else:
            notes = log_message
        
        conn.execute('UPDATE players SET notes = ? WHERE id = ?', (notes, player_id))
        
        # Registrar a alteração no histórico de HCP, se a função existir
        old_hcp_value = float(old_hcp.replace(',', '.')) if old_hcp and old_hcp.strip() else None
        try:
            # Verifique se a função record_hcp_change existe
            if 'record_hcp_change' in globals():
                record_hcp_change(player_id, old_hcp_value, hcp_value, 'player')
        except Exception as e:
            print(f"Erro ao registrar histórico de HCP: {e}")
        
        conn.commit()
        flash('Seu HCP Index foi atualizado com sucesso!', 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao atualizar o HCP: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('player_detail', player_id=player_id))


@app.route('/add_hcp_last_update_column')
def add_hcp_last_update_column():
    conn = get_db_connection()
    
    # Verificar se a coluna já existe
    columns_info = conn.execute('PRAGMA table_info(players)').fetchall()
    column_names = [col[1] for col in columns_info]
    
    if 'hcp_last_update' not in column_names:
        conn.execute('ALTER TABLE players ADD COLUMN hcp_last_update DATETIME')
        conn.commit()
        result = "Coluna 'hcp_last_update' adicionada com sucesso."
    else:
        result = "Coluna 'hcp_last_update' já existe."
    
    conn.close()
    return result


@app.route('/reset_player_password/<int:player_id>', methods=['POST'])
@login_required
def reset_player_password(player_id):
    """
    Permite que um administrador resete a senha de um jogador para o padrão (3 primeiras letras do nome)
    """
    # Verificar se é administrador
    if not session.get('is_admin', False):
        flash('Acesso restrito a administradores.', 'error')
        return redirect(url_for('dashboard'))
    
    # Verificar senha de admin
    senha = request.form.get('senha', '')
    if senha != '123':
        flash('Senha incorreta! Operação não autorizada.', 'error')
        return redirect(url_for('player_detail', player_id=player_id))
    
    conn = get_db_connection()
    
    # Buscar informações do jogador
    player = conn.execute('SELECT * FROM players WHERE id = ?', (player_id,)).fetchone()
    
    if not player:
        conn.close()
        flash('Jogador não encontrado!', 'error')
        return redirect(url_for('index'))
    
    # Definir nova senha como as 3 primeiras letras do nome em minúsculas
    default_password = player['name'].strip().lower()[:3]
    hashed_password = hash_password(default_password)
    
    # Atualizar a senha
    conn.execute('UPDATE players SET password = ? WHERE id = ?', 
                (hashed_password, player_id))
    
    conn.commit()
    conn.close()
    
    flash(f'Senha do jogador {player["name"]} resetada com sucesso! A nova senha é: {default_password}', 'success')
    return redirect(url_for('player_detail', player_id=player_id))




def add_country_column():
    conn = get_db_connection()
    
    # Verificar se a coluna já existe
    columns_info = conn.execute('PRAGMA table_info(players)').fetchall()
    column_names = [col[1] for col in columns_info]
    
    if 'country' not in column_names:
        conn.execute('ALTER TABLE players ADD COLUMN country TEXT DEFAULT NULL')
        conn.commit()
        print("Coluna 'country' adicionada à tabela players com valor padrão NULL.")
    else:
        print("Coluna 'country' já existe na tabela players.")
    
    conn.close()



# Adicione este código ao app.py para criar um filtro personalizado

@app.template_filter('country_code')
def country_code_filter(country_name):
    """
    Converte o nome do país para o código ISO de 2 letras usado para exibir bandeiras.
    """
    # Mapeamento de nomes de países para códigos ISO de 2 letras
    country_mapping = {
        'Brasil': 'br',
        'Argentina': 'ar',
        'Portugal': 'pt',
        'Estados Unidos': 'us',
        'Espanha': 'es',
        'Itália': 'it',
        'França': 'fr',
        'Alemanha': 'de',
        'Reino Unido': 'gb',
        'Inglaterra': 'gb-eng',
        'Escócia': 'gb-sct',
        'País de Gales': 'gb-wls',
        'Irlanda do Norte': 'gb-nir',
        'Japão': 'jp',
        'Coreia do Sul': 'kr',
        'China': 'cn',
        'Austrália': 'au',
        'Canadá': 'ca',
        'México': 'mx',
        'Chile': 'cl',
        'Colômbia': 'co',
        'Uruguai': 'uy',
        'Paraguai': 'py',
        'Peru': 'pe',
        'Venezuela': 've',
        'África do Sul': 'za',
        'Suíça': 'ch',
        'Suécia': 'se',
        'Noruega': 'no',
        'Dinamarca': 'dk',
        'Holanda': 'nl',
        'Países Baixos': 'nl',
        'Bélgica': 'be',
        'Irlanda': 'ie',
        'Nova Zelândia': 'nz',
        'Índia': 'in',
        'Rússia': 'ru',
        'Polônia': 'pl',
        'Áustria': 'at',
        'Grécia': 'gr',
        'Turquia': 'tr'
    }
    
    # Retorna o código ISO ou o nome do país em minúsculas como fallback
    return country_mapping.get(country_name, country_name.lower())


@app.route('/regulamento')
def regulamento():
    return render_template('regulamento.html')


@app.route('/relatorio')
def relatorio():
    return render_template('relatorio.html')


@app.route('/admin/create_admin', methods=['GET', 'POST'])
@login_required
def create_admin():
    # Verificar se é um administrador
    if not session.get('is_admin', False):
        flash('Acesso restrito a administradores.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Obter dados do formulário
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        admin_password = request.form.get('admin_password', '').strip()
        
        # Validar campos obrigatórios
        if not username or not password or not name:
            flash('Campos obrigatórios não preenchidos.', 'error')
            return redirect(url_for('create_admin'))
        
        # Verificar senha do admin atual
        if admin_password != '123':
            flash('Senha de administrador incorreta! Operação não autorizada.', 'error')
            return redirect(url_for('create_admin'))
        
        # Verificar se as senhas coincidem
        if password != confirm_password:
            flash('A senha e a confirmação não coincidem.', 'error')
            return redirect(url_for('create_admin'))
        
        conn = get_db_connection()
        
        try:
            # Verificar se o nome de usuário já existe
            existing_admin = conn.execute('SELECT * FROM admins WHERE username = ?', (username,)).fetchone()
            
            if existing_admin:
                conn.close()
                flash(f'O nome de usuário "{username}" já está em uso. Escolha outro.', 'error')
                return redirect(url_for('create_admin'))
            
            # Criar o hash da senha - verificar a implementação
            hashed_password = hash_password(password)
            
            # Imprimir para debug (remover em produção)
            print(f"Criando admin: {username}, Senha original: {password}, Hash: {hashed_password}")
            
            # Inserir o novo administrador
            conn.execute('''
                INSERT INTO admins (username, password, name, email, created_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (username, hashed_password, name, email))
            
            # Registrar em log para debug (opcional)
            conn.execute('''
                INSERT INTO system_settings (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (f"admin_creation_{username}", f"Admin {name} criado em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
            
            conn.commit()
            flash(f'Administrador "{name}" criado com sucesso! Use o nome de usuário "{username}" para login.', 'success')
            
            # Listar administradores para verificação
            admins = conn.execute('SELECT username, password FROM admins').fetchall()
            print("Lista de admins no banco:")
            for admin in admins:
                print(f"Username: {admin['username']}, Hash senha: {admin['password']}")
            
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            conn.rollback()
            flash(f'Erro ao criar administrador: {str(e)}', 'error')
        finally:
            conn.close()
        
        return redirect(url_for('create_admin'))
    
    # Para requisição GET, mostrar formulário
    return render_template('create_admin.html')



# Rota para listar todos os administradores
@app.route('/admin/list_admins')
@login_required
def list_admins():
    # Verificar se é um administrador
    if not session.get('is_admin', False):
        flash('Acesso restrito a administradores.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    admins = conn.execute('SELECT id, username, name, email, created_at, last_login FROM admins ORDER BY name').fetchall()
    conn.close()
    
    return render_template('list_admins.html', admins=admins)


@app.route('/admin/fix_admin_passwords', methods=['GET', 'POST'])
@login_required
def fix_admin_passwords():
    # Verificar se é um administrador
    if not session.get('is_admin', False):
        flash('Acesso restrito a administradores.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        admin_password = request.form.get('admin_password', '')
        
        # Verificar senha do admin atual
        if admin_password != '123':
            conn.close()
            flash('Senha de administrador incorreta! Operação não autorizada.', 'error')
            return redirect(url_for('fix_admin_passwords'))
        
        # Obter todos os administradores
        admins = conn.execute('SELECT id, username FROM admins WHERE username != "admin"').fetchall()
        
        # Redefinir as senhas para os nomes de usuário
        for admin in admins:
            # A nova senha será o próprio nome de usuário
            new_password = admin['username']
            hashed_password = hash_password(new_password)
            
            # Atualizar a senha
            conn.execute('UPDATE admins SET password = ? WHERE id = ?', (hashed_password, admin['id']))
            
            # Registrar a alteração
            print(f"Redefinida senha do admin {admin['username']}: {new_password} -> {hashed_password}")
        
        conn.commit()
        flash('As senhas de todos os administradores foram redefinidas. A nova senha é igual ao nome de usuário.', 'success')
        return redirect(url_for('list_admins'))
    
    # Para requisição GET, mostrar formulário
    return render_template('fix_admin_passwords.html')


@app.route('/admin/reset_admin_password/<int:admin_id>', methods=['POST'])
@login_required
def reset_admin_password(admin_id):
    # Verificar se é um administrador
    if not session.get('is_admin', False):
        flash('Acesso restrito a administradores.', 'error')
        return redirect(url_for('dashboard'))
    
    admin_password = request.form.get('admin_password', '')
    
    # Verificar senha do admin atual
    if admin_password != '123':
        flash('Senha incorreta! Operação não autorizada.', 'error')
        return redirect(url_for('list_admins'))
    
    conn = get_db_connection()
    
    try:
        # Buscar o admin a ter a senha resetada
        admin = conn.execute('SELECT * FROM admins WHERE id = ?', (admin_id,)).fetchone()
        
        if not admin:
            conn.close()
            flash('Administrador não encontrado.', 'error')
            return redirect(url_for('list_admins'))
        
        # Não permitir resetar a senha do admin principal
        if admin['username'] == 'admin':
            conn.close()
            flash('Não é possível resetar a senha do administrador principal.', 'error')
            return redirect(url_for('list_admins'))
        
        # A nova senha será o próprio nome de usuário
        new_password = admin['username']
        hashed_password = hash_password(new_password)
        
        # Atualizar a senha
        conn.execute('UPDATE admins SET password = ? WHERE id = ?', (hashed_password, admin_id))
        conn.commit()
        
        flash(f'Senha de {admin["name"]} resetada com sucesso. A nova senha é: {new_password}', 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao resetar senha: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('list_admins'))



@app.route('/admin/delete_admin/<int:admin_id>', methods=['GET', 'POST'])
@login_required
def delete_admin(admin_id):
    # Verificar se é um administrador
    if not session.get('is_admin', False):
        flash('Acesso restrito a administradores.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    
    # Buscar o admin a ser excluído
    admin = conn.execute('SELECT * FROM admins WHERE id = ?', (admin_id,)).fetchone()
    
    if not admin:
        conn.close()
        flash('Administrador não encontrado!', 'error')
        return redirect(url_for('list_admins'))
    
    # Verificar se é o admin principal (não pode ser excluído)
    if admin['username'] == 'admin':
        conn.close()
        flash('O administrador principal não pode ser excluído.', 'error')
        return redirect(url_for('list_admins'))
    
    # Verificar se é o próprio usuário tentando se excluir
    admin_current_id = session.get('user_id', '').split('_')[1] if isinstance(session.get('user_id', ''), str) else None
    if admin_current_id and int(admin_current_id) == admin_id:
        conn.close()
        flash('Você não pode excluir sua própria conta de administrador.', 'error')
        return redirect(url_for('list_admins'))
    
    # Para requisição GET, mostrar tela de confirmação
    if request.method == 'GET':
        conn.close()
        return render_template('delete_admin.html', admin=admin)
    
    # Para requisição POST, processar a exclusão
    senha = request.form.get('admin_password', '')
    confirm_delete = request.form.get('confirm_delete', 'no') == 'yes'
    
    if senha != '123':
        conn.close()
        flash('Senha incorreta! Operação não autorizada.', 'error')
        return redirect(url_for('delete_admin', admin_id=admin_id))
    
    if not confirm_delete:
        conn.close()
        flash('Você precisa confirmar a exclusão marcando a caixa de confirmação.', 'error')
        return redirect(url_for('delete_admin', admin_id=admin_id))
    
    try:
        # Registrar a ação de exclusão em um log
        conn.execute('''
            INSERT INTO system_settings (key, value, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
        ''', (f"admin_deletion_{admin['username']}", f"Admin {admin['name']} excluído em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} pelo administrador {session.get('username', 'desconhecido')}"))
        
        # Excluir o administrador
        conn.execute('DELETE FROM admins WHERE id = ?', (admin_id,))
        
        conn.commit()
        flash(f'Administrador "{admin["name"]}" (username: {admin["username"]}) foi excluído com sucesso.', 'success')
        
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao excluir administrador: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('list_admins'))

def add_profile_photo_column():
    conn = get_db_connection()
    
    # Verificar se a coluna já existe
    columns_info = conn.execute('PRAGMA table_info(players)').fetchall()
    column_names = [col[1] for col in columns_info]
    
    if 'profile_photo' not in column_names:
        conn.execute('ALTER TABLE players ADD COLUMN profile_photo TEXT DEFAULT NULL')
        conn.commit()
        print("Coluna 'profile_photo' adicionada à tabela players com valor padrão NULL.")
    else:
        print("Coluna 'profile_photo' já existe na tabela players.")
    
    conn.close()


# Rota para a página Golf Business
@app.route('/golf-business')
def golf_business():
    conn = get_db_connection()
    businesses = conn.execute('''
        SELECT b.*, p.name as owner_name, p.profile_photo as owner_photo
        FROM businesses b
        JOIN players p ON b.player_id = p.id
        WHERE b.active = 1
        ORDER BY b.created_at DESC
    ''').fetchall()
    conn.close()
    
    return render_template('golf_business.html', businesses=businesses)

# Rota para processamento do formulário de adição de negócio
@app.route('/add-business', methods=['POST'])
@login_required
def add_business():
    # Verificar se é administrador
    if not session.get('is_admin', False):
        flash('Apenas administradores podem adicionar negócios.', 'error')
        return redirect(url_for('golf_business'))
    
    if request.method == 'POST':
        try:
            # Obter dados do formulário
            player_id = request.form.get('player_id')
            business_name = request.form.get('business_name')
            business_category = request.form.get('business_category')
            business_description = request.form.get('business_description')
            business_contact = request.form.get('business_contact')
            
            # Validar campos obrigatórios
            if not player_id or not business_name or not business_category or not business_description:
                flash('Todos os campos obrigatórios devem ser preenchidos.', 'error')
                return redirect(url_for('admin_business'))
                
            # Processar imagem
            if 'business_image' in request.files:
                file = request.files['business_image']
                if file and allowed_file(file.filename):
                    # Gerar nome de arquivo seguro
                    filename = secure_filename(f"business_{player_id}_{int(datetime.now().timestamp())}.{file.filename.rsplit('.', 1)[1].lower()}")
                    
                    # Criar diretório se não existir
                    business_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'business_images')
                    os.makedirs(business_upload_folder, exist_ok=True)
                    
                    # Salvar arquivo
                    file_path = os.path.join(business_upload_folder, filename)
                    file.save(file_path)
                    
                    # Salvar no banco de dados
                    conn = get_db_connection()
                    conn.execute('''
                        INSERT INTO businesses 
                        (player_id, name, category, description, image_path, contact_info, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ''', (
                        player_id,
                        business_name,
                        business_category,
                        business_description,
                        filename,
                        business_contact
                    ))
                    
                    conn.commit()
                    conn.close()
                    
                    flash('Negócio cadastrado com sucesso!', 'success')
                    return redirect(url_for('admin_business'))
                else:
                    flash('Tipo de arquivo não permitido. Use apenas JPG, PNG ou GIF.', 'error')
            else:
                flash('Imagem é obrigatória para cadastro do negócio.', 'error')
        
        except Exception as e:
            flash(f'Erro ao cadastrar negócio: {str(e)}', 'error')
        
        return redirect(url_for('admin_business'))


@app.route('/admin/delete-business/<int:business_id>', methods=['POST'])
@login_required
def delete_business(business_id):
    # Verificar permissão
    if not session.get('is_admin', False):
        flash('Acesso restrito a administradores.', 'error')
        return redirect(url_for('dashboard'))
    
    # Verificar senha
    senha = request.form.get('senha', '')
    if senha != '123':
        flash('Senha incorreta! Operação não autorizada.', 'error')
        return redirect(url_for('admin_business'))
    
    conn = get_db_connection()
    
    try:
        # Obter informações do negócio
        business = conn.execute('SELECT * FROM businesses WHERE id = ?', (business_id,)).fetchone()
        
        if not business:
            conn.close()
            flash('Negócio não encontrado!', 'error')
            return redirect(url_for('admin_business'))
        
        # Marcar como inativo (soft delete)
        conn.execute('UPDATE businesses SET active = 0 WHERE id = ?', (business_id,))
        
        # Opcional: Remover fisicamente a imagem
        if business['image_path']:
            try:
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'business_images', business['image_path'])
                if os.path.exists(image_path):
                    os.remove(image_path)
            except Exception as e:
                print(f"Erro ao remover arquivo de imagem: {e}")
        
        conn.commit()
        flash('Negócio excluído com sucesso!', 'success')
    
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao excluir negócio: {str(e)}', 'error')
    
    finally:
        conn.close()
    
    return redirect(url_for('admin_business'))



@app.route('/api/businesses')
def api_businesses():
    filter_category = request.args.get('filter', 'all')
    
    conn = get_db_connection()
    
    # Consulta base
    query = '''
        SELECT b.*, p.name as owner_name, p.profile_photo as owner_photo
        FROM businesses b
        JOIN players p ON b.player_id = p.id
        WHERE b.active = 1
    '''
    
    # Aplicar filtro se não for "all"
    params = []
    if filter_category != 'all':
        query += ' AND b.category = ?'
        params.append(filter_category)
    
    query += ' ORDER BY b.created_at DESC'
    businesses = conn.execute(query, params).fetchall()
    
    # Converter para formato JSON
    business_list = []
    for b in businesses:
        business_dict = {
            'id': b['id'],
            'name': b['name'],
            'description': b['description'],
            'category': b['category'],
            'image_path': f"/static/profile_photos/business_images/{b['image_path']}" if b['image_path'] else None,
            'contact_info': b['contact_info'],
            'owner_name': b['owner_name'],
            'owner_photo': f"/static/profile_photos/{b['owner_photo']}" if b['owner_photo'] else "/static/profile_photos/default.png"
        }
        business_list.append(business_dict)
    
    conn.close()
    
    # Definir o cabeçalho Content-Type para json
    return jsonify({'businesses': business_list})



@app.route('/admin/business')
@login_required
def admin_business():
    # Verificar permissão de administrador
    if not session.get('is_admin', False):
        flash('Acesso restrito a administradores.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    
    # Buscar todos os negócios
    businesses = conn.execute('''
        SELECT b.*, p.name as owner_name
        FROM businesses b
        JOIN players p ON b.player_id = p.id
        ORDER BY b.created_at DESC
    ''').fetchall()
    
    # Buscar jogadores para o formulário
    players = conn.execute('SELECT id, name FROM players WHERE active = 1 ORDER BY name').fetchall()
    
    conn.close()
    
    return render_template('admin_business.html', businesses=businesses, players=players)



def verify_business_table_structure():
    conn = get_db_connection()
    try:
        # Verificar a definição atual da tabela
        table_info = conn.execute("PRAGMA table_info(businesses)").fetchall()
        
        # Verificar se existe a tabela e os campos necessários
        columns = [col[1] for col in table_info]
        
        # Se a tabela não existir ou estiver faltando o campo description
        if not table_info or 'description' not in columns:
            print("Recriando tabela businesses para suportar descrições maiores...")
            # Se necessário, recriar a tabela preservando dados
            create_business_table()
            
        print("Estrutura da tabela de negócios verificada com sucesso.")
    except Exception as e:
        print(f"Erro ao verificar tabela de negócios: {str(e)}")
    finally:
        conn.close()



@app.route('/admin/edit-business/<int:business_id>', methods=['POST'])
@login_required
def edit_business(business_id):
    # Verificar permissão
    if not session.get('is_admin', False):
        flash('Acesso restrito a administradores.', 'error')
        return redirect(url_for('dashboard'))
    
    # Verificar senha
    senha = request.form.get('senha', '')
    if senha != '123':
        flash('Senha incorreta! Operação não autorizada.', 'error')
        return redirect(url_for('admin_business'))
    
    try:
        # Obter dados do formulário
        player_id = request.form.get('player_id')
        business_name = request.form.get('business_name')
        business_category = request.form.get('business_category')
        business_description = request.form.get('business_description')
        business_contact = request.form.get('business_contact')
        
        # Validar dados
        if not player_id or not business_name or not business_category or not business_description:
            flash('Todos os campos obrigatórios devem ser preenchidos.', 'error')
            return redirect(url_for('admin_business'))
        
        conn = get_db_connection()
        
        # Obter informações do negócio atual
        current_business = conn.execute('SELECT * FROM businesses WHERE id = ?', (business_id,)).fetchone()
        
        if not current_business:
            conn.close()
            flash('Negócio não encontrado!', 'error')
            return redirect(url_for('admin_business'))
        
        # Processar atualização da imagem (se fornecida)
        if 'business_image' in request.files and request.files['business_image'].filename:
            file = request.files['business_image']
            
            if file and allowed_file(file.filename):
                # Gerar nome de arquivo seguro
                filename = secure_filename(f"business_{player_id}_{int(datetime.now().timestamp())}.{file.filename.rsplit('.', 1)[1].lower()}")
                
                # Criar diretório se não existir
                business_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'business_images')
                os.makedirs(business_upload_folder, exist_ok=True)
                
                # Salvar o arquivo
                file_path = os.path.join(business_upload_folder, filename)
                file.save(file_path)
                
                # Remover a imagem antiga, se existir
                if current_business['image_path']:
                    try:
                        old_file_path = os.path.join(business_upload_folder, current_business['image_path'])
                        if os.path.exists(old_file_path):
                            os.remove(old_file_path)
                    except Exception as e:
                        print(f"Erro ao remover imagem antiga: {e}")
                
                # Atualizar com a nova imagem
                conn.execute('''
                    UPDATE businesses
                    SET player_id = ?, name = ?, category = ?, description = ?,
                        contact_info = ?, image_path = ?
                    WHERE id = ?
                ''', (
                    player_id, business_name, business_category,
                    business_description, business_contact, filename, business_id
                ))
            else:
                conn.close()
                flash('Tipo de arquivo não permitido. Use apenas JPG, PNG ou GIF.', 'error')
                return redirect(url_for('admin_business'))
        else:
            # Atualizar sem alterar a imagem
            conn.execute('''
                UPDATE businesses
                SET player_id = ?, name = ?, category = ?, description = ?,
                    contact_info = ?
                WHERE id = ?
            ''', (
                player_id, business_name, business_category,
                business_description, business_contact, business_id
            ))
        
        conn.commit()
        conn.close()
        
        flash('Negócio atualizado com sucesso!', 'success')
        
    except Exception as e:
        flash(f'Erro ao atualizar negócio: {str(e)}', 'error')
    
    return redirect(url_for('admin_business'))


@app.template_filter('nl2br')
def nl2br_filter(text):
    """Converte quebras de linha em tags <br>"""
    if not text:
        return ""
    return text.replace('\n', '<br>')



if __name__ == '__main__':
    # Verificar se o banco de dados existe, caso contrário, importar dados


    # Criar tabela de configurações do sistema
    create_system_settings_table()
    
    # Criar tabela de negócios
    result = create_business_table()
    if not result:
        print("ALERTA: Erro ao criar tabela de negócios!")



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
    
    if 'hcp_last_update' not in column_names:
        print("Adicionando coluna 'hcp_last_update' à tabela players...")
        cursor.execute('ALTER TABLE players ADD COLUMN hcp_last_update DATETIME')
    
    if 'profile_photo' not in column_names:
        print("Adicionando coluna 'profile_photo' à tabela players...")
        cursor.execute('ALTER TABLE players ADD COLUMN profile_photo TEXT DEFAULT NULL')
    
    conn.commit()
    conn.close()

    # Criar a tabela de histórico de HCP
    create_hcp_history_table()
    
    # Criar a tabela de histórico diário se não existir
    create_daily_history_table()
    
    # Adicionar coluna de prazo de resposta à tabela de desafios
    add_response_deadline_column()

    # Adicionar coluna de país se não existir
    add_country_column()

    # Criar tabela de configurações do sistema
    create_system_settings_table()
    
    # Garantir que a pasta para fotos existe
    os.makedirs('static/profile_photos', exist_ok=True)
    
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
    

    create_business_table()

    # Modificação: adicionado argumento host='0.0.0.0' para permitir acesso externo
    app.run(debug=True, host='0.0.0.0')