#!/usr/bin/env python3
import sqlite3
import hashlib
import os
from datetime import datetime

DATABASE = 'golf_league.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def update_database():
    if not os.path.exists(DATABASE):
        print(f"Erro: Banco de dados '{DATABASE}' não encontrado.")
        return False
    
    print(f"Conectando ao banco de dados '{DATABASE}'...")
    conn = get_db_connection()
    
    try:
        # Verificar colunas existentes na tabela players
        columns_info = conn.execute('PRAGMA table_info(players)').fetchall()
        column_names = [col[1] for col in columns_info]
        
        print("Verificando e adicionando colunas necessárias...")
        
        # Adicionar coluna de senha à tabela players
        if 'password' not in column_names:
            conn.execute('ALTER TABLE players ADD COLUMN password TEXT')
            print("- Coluna 'password' adicionada à tabela players.")
        else:
            print("- Coluna 'password' já existe na tabela players.")
        
        # Adicionar coluna de último login
        if 'last_login' not in column_names:
            conn.execute('ALTER TABLE players ADD COLUMN last_login DATETIME')
            print("- Coluna 'last_login' adicionada à tabela players.")
        else:
            print("- Coluna 'last_login' já existe na tabela players.")
        
        # Adicionar coluna de token de recuperação de senha
        if 'reset_token' not in column_names:
            conn.execute('ALTER TABLE players ADD COLUMN reset_token TEXT')
            print("- Coluna 'reset_token' adicionada à tabela players.")
        else:
            print("- Coluna 'reset_token' já existe na tabela players.")
        
        # Adicionar coluna de data de expiração do token
        if 'reset_token_expiry' not in column_names:
            conn.execute('ALTER TABLE players ADD COLUMN reset_token_expiry DATETIME')
            print("- Coluna 'reset_token_expiry' adicionada à tabela players.")
        else:
            print("- Coluna 'reset_token_expiry' já existe na tabela players.")
        
        # Verificar se a tabela de administradores existe
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='admins'").fetchall()
        
        if not tables:
            print("Criando tabela 'admins'...")
            conn.execute('''
            CREATE TABLE admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                name TEXT NOT NULL,
                email TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # Criar admin padrão (username: admin, senha: 123)
            admin_password = hash_password('123')
            conn.execute('INSERT INTO admins (username, password, name) VALUES (?, ?, ?)', 
                        ('admin', admin_password, 'Administrador'))
            
            print("- Tabela 'admins' criada com usuário admin padrão (senha: 123).")
        else:
            print("- Tabela 'admins' já existe.")
            
            # Verificar se admin padrão existe
            admin = conn.execute('SELECT * FROM admins WHERE username = ?', ('admin',)).fetchone()
            if not admin:
                # Criar admin padrão
                admin_password = hash_password('123')
                conn.execute('INSERT INTO admins (username, password, name) VALUES (?, ?, ?)', 
                            ('admin', admin_password, 'Administrador'))
                print("- Usuário admin padrão criado (senha: 123).")
            else:
                print("- Usuário admin já existe.")
        
        # Definir senhas iniciais para todos os jogadores
        players = conn.execute('SELECT id, name, password FROM players WHERE active = 1').fetchall()
        updated_count = 0
        
        for player in players:
            if not player['password']:
                # Senha inicial: 3 primeiras letras do nome em minúsculas
                default_password = player['name'].strip().lower()[:3]
                hashed_password = hash_password(default_password)
                
                conn.execute('UPDATE players SET password = ? WHERE id = ?', 
                           (hashed_password, player['id']))
                updated_count += 1
        
        if updated_count > 0:
            print(f"- Senhas iniciais definidas para {updated_count} jogadores.")
        else:
            print("- Todos os jogadores já possuem senhas definidas.")
        
        # Commit das alterações
        conn.commit()
        print("\nBanco de dados atualizado com sucesso!")
        return True
    
    except Exception as e:
        conn.rollback()
        print(f"\nErro ao atualizar o banco de dados: {str(e)}")
        return False
    
    finally:
        conn.close()

if __name__ == "__main__":
    print("=== Atualização do Banco de Dados para Autenticação ===")
    update_database()