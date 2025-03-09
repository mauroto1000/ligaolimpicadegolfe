import sqlite3

# Configuração do banco de dados
DATABASE = 'golf_league.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def revert_daily_rankings_import():
    """Remove os registros importados das datas específicas"""
    conn = get_db_connection()
    
    # Datas dos registros a serem removidos (02/03/2025 a 08/03/2025)
    dates = [
        "2025-03-02",  # 02/03/2025
        "2025-03-03",  # 03/03/2025
        "2025-03-04",  # 04/03/2025
        "2025-03-05",  # 05/03/2025
        "2025-03-06",  # 06/03/2025
        "2025-03-07",  # 07/03/2025
        "2025-03-08",  # 08/03/2025
    ]
    
    # Verificar se a tabela existe
    table_exists = conn.execute('''
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='daily_ranking_history'
    ''').fetchone()
    
    if not table_exists:
        print("A tabela 'daily_ranking_history' não existe no banco de dados.")
        conn.close()
        return
    
    # Verificar quantos registros existem para essas datas
    count_before = 0
    for date in dates:
        count = conn.execute('''
            SELECT COUNT(*) as count FROM daily_ranking_history 
            WHERE date_recorded = ?
        ''', (date,)).fetchone()['count']
        count_before += count
        print(f"Registros para {date}: {count}")
    
    print(f"Total de registros a serem removidos: {count_before}")
    
    # Iniciar transação
    conn.execute('BEGIN TRANSACTION')
    
    try:
        # Remover registros para cada data
        for date in dates:
            conn.execute('''
                DELETE FROM daily_ranking_history 
                WHERE date_recorded = ?
            ''', (date,))
            print(f"Removidos registros para: {date}")
        
        # Verificar se todos os registros foram removidos
        count_after = 0
        for date in dates:
            count = conn.execute('''
                SELECT COUNT(*) as count FROM daily_ranking_history 
                WHERE date_recorded = ?
            ''', (date,)).fetchone()['count']
            count_after += count
        
        # Commit da transação
        conn.commit()
        
        print(f"\nReversão concluída!")
        print(f"Registros antes da reversão: {count_before}")
        print(f"Registros após a reversão: {count_after}")
        print(f"Registros removidos: {count_before - count_after}")
        
    except Exception as e:
        # Em caso de erro, reverter todas as alterações
        conn.rollback()
        print(f"ERRO durante a reversão: {str(e)}")
    finally:
        conn.close()

if __name__ == "__main__":
    revert_daily_rankings_import()