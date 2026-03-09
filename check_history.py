import sqlite3
from datetime import datetime, timedelta

# Configuração do banco de dados
DATABASE = 'golf_league.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def check_history_data():
    """
    Verifica os dados na tabela de histórico diário para diagnosticar problemas.
    """
    conn = get_db_connection()
    
    print("="*80)
    print("DIAGNÓSTICO DE DADOS DO HISTÓRICO DIÁRIO")
    print("="*80)
    
    # 1. Verificar número total de registros
    total_records = conn.execute('SELECT COUNT(*) as count FROM daily_ranking_history').fetchone()
    print(f"Total de registros na tabela daily_ranking_history: {total_records['count']}")
    
    # 2. Verificar datas distintas registradas
    dates = conn.execute('SELECT DISTINCT date_recorded FROM daily_ranking_history ORDER BY date_recorded').fetchall()
    print(f"Datas distintas registradas: {len(dates)}")
    for i, date in enumerate(dates):
        print(f"  {i+1}. {date['date_recorded']}")
    
    # 3. Verificar jogadores registrados hoje
    today = datetime.now().date().strftime('%Y-%m-%d')
    today_records = conn.execute('''
        SELECT p.name, h.position, h.tier 
        FROM daily_ranking_history h
        JOIN players p ON h.player_id = p.id
        WHERE h.date_recorded = ?
        ORDER BY h.position
    ''', (today,)).fetchall()
    
    print(f"\nRegistros para hoje ({today}): {len(today_records)}")
    for i, record in enumerate(today_records):
        print(f"  {i+1}. {record['name']}: Posição {record['position']} (Tier {record['tier']})")
    
    # 4. Verificar registros para Roberto Maueler
    print("\nHistórico para Roberto Maueler:")
    roberto = conn.execute("SELECT id FROM players WHERE name LIKE '%Roberto Maueler%'").fetchone()
    
    if roberto:
        roberto_id = roberto['id']
        roberto_history = conn.execute('''
            SELECT date_recorded, position, tier 
            FROM daily_ranking_history
            WHERE player_id = ?
            ORDER BY date_recorded
        ''', (roberto_id,)).fetchall()
        
        print(f"  Encontrados {len(roberto_history)} registros")
        for record in roberto_history:
            print(f"  {record['date_recorded']}: Posição {record['position']} (Tier {record['tier']})")
    else:
        print("  Roberto Maueler não encontrado no banco de dados")
    
    # 5. Verificar registros inconsistentes (posição duplicada na mesma data)
    print("\nVerificando possíveis inconsistências:")
    
    for date in [d['date_recorded'] for d in dates]:
        positions = conn.execute('''
            SELECT position, COUNT(*) as count
            FROM daily_ranking_history
            WHERE date_recorded = ?
            GROUP BY position
            HAVING COUNT(*) > 1
        ''', (date,)).fetchall()
        
        if positions:
            print(f"  Data {date}: Posições duplicadas encontradas:")
            for pos in positions:
                print(f"    Posição {pos['position']} aparece {pos['count']} vezes")
                
                # Mostrar detalhes dos jogadores com posição duplicada
                duplicates = conn.execute('''
                    SELECT p.name
                    FROM daily_ranking_history h
                    JOIN players p ON h.player_id = p.id
                    WHERE h.date_recorded = ? AND h.position = ?
                ''', (date, pos['position'])).fetchall()
                
                for dup in duplicates:
                    print(f"      - {dup['name']}")
    
    # 6. Verificar se há jogadores faltando em alguma data
    total_active_players = conn.execute('SELECT COUNT(*) as count FROM players WHERE active = 1').fetchone()['count']
    
    print(f"\nTotal de jogadores ativos atualmente: {total_active_players}")
    print("Verificando se todos os jogadores têm registros em cada data:")
    
    for date in [d['date_recorded'] for d in dates]:
        date_players_count = conn.execute('''
            SELECT COUNT(DISTINCT player_id) as count
            FROM daily_ranking_history
            WHERE date_recorded = ?
        ''', (date,)).fetchone()['count']
        
        if date_players_count != total_active_players:
            print(f"  Data {date}: {date_players_count} jogadores registrados (possível inconsistência)")
    
    # 7. Verificar e listar datas com poucos registros (potencial problema)
    print("\nDatas com número anormal de registros:")
    for date in [d['date_recorded'] for d in dates]:
        date_count = conn.execute('''
            SELECT COUNT(*) as count
            FROM daily_ranking_history
            WHERE date_recorded = ?
        ''', (date,)).fetchone()['count']
        
        if date_count < total_active_players / 2:  # Se menos da metade dos jogadores têm registros
            print(f"  Data {date}: Apenas {date_count} registros (potencial problema)")
            
            # Listar os jogadores registrados nesta data
            players_in_date = conn.execute('''
                SELECT p.name, h.position
                FROM daily_ranking_history h
                JOIN players p ON h.player_id = p.id
                WHERE h.date_recorded = ?
                ORDER BY h.position
            ''', (date,)).fetchall()
            
            for player in players_in_date:
                print(f"    - {player['name']}: Posição {player['position']}")
    
    # 8. Comparar situação atual com o histórico mais recente
    print("\nComparando situação atual com os registros mais recentes:")
    
    latest_date = conn.execute('''
        SELECT MAX(date_recorded) as latest_date
        FROM daily_ranking_history
    ''').fetchone()
    
    if latest_date and latest_date['latest_date']:
        latest = latest_date['latest_date']
        
        # Comparar jogadores ativos com os registrados na data mais recente
        active_players = conn.execute('''
            SELECT id, name, position, tier
            FROM players
            WHERE active = 1
            ORDER BY position
        ''').fetchall()
        
        latest_records = conn.execute('''
            SELECT h.player_id, p.name, h.position, h.tier
            FROM daily_ranking_history h
            JOIN players p ON h.player_id = p.id
            WHERE h.date_recorded = ?
            ORDER BY h.position
        ''', (latest,)).fetchall()
        
        print(f"  Data mais recente no histórico: {latest}")
        print(f"  Jogadores ativos atualmente: {len(active_players)}")
        print(f"  Jogadores com registros na data mais recente: {len(latest_records)}")
        
        # Comparar posições e tiers
        discrepancies = []
        active_ids = [p['id'] for p in active_players]
        latest_ids = [r['player_id'] for r in latest_records]
        
        # Verificar jogadores ativos sem registro na data mais recente
        missing_in_latest = set(active_ids) - set(latest_ids)
        if missing_in_latest:
            print("  Jogadores ativos sem registro na data mais recente:")
            for player_id in missing_in_latest:
                player = conn.execute('SELECT name FROM players WHERE id = ?', (player_id,)).fetchone()
                print(f"    - {player['name']}")
        
        # Verificar jogadores com registros recentes que não estão ativos
        extra_in_latest = set(latest_ids) - set(active_ids)
        if extra_in_latest:
            print("  Jogadores com registro recente que não estão ativos:")
            for player_id in extra_in_latest:
                player = conn.execute('SELECT name FROM players WHERE id = ?', (player_id,)).fetchone()
                print(f"    - {player['name']}")
        
        # Verificar discrepâncias de posição e tier
        for active in active_players:
            # Encontrar o registro correspondente na data mais recente
            latest_record = None
            for record in latest_records:
                if record['player_id'] == active['id']:
                    latest_record = record
                    break
            
            if latest_record:
                # Comparar posição e tier
                if active['position'] != latest_record['position'] or active['tier'] != latest_record['tier']:
                    discrepancies.append({
                        'name': active['name'],
                        'current_position': active['position'],
                        'current_tier': active['tier'],
                        'latest_position': latest_record['position'],
                        'latest_tier': latest_record['tier']
                    })
        
        if discrepancies:
            print("  Discrepâncias entre posições/tiers atuais e mais recentes:")
            for d in discrepancies:
                print(f"    - {d['name']}: Atual={d['current_position']} (Tier {d['current_tier']}), "
                      f"Histórico={d['latest_position']} (Tier {d['latest_tier']})")
        else:
            print("  Sem discrepâncias entre posições/tiers atuais e histórico recente.")
    
    conn.close()
    print("\nDiagnóstico concluído.")

def fix_duplicate_positions():
    """
    Corrige posições duplicadas no histórico diário.
    """
    conn = get_db_connection()
    
    print("="*80)
    print("CORREÇÃO DE POSIÇÕES DUPLICADAS NO HISTÓRICO")
    print("="*80)
    
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
                print(f"Encontradas posições duplicadas em {date}:")
                
                for dup in duplicates:
                    position = dup['position']
                    print(f"  Posição {position} aparece {dup['count']} vezes")
                    
                    # Buscar jogadores com esta posição duplicada
                    players_with_dup = conn.execute('''
                        SELECT h.id, h.player_id, p.name
                        FROM daily_ranking_history h
                        JOIN players p ON h.player_id = p.id
                        WHERE h.date_recorded = ? AND h.position = ?
                        ORDER BY h.id
                    ''', (date, position)).fetchall()
                    
                    # Listar jogadores com a posição duplicada
                    for i, player in enumerate(players_with_dup):
                        print(f"    {i+1}. {player['name']} (ID {player['id']})")
                    
                    # Manter apenas o primeiro registro (o mais antigo) e remover os outros
                    if len(players_with_dup) > 1:
                        for player in players_with_dup[1:]:
                            conn.execute('DELETE FROM daily_ranking_history WHERE id = ?', (player['id'],))
                            print(f"    -> Removido registro para {player['name']}")
                            total_fixed += 1
            
        conn.commit()
        print(f"\nTotal de duplicatas corrigidas: {total_fixed}")
                    
    except Exception as e:
        conn.rollback()
        print(f"ERRO durante a correção: {str(e)}")
    finally:
        conn.close()
    
    print("\nProcesso de correção concluído.")

def regenerate_history_for_date(date_str):
    """
    Regenera o histórico para uma data específica baseado nas posições atuais.
    Útil quando os dados para uma certa data estão muito inconsistentes.
    
    Args:
        date_str: Data no formato YYYY-MM-DD
    """
    conn = get_db_connection()
    
    try:
        # Validar formato da data
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            print(f"Formato de data inválido. Use YYYY-MM-DD")
            return
        
        print(f"Regenerando histórico para {date_str}...")
        
        # Remover registros existentes para a data
        deleted = conn.execute('DELETE FROM daily_ranking_history WHERE date_recorded = ?', (date_str,)).rowcount
        print(f"Removidos {deleted} registros existentes")
        
        # Obter todos os jogadores ativos
        players = conn.execute('SELECT id, position, tier FROM players WHERE active = 1 ORDER BY position').fetchall()
        
        # Inserir novos registros com as posições atuais
        for player in players:
            conn.execute('''
                INSERT INTO daily_ranking_history 
                (player_id, position, tier, date_recorded)
                VALUES (?, ?, ?, ?)
            ''', (player['id'], player['position'], player['tier'], date_str))
        
        conn.commit()
        print(f"Inseridos {len(players)} novos registros para {date_str}")
        
    except Exception as e:
        conn.rollback()
        print(f"ERRO durante a regeneração: {str(e)}")
    finally:
        conn.close()

if __name__ == "__main__":
    # Executar o diagnóstico
    check_history_data()
    
    # Perguntar se deseja corrigir posições duplicadas
    fix_duplicates = input("\nDeseja corrigir posições duplicadas? (s/n): ")
    if fix_duplicates.lower() == 's':
        fix_duplicate_positions()
    
    # Perguntar se deseja regenerar histórico para uma data específica
    regenerate = input("\nDeseja regenerar o histórico para uma data específica? (s/n): ")
    if regenerate.lower() == 's':
        date = input("Digite a data no formato YYYY-MM-DD: ")
        regenerate_history_for_date(date)