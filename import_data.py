import sqlite3
import os

# Criar banco de dados
def create_database():
    conn = sqlite3.connect('golf_league.db')
    cursor = conn.cursor()
    
    # Ler o esquema SQL e executar
    with open('schema.sql', 'r') as f:
        schema = f.read()
        cursor.executescript(schema)
    
    conn.commit()
    return conn, cursor

# Determinar a linha (tier) com base na posição e na estrutura da pirâmide
def get_tier_from_position(position):
    tiers = {
        'A': [1],
        'B': [2, 3],
        'C': [4, 5, 6],
        'D': [7, 8, 9, 10],
        'E': [11, 12, 13, 14, 15],
        'F': [16, 17, 18, 19, 20, 21],
        'G': [22, 23, 24, 25, 26, 27, 28],
        'H': [29, 30, 31, 32, 33, 34, 35, 36],
        'I': [37, 38, 39, 40, 41, 42, 43, 44, 45],
        'J': [46, 47, 48, 49, 50, 51, 52, 53, 54, 55],
        'K': [56, 57, 58, 59, 60, 61]
    }
    
    for tier, positions in tiers.items():
        if position in positions:
            return tier
    
    # Para posições não mapeadas (caso necessário expandir)
    if position <= 78:
        return 'L'
    return 'M'

# Importar dados dos jogadores do PDF (manualmente extraídos)
def import_players_data(cursor):
    players_data = [
        (1, "Patrick Amorim", 0.0),
        (2, "Brady Beauchamp", 1.0),
        (3, "Vicente Jesus", 3.7),
        (4, "Roberto Fernandes", 8.1),
        (5, "Marcelo Modesto", 9.0),
        (6, "Stefanno Dias", 10.1),
        (7, "Arlindo Borges", 10.6),
        (8, "Miguel Santinoni", 11.3),
        (9, "Marcos Dias", 12.0),
        (10, "Scott Radeztsky", 12.6),
        (11, "Roberto Mauler", 13.0),
        (12, "Mark Lloyd", 13.5),
        (13, "Robert W. Donaldson (Bob)", 13.5),
        (14, "Paulo Cesar da Silva", 13.9),
        (15, "Alfredo \"Jakaré\" Teixeira", 14.8),
        (16, "Marcelo Merlo", 15.4),
        (17, "Carlos Moreira", 16.2),
        (18, "Andre Vasconcellos", 16.3),
        (19, "Fernando Fernandes", 16.5),
        (20, "Eduardo Machado", 17.5),
        (21, "Marcelo Klujsza", 17.6),
        (22, "Cassio Farias", 18.0),
        (23, "Jose Ricardo Trigo", 18.3),
        (24, "Marcos Martins", 18.4),
        (25, "Chang Vang", 18.4),
        (26, "Adolfo Gentil", 18.8),
        (27, "Marcelo Barbosa Cruz", 18.8),
        (28, "Philip Carruthers", 18.8),
        (29, "Mario Colmenares", 19.1),
        (30, "Sergio Pinto", 19.2),
        (31, "Diego Gil", 19.5),
        (32, "Rodrigo Mendes", 19.6),
        (33, "Luis Ernesto Delgado", 19.6),
        (34, "Gustavo Rocha Freire", 19.7),
        (35, "Ercole A Talarico", 19.9),
        (36, "Regis Fichtner", 20.0),
        (37, "Roberto Fiani", 20.4),
        (38, "Robert Thomas", 20.6),
        (39, "Mauro Tomio Saito", 21.0),
        (40, "Felipe Farias Da Costa", 21.3),
        (41, "Antonio Nunes Vieira Junior", 21.7),
        (42, "Luiz Fernando Teixeira de Carvalho", 22.1),
        (43, "Arapuan Motta Netto", 22.2),
        (44, "Daniel Peres", 22.5),
        (45, "Antônio Carlos Lins Maranhão", 23.4),
        (46, "Oeyvind Gomnaes", 23.7),
        (47, "Evandro Mendes Teixeira da Silva", 25.3),
        (48, "Cesar Silva", 25.5),
        (49, "Sergio Barbosa Pereira", 25.9),
        (50, "Glauco Vasconcellos da Silva Ramos", 26.0),
        (51, "Edmundo Julio Jung Marques", 26.4),
        (52, "Leonardo de Souza Urpia", 26.5),
        (53, "Paulo Marcio Mauro", 27.0),
        (54, "Paulo Ricardo Pinto", 27.3),
        (55, "Carlos Alberto Arouca", 28.7),
        (56, "Roberto Luiz Vianna Veras", 30.3),
        (57, "Jorge Pereira de Almeida", 34.0),
        (58, "Paulo Sérgio Teixeira de Andrade", 36.0),
        (59, "Eduardo Henrique Dantas", 36.0),
        (60, "Henrique Jorge Jatobá Barreto", 36.0),
        (61, "Vinicius Terk Cruz", 38.6),
    ]
    
    # Limpar a tabela de jogadores existente (se necessário)
    cursor.execute('DELETE FROM players')
    
    # Inserir cada jogador com seu tier baseado na posição
    for position, name, hcp_index in players_data:
        tier = get_tier_from_position(position)
        cursor.execute(
            'INSERT INTO players (position, name, hcp_index, tier) VALUES (?, ?, ?, ?)',
            (position, name, hcp_index, tier)
        )
    
    print(f"Importados {len(players_data)} jogadores.")

if __name__ == "__main__":
    # Verificar se o banco de dados já existe
    db_exists = os.path.exists('golf_league.db')
    
    conn, cursor = create_database()
    
    if not db_exists or input("O banco de dados já existe. Deseja reimportar os dados? (s/n): ").lower() == 's':
        import_players_data(cursor)
        print("Dados importados com sucesso!")
    else:
        print("Importação cancelada.")
    
    conn.commit()
    conn.close()