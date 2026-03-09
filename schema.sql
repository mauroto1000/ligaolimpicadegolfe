-- Tabela de Jogadores
CREATE TABLE IF NOT EXISTS players (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    hcp_index REAL NOT NULL,
    position INTEGER NOT NULL,
    tier TEXT NOT NULL,  -- A, B, C, etc. (representando as linhas da pirâmide)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de Desafios
CREATE TABLE IF NOT EXISTS challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenger_id INTEGER NOT NULL,
    challenged_id INTEGER NOT NULL,
    status TEXT NOT NULL, -- 'pending', 'accepted', 'completed', 'rejected'
    scheduled_date DATE,
    result TEXT, -- 'challenger_win', 'challenged_win'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (challenger_id) REFERENCES players (id),
    FOREIGN KEY (challenged_id) REFERENCES players (id)
);

-- Tabela de Histórico de Rankings
CREATE TABLE IF NOT EXISTS ranking_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    player_id INTEGER NOT NULL,
    old_position INTEGER NOT NULL,
    new_position INTEGER NOT NULL,
    old_tier TEXT NOT NULL,
    new_tier TEXT NOT NULL,
    change_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reason TEXT NOT NULL, -- ex: 'challenge_win', 'challenge_loss', 'monthly_update'
    challenge_id INTEGER,
    FOREIGN KEY (player_id) REFERENCES players (id),
    FOREIGN KEY (challenge_id) REFERENCES challenges (id)
);