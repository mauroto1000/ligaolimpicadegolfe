-- Script para atualizar o HCP Index dos jogadores usando correspondência parcial de nomes
-- Data de atualização: 01/03/2025

-- Iniciar transação explicitamente
BEGIN TRANSACTION;

-- Criar tabela temporária para registrar jogadores não encontrados
CREATE TEMP TABLE IF NOT EXISTS not_found_players (
    name TEXT,
    hcp_index REAL
);

-- Patrick Amorim (ZERO)
UPDATE players SET hcp_index = 0.0 WHERE name LIKE '%Patrick%Amorim%';
INSERT INTO not_found_players SELECT 'Patrick Amorim', 0.0 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Patrick%Amorim%'
);

-- Brady Beauchamp (1.0)
UPDATE players SET hcp_index = 1.0 WHERE name LIKE '%Brady%Beauchamp%';
INSERT INTO not_found_players SELECT 'Brady Beauchamp', 1.0 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Brady%Beauchamp%'
);

-- Vicente Jesus (3.7)
UPDATE players SET hcp_index = 3.7 WHERE name LIKE '%Vicente%Jesus%';
INSERT INTO not_found_players SELECT 'Vicente Jesus', 3.7 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Vicente%Jesus%'
);

-- Roberto Fernandes (8.1)
UPDATE players SET hcp_index = 8.1 WHERE name LIKE '%Roberto%Fernandes%';
INSERT INTO not_found_players SELECT 'Roberto Fernandes', 8.1 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Roberto%Fernandes%'
);

-- Marcelo Modesto (9.0)
UPDATE players SET hcp_index = 9.0 WHERE name LIKE '%Marcelo%Modesto%';
INSERT INTO not_found_players SELECT 'Marcelo Modesto', 9.0 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Marcelo%Modesto%'
);

-- Stefanno Dias (10.1)
UPDATE players SET hcp_index = 10.1 WHERE name LIKE '%Stefanno%Dias%';
INSERT INTO not_found_players SELECT 'Stefanno Dias', 10.1 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Stefanno%Dias%'
);

-- Arlindo Borges (10.6)
UPDATE players SET hcp_index = 10.6 WHERE name LIKE '%Arlindo%Borges%';
INSERT INTO not_found_players SELECT 'Arlindo Borges', 10.6 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Arlindo%Borges%'
);

-- Miguel Santinoni (11.3)
UPDATE players SET hcp_index = 11.3 WHERE name LIKE '%Miguel%Santinoni%';
INSERT INTO not_found_players SELECT 'Miguel Santinoni', 11.3 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Miguel%Santinoni%'
);

-- Marcos Dias (12.0)
UPDATE players SET hcp_index = 12.0 WHERE name LIKE '%Marcos%Dias%';
INSERT INTO not_found_players SELECT 'Marcos Dias', 12.0 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Marcos%Dias%'
);

-- Scott Radeztsky (12.6)
UPDATE players SET hcp_index = 12.6 WHERE name LIKE '%Scott%Rad%ztsky%';
INSERT INTO not_found_players SELECT 'Scott Radeztsky', 12.6 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Scott%Rad%ztsky%'
);

-- Roberto Mauler (13.0)
UPDATE players SET hcp_index = 13.0 WHERE name LIKE '%Roberto%Mauler%';
INSERT INTO not_found_players SELECT 'Roberto Mauler', 13.0 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Roberto%Mauler%'
);

-- Mark Lloyd (13.5)
UPDATE players SET hcp_index = 13.5 WHERE name LIKE '%Mark%Lloyd%';
INSERT INTO not_found_players SELECT 'Mark Lloyd', 13.5 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Mark%Lloyd%'
);

-- Robert W. Donaldson (Bob) (13.5)
UPDATE players SET hcp_index = 13.5 WHERE name LIKE '%Robert%Donaldson%' OR name LIKE '%Bob%Donaldson%';
INSERT INTO not_found_players SELECT 'Robert W. Donaldson (Bob)', 13.5 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Robert%Donaldson%' OR name LIKE '%Bob%Donaldson%'
);

-- Paulo Cesar da Silva (13.9)
UPDATE players SET hcp_index = 13.9 WHERE name LIKE '%Paulo%Cesar%Silva%';
INSERT INTO not_found_players SELECT 'Paulo Cesar da Silva', 13.9 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Paulo%Cesar%Silva%'
);

-- Alfredo "Jakaré" Teixeira (14.8)
UPDATE players SET hcp_index = 14.8 WHERE name LIKE '%Alfredo%Teixeira%' OR name LIKE '%Jakaré%';
INSERT INTO not_found_players SELECT 'Alfredo "Jakaré" Teixeira', 14.8 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Alfredo%Teixeira%' OR name LIKE '%Jakaré%'
);

-- Marcelo Merlo (15.4)
UPDATE players SET hcp_index = 15.4 WHERE name LIKE '%Marcelo%Merlo%';
INSERT INTO not_found_players SELECT 'Marcelo Merlo', 15.4 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Marcelo%Merlo%'
);

-- Carlos Moreira (16.2)
UPDATE players SET hcp_index = 16.2 WHERE name LIKE '%Carlos%Moreira%';
INSERT INTO not_found_players SELECT 'Carlos Moreira', 16.2 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Carlos%Moreira%'
);

-- Andre Vasconcellos (16.3)
UPDATE players SET hcp_index = 16.3 WHERE name LIKE '%Andre%Vasconcellos%';
INSERT INTO not_found_players SELECT 'Andre Vasconcellos', 16.3 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Andre%Vasconcellos%'
);

-- Fernando Fernandes (16.5)
UPDATE players SET hcp_index = 16.5 WHERE name LIKE '%Fernando%Fernandes%';
INSERT INTO not_found_players SELECT 'Fernando Fernandes', 16.5 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Fernando%Fernandes%'
);

-- Eduardo Machado (17.5)
UPDATE players SET hcp_index = 17.5 WHERE name LIKE '%Eduardo%Machado%';
INSERT INTO not_found_players SELECT 'Eduardo Machado', 17.5 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Eduardo%Machado%'
);

-- Marcelo Klujsza (17.6)
UPDATE players SET hcp_index = 17.6 WHERE name LIKE '%Marcelo%Klujsza%';
INSERT INTO not_found_players SELECT 'Marcelo Klujsza', 17.6 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Marcelo%Klujsza%'
);

-- Cassio Farias (18.0)
UPDATE players SET hcp_index = 18.0 WHERE name LIKE '%Cassio%Farias%';
INSERT INTO not_found_players SELECT 'Cassio Farias', 18.0 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Cassio%Farias%'
);

-- Jose Ricardo Trigo (18.3)
UPDATE players SET hcp_index = 18.3 WHERE name LIKE '%Jose%Ricardo%Trigo%' OR name LIKE '%José%Ricardo%Trigo%';
INSERT INTO not_found_players SELECT 'Jose Ricardo Trigo', 18.3 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Jose%Ricardo%Trigo%' OR name LIKE '%José%Ricardo%Trigo%'
);

-- Chang Vang (18.4)
UPDATE players SET hcp_index = 18.4 WHERE name LIKE '%Chang%Vang%';
INSERT INTO not_found_players SELECT 'Chang Vang', 18.4 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Chang%Vang%'
);

-- Adolfo Gentil (18.8)
UPDATE players SET hcp_index = 18.8 WHERE name LIKE '%Adolfo%Gentil%';
INSERT INTO not_found_players SELECT 'Adolfo Gentil', 18.8 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Adolfo%Gentil%'
);

-- Marcelo Barbosa Cruz (18.8)
UPDATE players SET hcp_index = 18.8 WHERE name LIKE '%Marcelo%Barbosa%Cruz%';
INSERT INTO not_found_players SELECT 'Marcelo Barbosa Cruz', 18.8 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Marcelo%Barbosa%Cruz%'
);

-- Mario Colmenares (19.1)
UPDATE players SET hcp_index = 19.1 WHERE name LIKE '%Mario%Colmenares%' OR name LIKE '%Mário%Colmenares%';
INSERT INTO not_found_players SELECT 'Mario Colmenares', 19.1 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Mario%Colmenares%' OR name LIKE '%Mário%Colmenares%'
);

-- Sergio Pinto (19.2)
UPDATE players SET hcp_index = 19.2 WHERE name LIKE '%Sergio%Pinto%' OR name LIKE '%Sérgio%Pinto%';
INSERT INTO not_found_players SELECT 'Sergio Pinto', 19.2 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Sergio%Pinto%' OR name LIKE '%Sérgio%Pinto%'
);

-- Diego Gil (19.5)
UPDATE players SET hcp_index = 19.5 WHERE name LIKE '%Diego%Gil%';
INSERT INTO not_found_players SELECT 'Diego Gil', 19.5 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Diego%Gil%'
);

-- Rodrigo Mendes (19.6)
UPDATE players SET hcp_index = 19.6 WHERE name LIKE '%Rodrigo%Mendes%' AND name NOT LIKE '%Teixeira%';
INSERT INTO not_found_players SELECT 'Rodrigo Mendes', 19.6 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Rodrigo%Mendes%' AND name NOT LIKE '%Teixeira%'
);

-- Luis Ernesto Delgado (19.6)
UPDATE players SET hcp_index = 19.6 WHERE name LIKE '%Luis%Ernesto%Delgado%' OR name LIKE '%Luís%Ernesto%Delgado%';
INSERT INTO not_found_players SELECT 'Luis Ernesto Delgado', 19.6 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Luis%Ernesto%Delgado%' OR name LIKE '%Luís%Ernesto%Delgado%'
);

-- Gustavo Rocha Freire (19.7)
UPDATE players SET hcp_index = 19.7 WHERE name LIKE '%Gustavo%Rocha%Freire%';
INSERT INTO not_found_players SELECT 'Gustavo Rocha Freire', 19.7 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Gustavo%Rocha%Freire%'
);

-- Ercole A Talarico (19.9)
UPDATE players SET hcp_index = 19.9 WHERE name LIKE '%Ercole%Talarico%';
INSERT INTO not_found_players SELECT 'Ercole A Talarico', 19.9 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Ercole%Talarico%'
);

-- Regis Fichtner (20.0)
UPDATE players SET hcp_index = 20.0 WHERE name LIKE '%Regis%Fichtner%' OR name LIKE '%Régis%Fichtner%';
INSERT INTO not_found_players SELECT 'Regis Fichtner', 20.0 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Regis%Fichtner%' OR name LIKE '%Régis%Fichtner%'
);

-- Roberto Fiani (20.4)
UPDATE players SET hcp_index = 20.4 WHERE name LIKE '%Roberto%Fiani%';
INSERT INTO not_found_players SELECT 'Roberto Fiani', 20.4 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Roberto%Fiani%'
);

-- Robert Thomas (20.6)
UPDATE players SET hcp_index = 20.6 WHERE name LIKE '%Robert%Thomas%';
INSERT INTO not_found_players SELECT 'Robert Thomas', 20.6 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Robert%Thomas%'
);

-- Mauro Tomio Saito (21.0)
UPDATE players SET hcp_index = 21.0 WHERE name LIKE '%Mauro%Tomio%Saito%' OR name LIKE '%Mauro%Saito%';
INSERT INTO not_found_players SELECT 'Mauro Tomio Saito', 21.0 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Mauro%Tomio%Saito%' OR name LIKE '%Mauro%Saito%'
);

-- Felipe Farias Da Costa (21.3)
UPDATE players SET hcp_index = 21.3 WHERE name LIKE '%Felipe%Farias%Costa%' OR name LIKE '%Felipe%Farias%';
INSERT INTO not_found_players SELECT 'Felipe Farias Da Costa', 21.3 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Felipe%Farias%Costa%' OR name LIKE '%Felipe%Farias%'
);

-- Antonio Nunes Vieira Junior (21.7)
UPDATE players SET hcp_index = 21.7 WHERE name LIKE '%Antonio%Nunes%Vieira%' OR name LIKE '%Antônio%Nunes%Vieira%';
INSERT INTO not_found_players SELECT 'Antonio Nunes Vieira Junior', 21.7 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Antonio%Nunes%Vieira%' OR name LIKE '%Antônio%Nunes%Vieira%'
);

-- Luiz Fernando Teixeira de Carvalho (22.1)
UPDATE players SET hcp_index = 22.1 WHERE name LIKE '%Luiz%Fernando%Teixeira%Carvalho%';
INSERT INTO not_found_players SELECT 'Luiz Fernando Teixeira de Carvalho', 22.1 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Luiz%Fernando%Teixeira%Carvalho%'
);

-- Arapuan Motta Netto (22.2)
UPDATE players SET hcp_index = 22.2 WHERE name LIKE '%Arapuan%Motta%' OR name LIKE '%Arapuã%Motta%';
INSERT INTO not_found_players SELECT 'Arapuan Motta Netto', 22.2 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Arapuan%Motta%' OR name LIKE '%Arapuã%Motta%'
);

-- Daniel Peres (22.5)
UPDATE players SET hcp_index = 22.5 WHERE name LIKE '%Daniel%Peres%';
INSERT INTO not_found_players SELECT 'Daniel Peres', 22.5 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Daniel%Peres%'
);

-- Antônio Carlos Lins Maranhão (23.4)
UPDATE players SET hcp_index = 23.4 WHERE name LIKE '%Carlos%Lins%Maranhão%' OR name LIKE '%Carlos%Lins%Maranhao%';
INSERT INTO not_found_players SELECT 'Antônio Carlos Lins Maranhão', 23.4 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Carlos%Lins%Maranhão%' OR name LIKE '%Carlos%Lins%Maranhao%'
);

-- Oeyvind Gomnaes (23.7)
UPDATE players SET hcp_index = 23.7 WHERE name LIKE '%Oeyvind%Gomnaes%' OR name LIKE '%Oeyvind%';
INSERT INTO not_found_players SELECT 'Oeyvind Gomnaes', 23.7 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Oeyvind%Gomnaes%' OR name LIKE '%Oeyvind%'
);

-- Evandro Mendes Teixeira da Silva (25.3)
UPDATE players SET hcp_index = 25.3 WHERE name LIKE '%Evandro%Mendes%Teixeira%';
INSERT INTO not_found_players SELECT 'Evandro Mendes Teixeira da Silva', 25.3 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Evandro%Mendes%Teixeira%'
);

-- Cesar Silva (25.5)
UPDATE players SET hcp_index = 25.5 WHERE name LIKE '%Cesar%Silva%' AND name NOT LIKE '%Paulo%';
INSERT INTO not_found_players SELECT 'Cesar Silva', 25.5 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Cesar%Silva%' AND name NOT LIKE '%Paulo%'
);

-- Sergio Barbosa Pereira (25.9)
UPDATE players SET hcp_index = 25.9 WHERE name LIKE '%Sergio%Barbosa%Pereira%' OR name LIKE '%Sérgio%Barbosa%Pereira%';
INSERT INTO not_found_players SELECT 'Sergio Barbosa Pereira', 25.9 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Sergio%Barbosa%Pereira%' OR name LIKE '%Sérgio%Barbosa%Pereira%'
);

-- Glauco Vasconcellos da Silva Ramos (26.0)
UPDATE players SET hcp_index = 26.0 WHERE name LIKE '%Glauco%Vasconcellos%Ramos%' OR name LIKE '%Glauco%Vasconcelos%Ramos%';
INSERT INTO not_found_players SELECT 'Glauco Vasconcellos da Silva Ramos', 26.0 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Glauco%Vasconcellos%Ramos%' OR name LIKE '%Glauco%Vasconcelos%Ramos%'
);

-- Edmundo Julio Jung Marques (26.4)
UPDATE players SET hcp_index = 26.4 WHERE name LIKE '%Edmundo%Jung%Marques%';
INSERT INTO not_found_players SELECT 'Edmundo Julio Jung Marques', 26.4 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Edmundo%Jung%Marques%'
);

-- Leonardo de Souza Urpia (26.5)
UPDATE players SET hcp_index = 26.5 WHERE name LIKE '%Leonardo%Souza%Urpia%';
INSERT INTO not_found_players SELECT 'Leonardo de Souza Urpia', 26.5 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Leonardo%Souza%Urpia%'
);

-- Paulo Marcio Mauro (27.0)
UPDATE players SET hcp_index = 27.0 WHERE name LIKE '%Paulo%Marcio%Mauro%' OR name LIKE '%Paulo%Márcio%Mauro%';
INSERT INTO not_found_players SELECT 'Paulo Marcio Mauro', 27.0 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Paulo%Marcio%Mauro%' OR name LIKE '%Paulo%Márcio%Mauro%'
);

-- Paulo Ricardo Pinto (27.3)
UPDATE players SET hcp_index = 27.3 WHERE name LIKE '%Paulo%Ricardo%Pinto%';
INSERT INTO not_found_players SELECT 'Paulo Ricardo Pinto', 27.3 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Paulo%Ricardo%Pinto%'
);

-- Carlos Alberto Arouca (28.7)
UPDATE players SET hcp_index = 28.7 WHERE name LIKE '%Carlos%Alberto%Arouca%';
INSERT INTO not_found_players SELECT 'Carlos Alberto Arouca', 28.7 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Carlos%Alberto%Arouca%'
);

-- Roberto Luiz Vianna Veras (30.3)
UPDATE players SET hcp_index = 30.3 WHERE name LIKE '%Roberto%Luiz%Vianna%Veras%' OR name LIKE '%Roberto%Luiz%Viana%Veras%';
INSERT INTO not_found_players SELECT 'Roberto Luiz Vianna Veras', 30.3 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Roberto%Luiz%Vianna%Veras%' OR name LIKE '%Roberto%Luiz%Viana%Veras%'
);

-- Jorge Pereira de Almeida (34.0)
UPDATE players SET hcp_index = 34.0 WHERE name LIKE '%Jorge%Pereira%Almeida%';
INSERT INTO not_found_players SELECT 'Jorge Pereira de Almeida', 34.0 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Jorge%Pereira%Almeida%'
);

-- Paulo Sérgio Teixeira de Andrade (36.0)
UPDATE players SET hcp_index = 36.0 WHERE name LIKE '%Paulo%Sergio%Teixeira%Andrade%' OR name LIKE '%Paulo%Sérgio%Teixeira%Andrade%';
INSERT INTO not_found_players SELECT 'Paulo Sérgio Teixeira de Andrade', 36.0 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Paulo%Sergio%Teixeira%Andrade%' OR name LIKE '%Paulo%Sérgio%Teixeira%Andrade%'
);

-- Eduardo Henrique Dantas (36.0)
UPDATE players SET hcp_index = 36.0 WHERE name LIKE '%Eduardo%Henrique%Dantas%';
INSERT INTO not_found_players SELECT 'Eduardo Henrique Dantas', 36.0 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Eduardo%Henrique%Dantas%'
);

-- Henrique Jorge Jatobá Barreto (36.0)
UPDATE players SET hcp_index = 36.0 WHERE name LIKE '%Henrique%Jorge%Jatobá%' OR name LIKE '%Henrique%Jorge%Jatoba%';
INSERT INTO not_found_players SELECT 'Henrique Jorge Jatobá Barreto', 36.0 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Henrique%Jorge%Jatobá%' OR name LIKE '%Henrique%Jorge%Jatoba%'
);

-- Vinicius Terk Cruz (38.6)
UPDATE players SET hcp_index = 38.6 WHERE name LIKE '%Vinicius%Terk%Cruz%' OR name LIKE '%Vinícius%Terk%Cruz%';
INSERT INTO not_found_players SELECT 'Vinicius Terk Cruz', 38.6 WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Vinicius%Terk%Cruz%' OR name LIKE '%Vinícius%Terk%Cruz%'
);

-- Tentar atualizar as notas de um jogador existente
UPDATE players SET notes = COALESCE(notes, '') || ' | Atualização em massa de HCP Index com data de 01/03/2025'
WHERE id IN (SELECT id FROM players WHERE active = 1 ORDER BY position LIMIT 1);

-- Verificar quais jogadores não foram encontrados
SELECT * FROM not_found_players;

-- Confirmar as alterações
COMMIT;