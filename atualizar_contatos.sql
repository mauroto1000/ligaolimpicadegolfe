-- Script para atualizar o contato (email/celular) dos jogadores
-- Data de atualização: 07/03/2025

-- Iniciar transação explicitamente
BEGIN TRANSACTION;

-- Criar tabela temporária para registrar jogadores não encontrados
CREATE TEMP TABLE IF NOT EXISTS not_found_players (
    name TEXT,
    contact TEXT
);

-- Adolfo Gentil (21)986041976
UPDATE players SET email = '(21)986041976' WHERE name LIKE '%Adolfo%Gentil%';
INSERT INTO not_found_players SELECT 'Adolfo Gentil', '(21)986041976' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Adolfo%Gentil%'
);

-- Alfredo "Jakaré" Teixeira (21)972887791
UPDATE players SET email = '(21)972887791' WHERE name LIKE '%Alfredo%Teixeira%' OR name LIKE '%Jakaré%';
INSERT INTO not_found_players SELECT 'Alfredo "Jakaré" Teixeira', '(21)972887791' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Alfredo%Teixeira%' OR name LIKE '%Jakaré%'
);

-- Andre Vasconcellos (21)999353003
UPDATE players SET email = '(21)999353003' WHERE name LIKE '%Andre%Vasconcellos%';
INSERT INTO not_found_players SELECT 'Andre Vasconcellos', '(21)999353003' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Andre%Vasconcellos%'
);

-- Antônio Carlos Lins Maranhão (21)995159696
UPDATE players SET email = '(21)995159696' WHERE name LIKE '%Carlos%Lins%Maranhão%' OR name LIKE '%Carlos%Lins%Maranhao%';
INSERT INTO not_found_players SELECT 'Antônio Carlos Lins Maranhão', '(21)995159696' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Carlos%Lins%Maranhão%' OR name LIKE '%Carlos%Lins%Maranhao%'
);

-- Antonio Nunes Vieira Junior (21)974129897
UPDATE players SET email = '(21)974129897' WHERE name LIKE '%Antonio%Nunes%Vieira%' OR name LIKE '%Antônio%Nunes%Vieira%';
INSERT INTO not_found_players SELECT 'Antonio Nunes Vieira Junior', '(21)974129897' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Antonio%Nunes%Vieira%' OR name LIKE '%Antônio%Nunes%Vieira%'
);

-- Arapuan Motta Netto (21)981237956
UPDATE players SET email = '(21)981237956' WHERE name LIKE '%Arapuan%Motta%' OR name LIKE '%Arapuã%Motta%';
INSERT INTO not_found_players SELECT 'Arapuan Motta Netto', '(21)981237956' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Arapuan%Motta%' OR name LIKE '%Arapuã%Motta%'
);

-- Arlindo Borges (21)988447230
UPDATE players SET email = '(21)988447230' WHERE name LIKE '%Arlindo%Borges%';
INSERT INTO not_found_players SELECT 'Arlindo Borges', '(21)988447230' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Arlindo%Borges%'
);

-- Brady Beauchamp 1(612)5988448
UPDATE players SET email = '1(612)5988448' WHERE name LIKE '%Brady%Beauchamp%';
INSERT INTO not_found_players SELECT 'Brady Beauchamp', '1(612)5988448' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Brady%Beauchamp%'
);

-- Carlos Alberto Arouca (21)972129065
UPDATE players SET email = '(21)972129065' WHERE name LIKE '%Carlos%Alberto%Arouca%';
INSERT INTO not_found_players SELECT 'Carlos Alberto Arouca', '(21)972129065' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Carlos%Alberto%Arouca%'
);

-- Carlos Moreira (21)996383583
UPDATE players SET email = '(21)996383583' WHERE name LIKE '%Carlos%Moreira%';
INSERT INTO not_found_players SELECT 'Carlos Moreira', '(21)996383583' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Carlos%Moreira%'
);

-- Cassio Farias (21)982612278
UPDATE players SET email = '(21)982612278' WHERE name LIKE '%Cassio%Farias%';
INSERT INTO not_found_players SELECT 'Cassio Farias', '(21)982612278' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Cassio%Farias%'
);

-- Cesar Silva (21)981165656
UPDATE players SET email = '(21)981165656' WHERE name LIKE '%Cesar%Silva%' AND name NOT LIKE '%Paulo%';
INSERT INTO not_found_players SELECT 'Cesar Silva', '(21)981165656' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Cesar%Silva%' AND name NOT LIKE '%Paulo%'
);

-- Chang Vang (11)983170125
UPDATE players SET email = '(11)983170125' WHERE name LIKE '%Chang%Vang%';
INSERT INTO not_found_players SELECT 'Chang Vang', '(11)983170125' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Chang%Vang%'
);

-- Daniel Peres (21)996790166
UPDATE players SET email = '(21)996790166' WHERE name LIKE '%Daniel%Peres%';
INSERT INTO not_found_players SELECT 'Daniel Peres', '(21)996790166' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Daniel%Peres%'
);

-- Diego Gil (21)980001313
UPDATE players SET email = '(21)980001313' WHERE name LIKE '%Diego%Gil%';
INSERT INTO not_found_players SELECT 'Diego Gil', '(21)980001313' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Diego%Gil%'
);

-- Edmundo Julio Jung Marques (21)982181300
UPDATE players SET email = '(21)982181300' WHERE name LIKE '%Edmundo%Jung%Marques%';
INSERT INTO not_found_players SELECT 'Edmundo Julio Jung Marques', '(21)982181300' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Edmundo%Jung%Marques%'
);

-- Eduardo Henrique Dantas (21)987528153
UPDATE players SET email = '(21)987528153' WHERE name LIKE '%Eduardo%Henrique%Dantas%';
INSERT INTO not_found_players SELECT 'Eduardo Henrique Dantas', '(21)987528153' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Eduardo%Henrique%Dantas%'
);

-- Eduardo Machado (21)987770001
UPDATE players SET email = '(21)987770001' WHERE name LIKE '%Eduardo%Machado%';
INSERT INTO not_found_players SELECT 'Eduardo Machado', '(21)987770001' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Eduardo%Machado%'
);

-- Ercole A Talarico (21)999826377
UPDATE players SET email = '(21)999826377' WHERE name LIKE '%Ercole%Talarico%';
INSERT INTO not_found_players SELECT 'Ercole A Talarico', '(21)999826377' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Ercole%Talarico%'
);

-- Evandro Mendes Teixeira da Silva (21)999848392
UPDATE players SET email = '(21)999848392' WHERE name LIKE '%Evandro%Mendes%Teixeira%';
INSERT INTO not_found_players SELECT 'Evandro Mendes Teixeira da Silva', '(21)999848392' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Evandro%Mendes%Teixeira%'
);

-- Felipe Farias Da Costa (21)981095353
UPDATE players SET email = '(21)981095353' WHERE name LIKE '%Felipe%Farias%Costa%' OR name LIKE '%Felipe%Farias%';
INSERT INTO not_found_players SELECT 'Felipe Farias Da Costa', '(21)981095353' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Felipe%Farias%Costa%' OR name LIKE '%Felipe%Farias%'
);

-- Fernando Fernandes (21)989087890
UPDATE players SET email = '(21)989087890' WHERE name LIKE '%Fernando%Fernandes%';
INSERT INTO not_found_players SELECT 'Fernando Fernandes', '(21)989087890' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Fernando%Fernandes%'
);

-- Glauco Vasconcellos da Silva Ramos (21)998686069
UPDATE players SET email = '(21)998686069' WHERE name LIKE '%Glauco%Vasconcellos%Ramos%' OR name LIKE '%Glauco%Vasconcelos%Ramos%';
INSERT INTO not_found_players SELECT 'Glauco Vasconcellos da Silva Ramos', '(21)998686069' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Glauco%Vasconcellos%Ramos%' OR name LIKE '%Glauco%Vasconcelos%Ramos%'
);

-- Gregorio Del Val Gandullo (21)998195762
UPDATE players SET email = '(21)998195762' WHERE name LIKE '%Gregorio%Del%Val%Gandullo%';
INSERT INTO not_found_players SELECT 'Gregorio Del Val Gandullo', '(21)998195762' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Gregorio%Del%Val%Gandullo%'
);

-- Gustavo Rocha Freire (21)967281329
UPDATE players SET email = '(21)967281329' WHERE name LIKE '%Gustavo%Rocha%Freire%';
INSERT INTO not_found_players SELECT 'Gustavo Rocha Freire', '(21)967281329' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Gustavo%Rocha%Freire%'
);

-- Henrique Jorge Jatobá Barreto (21)999786473
UPDATE players SET email = '(21)999786473' WHERE name LIKE '%Henrique%Jorge%Jatobá%' OR name LIKE '%Henrique%Jorge%Jatoba%';
INSERT INTO not_found_players SELECT 'Henrique Jorge Jatobá Barreto', '(21)999786473' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Henrique%Jorge%Jatobá%' OR name LIKE '%Henrique%Jorge%Jatoba%'
);

-- João Victor Lahmann (21)971513700
UPDATE players SET email = '(21)971513700' WHERE name LIKE '%João%Victor%Lahmann%' OR name LIKE '%Joao%Victor%Lahmann%';
INSERT INTO not_found_players SELECT 'João Victor Lahmann', '(21)971513700' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%João%Victor%Lahmann%' OR name LIKE '%Joao%Victor%Lahmann%'
);

-- Jorge Pereira de Almeida (21)982945031
UPDATE players SET email = '(21)982945031' WHERE name LIKE '%Jorge%Pereira%Almeida%';
INSERT INTO not_found_players SELECT 'Jorge Pereira de Almeida', '(21)982945031' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Jorge%Pereira%Almeida%'
);

-- Jose Ricardo Trigo (21)995067726
UPDATE players SET email = '(21)995067726' WHERE name LIKE '%Jose%Ricardo%Trigo%' OR name LIKE '%José%Ricardo%Trigo%';
INSERT INTO not_found_players SELECT 'Jose Ricardo Trigo', '(21)995067726' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Jose%Ricardo%Trigo%' OR name LIKE '%José%Ricardo%Trigo%'
);

-- Leonardo de Souza Urpia (71)996818150
UPDATE players SET email = '(71)996818150' WHERE name LIKE '%Leonardo%Souza%Urpia%';
INSERT INTO not_found_players SELECT 'Leonardo de Souza Urpia', '(71)996818150' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Leonardo%Souza%Urpia%'
);

-- Luis Ernesto Delgado 32(472)284570
UPDATE players SET email = '32(472)284570' WHERE name LIKE '%Luis%Ernesto%Delgado%' OR name LIKE '%Luís%Ernesto%Delgado%';
INSERT INTO not_found_players SELECT 'Luis Ernesto Delgado', '32(472)284570' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Luis%Ernesto%Delgado%' OR name LIKE '%Luís%Ernesto%Delgado%'
);

-- Luiz Fernando Teixeira de Carvalho (21)988028537
UPDATE players SET email = '(21)988028537' WHERE name LIKE '%Luiz%Fernando%Teixeira%Carvalho%';
INSERT INTO not_found_players SELECT 'Luiz Fernando Teixeira de Carvalho', '(21)988028537' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Luiz%Fernando%Teixeira%Carvalho%'
);

-- Marcelo Barbosa Cruz (21)981075500
UPDATE players SET email = '(21)981075500' WHERE name LIKE '%Marcelo%Barbosa%Cruz%';
INSERT INTO not_found_players SELECT 'Marcelo Barbosa Cruz', '(21)981075500' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Marcelo%Barbosa%Cruz%'
);

-- Marcelo Klujsza (21)981076261
UPDATE players SET email = '(21)981076261' WHERE name LIKE '%Marcelo%Klujsza%';
INSERT INTO not_found_players SELECT 'Marcelo Klujsza', '(21)981076261' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Marcelo%Klujsza%'
);

-- Marcelo Merlo (21)980504343
UPDATE players SET email = '(21)980504343' WHERE name LIKE '%Marcelo%Merlo%';
INSERT INTO not_found_players SELECT 'Marcelo Merlo', '(21)980504343' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Marcelo%Merlo%'
);

-- Marcelo Modesto (21)977464039
UPDATE players SET email = '(21)977464039' WHERE name LIKE '%Marcelo%Modesto%';
INSERT INTO not_found_players SELECT 'Marcelo Modesto', '(21)977464039' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Marcelo%Modesto%'
);

-- Marcos Dias (21)994380036
UPDATE players SET email = '(21)994380036' WHERE name LIKE '%Marcos%Dias%';
INSERT INTO not_found_players SELECT 'Marcos Dias', '(21)994380036' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Marcos%Dias%'
);

-- Marcos Martins (21)997659483
UPDATE players SET email = '(21)997659483' WHERE name LIKE '%Marcos%Martins%';
INSERT INTO not_found_players SELECT 'Marcos Martins', '(21)997659483' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Marcos%Martins%'
);

-- Mario Colmenares 57(315)6480422
UPDATE players SET email = '57(315)6480422' WHERE name LIKE '%Mario%Colmenares%' OR name LIKE '%Mário%Colmenares%';
INSERT INTO not_found_players SELECT 'Mario Colmenares', '57(315)6480422' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Mario%Colmenares%' OR name LIKE '%Mário%Colmenares%'
);

-- Mark Lloyd 61(417)335962
UPDATE players SET email = '61(417)335962' WHERE name LIKE '%Mark%Lloyd%';
INSERT INTO not_found_players SELECT 'Mark Lloyd', '61(417)335962' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Mark%Lloyd%'
);

-- Mauro Tomio Saito (21)969275688
UPDATE players SET email = '(21)969275688' WHERE name LIKE '%Mauro%Tomio%Saito%' OR name LIKE '%Mauro%Saito%';
INSERT INTO not_found_players SELECT 'Mauro Tomio Saito', '(21)969275688' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Mauro%Tomio%Saito%' OR name LIKE '%Mauro%Saito%'
);

-- Miguel Santinoni (21)996688577
UPDATE players SET email = '(21)996688577' WHERE name LIKE '%Miguel%Santinoni%';
INSERT INTO not_found_players SELECT 'Miguel Santinoni', '(21)996688577' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Miguel%Santinoni%'
);

-- Oeyvind Gomnaes (21)982123485
UPDATE players SET email = '(21)982123485' WHERE name LIKE '%Oeyvind%Gomnaes%' OR name LIKE '%Oeyvind%';
INSERT INTO not_found_players SELECT 'Oeyvind Gomnaes', '(21)982123485' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Oeyvind%Gomnaes%' OR name LIKE '%Oeyvind%'
);

-- Patrick Amorim (21)986623666
UPDATE players SET email = '(21)986623666' WHERE name LIKE '%Patrick%Amorim%';
INSERT INTO not_found_players SELECT 'Patrick Amorim', '(21)986623666' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Patrick%Amorim%'
);

-- Paulo Cesar da Silva (21)997012748
UPDATE players SET email = '(21)997012748' WHERE name LIKE '%Paulo%Cesar%Silva%';
INSERT INTO not_found_players SELECT 'Paulo Cesar da Silva', '(21)997012748' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Paulo%Cesar%Silva%'
);

-- Paulo Marcio Mauro (21)986492438
UPDATE players SET email = '(21)986492438' WHERE name LIKE '%Paulo%Marcio%Mauro%' OR name LIKE '%Paulo%Márcio%Mauro%';
INSERT INTO not_found_players SELECT 'Paulo Marcio Mauro', '(21)986492438' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Paulo%Marcio%Mauro%' OR name LIKE '%Paulo%Márcio%Mauro%'
);

-- Paulo Ricardo Pinto (21)981114544
UPDATE players SET email = '(21)981114544' WHERE name LIKE '%Paulo%Ricardo%Pinto%';
INSERT INTO not_found_players SELECT 'Paulo Ricardo Pinto', '(21)981114544' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Paulo%Ricardo%Pinto%'
);

-- Paulo Sérgio Teixeira de Andrade (21)984857196
UPDATE players SET email = '(21)984857196' WHERE name LIKE '%Paulo%Sergio%Teixeira%Andrade%' OR name LIKE '%Paulo%Sérgio%Teixeira%Andrade%';
INSERT INTO not_found_players SELECT 'Paulo Sérgio Teixeira de Andrade', '(21)984857196' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Paulo%Sergio%Teixeira%Andrade%' OR name LIKE '%Paulo%Sérgio%Teixeira%Andrade%'
);

-- Philip Carruthers (21)991330559
UPDATE players SET email = '(21)991330559' WHERE name LIKE '%Philip%Carruthers%';
INSERT INTO not_found_players SELECT 'Philip Carruthers', '(21)991330559' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Philip%Carruthers%'
);

-- Regis Fichtner (21)967094383
UPDATE players SET email = '(21)967094383' WHERE name LIKE '%Regis%Fichtner%' OR name LIKE '%Régis%Fichtner%';
INSERT INTO not_found_players SELECT 'Regis Fichtner', '(21)967094383' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Regis%Fichtner%' OR name LIKE '%Régis%Fichtner%'
);

-- Robert Thomas (21)967266211
UPDATE players SET email = '(21)967266211' WHERE name LIKE '%Robert%Thomas%';
INSERT INTO not_found_players SELECT 'Robert Thomas', '(21)967266211' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Robert%Thomas%'
);

-- Robert W. Donaldson (Bob) (21)996003721
UPDATE players SET email = '(21)996003721' WHERE name LIKE '%Robert%Donaldson%' OR name LIKE '%Bob%Donaldson%';
INSERT INTO not_found_players SELECT 'Robert W. Donaldson (Bob)', '(21)996003721' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Robert%Donaldson%' OR name LIKE '%Bob%Donaldson%'
);

-- Roberto Fernandes (21)964385011
UPDATE players SET email = '(21)964385011' WHERE name LIKE '%Roberto%Fernandes%';
INSERT INTO not_found_players SELECT 'Roberto Fernandes', '(21)964385011' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Roberto%Fernandes%'
);

-- Roberto Fiani (21)981674601
UPDATE players SET email = '(21)981674601' WHERE name LIKE '%Roberto%Fiani%';
INSERT INTO not_found_players SELECT 'Roberto Fiani', '(21)981674601' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Roberto%Fiani%'
);

-- Roberto Luiz Vianna Veras (21)981348688
UPDATE players SET email = '(21)981348688' WHERE name LIKE '%Roberto%Luiz%Vianna%Veras%' OR name LIKE '%Roberto%Luiz%Viana%Veras%';
INSERT INTO not_found_players SELECT 'Roberto Luiz Vianna Veras', '(21)981348688' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Roberto%Luiz%Vianna%Veras%' OR name LIKE '%Roberto%Luiz%Viana%Veras%'
);

-- Roberto Mauler (21)981458016
UPDATE players SET email = '(21)981458016' WHERE name LIKE '%Roberto%Mauler%';
INSERT INTO not_found_players SELECT 'Roberto Mauler', '(21)981458016' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Roberto%Mauler%'
);

-- Rodrigo Mendes (21)986284070
UPDATE players SET email = '(21)986284070' WHERE name LIKE '%Rodrigo%Mendes%' AND name NOT LIKE '%Teixeira%';
INSERT INTO not_found_players SELECT 'Rodrigo Mendes', '(21)986284070' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Rodrigo%Mendes%' AND name NOT LIKE '%Teixeira%'
);

-- Scott Radeztsky 1(312)9526761
UPDATE players SET email = '1(312)9526761' WHERE name LIKE '%Scott%Rad%ztsky%';
INSERT INTO not_found_players SELECT 'Scott Radeztsky', '1(312)9526761' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Scott%Rad%ztsky%'
);

-- Sergio Barbosa Pereira (21)987128411
UPDATE players SET email = '(21)987128411' WHERE name LIKE '%Sergio%Barbosa%Pereira%' OR name LIKE '%Sérgio%Barbosa%Pereira%';
INSERT INTO not_found_players SELECT 'Sergio Barbosa Pereira', '(21)987128411' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Sergio%Barbosa%Pereira%' OR name LIKE '%Sérgio%Barbosa%Pereira%'
);

-- Sergio Pinto (21)999860544
UPDATE players SET email = '(21)999860544' WHERE name LIKE '%Sergio%Pinto%' OR name LIKE '%Sérgio%Pinto%';
INSERT INTO not_found_players SELECT 'Sergio Pinto', '(21)999860544' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Sergio%Pinto%' OR name LIKE '%Sérgio%Pinto%'
);

-- Vicente Jesus (21)990034305
UPDATE players SET email = '(21)990034305' WHERE name LIKE '%Vicente%Jesus%';
INSERT INTO not_found_players SELECT 'Vicente Jesus', '(21)990034305' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Vicente%Jesus%'
);

-- Vinicius Terk Cruz (21)975760660
UPDATE players SET email = '(21)975760660' WHERE name LIKE '%Vinicius%Terk%Cruz%' OR name LIKE '%Vinícius%Terk%Cruz%';
INSERT INTO not_found_players SELECT 'Vinicius Terk Cruz', '(21)975760660' WHERE NOT EXISTS (
    SELECT 1 FROM players WHERE name LIKE '%Vinicius%Terk%Cruz%' OR name LIKE '%Vinícius%Terk%Cruz%'
);

-- Tentar atualizar as notas de um jogador existente
UPDATE players SET notes = COALESCE(notes, '') || ' | Atualização em massa de contatos (email/celular) com data de 07/03/2025'
WHERE id IN (SELECT id FROM players WHERE active = 1 ORDER BY position LIMIT 1);

-- Verificar quais jogadores não foram encontrados
SELECT * FROM not_found_players;

-- Confirmar as alterações
COMMIT;