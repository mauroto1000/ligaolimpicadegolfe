-- ============================================================
-- SCRIPT: Adiciona no_federado e popula hcp_index (CBG)
-- Gerado em: 2026-04-28
-- Cruzamento: Lista CBG Campo Olímpico × jogadores ativos da Liga
-- ============================================================

-- PASSO 1: Adicionar coluna no_federado (executar apenas uma vez)
-- Se já existir, o SQLite retornará erro — ignore e continue para o PASSO 2.
ALTER TABLE players ADD COLUMN no_federado TEXT;


-- ============================================================
-- PASSO 2: Atualizar hcp_index e no_federado por jogador
-- Formato: UPDATE players SET hcp_index=<HCP>, no_federado='<No.Fed>' WHERE id=<id>;
-- ============================================================

-- Alejandro Scheffler (CBG: Alexandre Scheffler, 15962)
UPDATE players SET hcp_index=21.4, no_federado='15962' WHERE id=89;

-- Alexandre Ventura (CBG: Alexandre Chinaglia Quintão Ventura, 16050)
UPDATE players SET hcp_index=13.3, no_federado='16050' WHERE id=113;

-- Andre Vasconcellos (CBG: André Vasconcellos, 15096)
UPDATE players SET hcp_index=17.8, no_federado='15096' WHERE id=18;

-- António Simões (CBG: Antonio Simões, 15568)
UPDATE players SET hcp_index=26.8, no_federado='15568' WHERE id=77;

-- Arapuan Motta Netto (CBG: Arapuan Medeiros da Motta Netto, 15822)
UPDATE players SET hcp_index=15.8, no_federado='15822' WHERE id=43;

-- Arlindo Borges (CBG: Arlindo Borges Correia, 16033)
UPDATE players SET hcp_index=11.6, no_federado='16033' WHERE id=7;

-- Barry Pussell (CBG: Barry Pussell, 20084)
UPDATE players SET hcp_index=4.0, no_federado='20084' WHERE id=134;

-- Brady Beauchamp (CBG: Brady Beauchamp, 15597)
UPDATE players SET hcp_index=0.1, no_federado='15597' WHERE id=2;

-- Bruno Ramos Ferreira (CBG: Bruno Ramos, 16051)
UPDATE players SET hcp_index=23.9, no_federado='16051' WHERE id=115;

-- Carlos Alberto Arouca (CBG: Carlos Alberto Arouca, 16052)
UPDATE players SET hcp_index=25.8, no_federado='16052' WHERE id=55;

-- Carlos Eduardo Ferreira (CBG: Carlos Eduardo Ferreira, 10130) — Profissional, HCP=0
UPDATE players SET hcp_index=0.0, no_federado='10130' WHERE id=85;

-- Carlos Moreira (CBG: Carlos Moreira, 15553)
UPDATE players SET hcp_index=15.1, no_federado='15553' WHERE id=17;

-- Chang Vang (CBG: Chang Vang Thiz, 15628)
UPDATE players SET hcp_index=16.1, no_federado='15628' WHERE id=25;

-- Chip Dodel (CBG: Charles (Chip) Dodel, 15955)
UPDATE players SET hcp_index=2.1, no_federado='15955' WHERE id=118;

-- Clovis Infante (CBG: Clovis Brum Infante, 15460)
UPDATE players SET hcp_index=16.7, no_federado='15460' WHERE id=104;

-- Daniel Peres (CBG: Daniel Peres de Souza, 15753)
UPDATE players SET hcp_index=20.6, no_federado='15753' WHERE id=44;

-- Dario Conca (CBG: Dario Leonardo Conca, 16027)
UPDATE players SET hcp_index=9.8, no_federado='16027' WHERE id=87;

-- Diego Munoz (CBG: Diego Munoz Ortega, 15472)
UPDATE players SET hcp_index=22.6, no_federado='15472' WHERE id=136;

-- Domingos Borges Leal Neto (CBG: Domingos Leal Borges, 15792)
UPDATE players SET hcp_index=24.6, no_federado='15792' WHERE id=69;

-- Edmundo Julio Jung Marques (CBG: Edmundo Jung Marques, 15948)
UPDATE players SET hcp_index=30.6, no_federado='15948' WHERE id=51;

-- Eduardo Henrique Dantas (CBG: Eduardo Henrique Dantas, 16118)
UPDATE players SET hcp_index=30.6, no_federado='16118' WHERE id=59;

-- Ercole A Talarico (CBG: Ercole Antonio Talarico, 15155)
UPDATE players SET hcp_index=22.6, no_federado='15155' WHERE id=35;

-- Felipe Farias Da Costa (CBG: Felipe Farias de Oliveira Costa, 15870)
UPDATE players SET hcp_index=21.2, no_federado='15870' WHERE id=40;

-- Fernando Fernandes (CBG: Fernando Fernandes, 15487)
UPDATE players SET hcp_index=16.9, no_federado='15487' WHERE id=19;

-- Fernando Olinto (CBG: Fernando Prado Lopes Olinto, 20085)
UPDATE players SET hcp_index=16.9, no_federado='20085' WHERE id=125;

-- Glauco Vasconcellos da Silva Ramos (CBG: Glauco Da Silva Ramos Vasconcellos, 15878)
UPDATE players SET hcp_index=26.0, no_federado='15878' WHERE id=50;

-- Gregorio Del Val Gandullo (CBG: Gregorio Del Val Gandullo, 15796)
UPDATE players SET hcp_index=7.2, no_federado='15796' WHERE id=63;

-- Gustavo Rocha Freire (CBG: Gustavo Rocha Veloso Freire, 15911)
UPDATE players SET hcp_index=22.9, no_federado='15911' WHERE id=34;

-- Gustavo Scofano (CBG: Gustavo Calvo Scofano, 15716)
UPDATE players SET hcp_index=22.7, no_federado='15716' WHERE id=91;

-- Helio Isaac Barki (CBG: Helio Isaac Barki, 15010)
UPDATE players SET hcp_index=11.3, no_federado='15010' WHERE id=84;

-- Jens Gaardsvig (CBG: Jens Gaardsvig, 15421)
UPDATE players SET hcp_index=19.5, no_federado='15421' WHERE id=83;

-- João Moreira (CBG: Joao Moreira, 15640)
UPDATE players SET hcp_index=32.3, no_federado='15640' WHERE id=112;

-- John Richard West (CBG: John Richard West, 15578)
UPDATE players SET hcp_index=25.2, no_federado='15578' WHERE id=71;

-- Jorge Rodrigues (CBG: Jorge Rodrigues da Silva Neto, 16127)
UPDATE players SET hcp_index=23.6, no_federado='16127' WHERE id=114;

-- Jorge Traspadini (CBG: Jorge Traspadini, 15525)
UPDATE players SET hcp_index=10.2, no_federado='15525' WHERE id=117;

-- José Bueno (CBG: Jose Bueno, 15559)
UPDATE players SET hcp_index=33.3, no_federado='15559' WHERE id=103;

-- José Carlos Silveira Bruno (CBG: Jose Carlos Silveira Bruno, 16150)
UPDATE players SET hcp_index=19.2, no_federado='16150' WHERE id=137;

-- José Luís López Betanzo (CBG: Jose Luis Lopez Betanzo, 16063)
UPDATE players SET hcp_index=17.8, no_federado='16063' WHERE id=119;

-- Jose Ricardo Trigo (CBG: Jose Ricardo Trigo, 15609)
UPDATE players SET hcp_index=20.6, no_federado='15609' WHERE id=23;

-- Lucas Nercessian (CBG: Lucas Nercessian, 19256)
UPDATE players SET hcp_index=21.5, no_federado='19256' WHERE id=81;

-- Luis Ernesto Delgado (CBG: Luis E. Delgado Reyes, 15740)
UPDATE players SET hcp_index=19.3, no_federado='15740' WHERE id=33;

-- Marcelo Klujsza (CBG: Marcelo Klujza, 16236)
UPDATE players SET hcp_index=15.8, no_federado='16236' WHERE id=21;

-- Marcelo Merlo (CBG: Marcelo Thomasi Merlo, 15502)
UPDATE players SET hcp_index=20.4, no_federado='15502' WHERE id=16;

-- Marcos Martins (CBG: Marcos J. B. Martins, 15606)
UPDATE players SET hcp_index=17.3, no_federado='15606' WHERE id=24;

-- Marcos Dias (CBG: Marcos Teixeira Dias, 15900)
UPDATE players SET hcp_index=7.4, no_federado='15900' WHERE id=9;

-- Mario Colmenares (CBG: Mario Colmenares, 16008)
UPDATE players SET hcp_index=18.4, no_federado='16008' WHERE id=29;

-- Mark Lloyd (CBG: Mark Lloyd, 16070)
UPDATE players SET hcp_index=12.3, no_federado='16070' WHERE id=12;

-- Martín de la Rosa (CBG: Martin Ramiro De La Rosa, 15722)
UPDATE players SET hcp_index=15.5, no_federado='15722' WHERE id=78;

-- Matheus Hernandes (CBG: Matheus Hernandes, 15928)
UPDATE players SET hcp_index=26.9, no_federado='15928' WHERE id=128;

-- Mauro Saito (CBG: Mauro Tomio Saito, 15480)
UPDATE players SET hcp_index=18.8, no_federado='15480' WHERE id=39;

-- Oeyvind Gomnaes (CBG: Oeyvind Gomnaes (Even), 15473)
UPDATE players SET hcp_index=25.9, no_federado='15473' WHERE id=46;

-- Paulo Cesar da Silva (CBG: Paulo Cesar da Silva, 15245)
UPDATE players SET hcp_index=14.6, no_federado='15245' WHERE id=14;

-- Paulo Marcio Mauro (CBG: Paulo Marcio Mauro, 15621)
UPDATE players SET hcp_index=28.8, no_federado='15621' WHERE id=53;

-- Paulo Ricardo Pinto (CBG: Paulo Ricardo De Oliveira Pinto, 14980)
UPDATE players SET hcp_index=25.3, no_federado='14980' WHERE id=54;

-- Pedro Luiz de Souza Pinto Filho (CBG: Pedro Luiz De Souza Pinto Filho, 15575)
UPDATE players SET hcp_index=14.2, no_federado='15575' WHERE id=79;

-- Rafael Racy (CBG: Rafael Racy, 15809)
UPDATE players SET hcp_index=9.6, no_federado='15809' WHERE id=105;

-- Regis Fichtner (CBG: Régis Fichtner, 15413)
UPDATE players SET hcp_index=20.7, no_federado='15413' WHERE id=36;

-- Bob / Robert Donaldson (CBG: Robert (Bob) Donaldson, 16035)
UPDATE players SET hcp_index=9.7, no_federado='16035' WHERE id=13;

-- Roberto Fernandes (CBG: Roberto André da Silva Fernandes, 15827)
UPDATE players SET hcp_index=10.8, no_federado='15827' WHERE id=4;

-- Roberto Fiani (CBG: Roberto Fiani, 15920)
UPDATE players SET hcp_index=20.6, no_federado='15920' WHERE id=37;

-- Roberto Maueler (CBG: Roberto Maueler, 15770)
UPDATE players SET hcp_index=11.0, no_federado='15770' WHERE id=11;

-- Rodrigo da Silva Almeida (CBG: Rodrigo Da Silva Almeida, 15779)
UPDATE players SET hcp_index=25.0, no_federado='15779' WHERE id=80;

-- Rodrigo Mendes (CBG: Rodrigo Mendes De Brito, 15880)
UPDATE players SET hcp_index=13.6, no_federado='15880' WHERE id=32;

-- Rolf Palm (CBG: Rolf Palm, 16121)
UPDATE players SET hcp_index=16.5, no_federado='16121' WHERE id=133;

-- Scott Radeztsky (CBG: Scoot Redlezstky, 16095)
UPDATE players SET hcp_index=10.7, no_federado='16095' WHERE id=10;

-- Sebastián Sarrido (CBG: Sebastian Mario Sarrido, 15667)
UPDATE players SET hcp_index=18.8, no_federado='15667' WHERE id=64;

-- Sergio Pinto (CBG: Sergio Augusto Pinto, 15296)
UPDATE players SET hcp_index=21.3, no_federado='15296' WHERE id=30;

-- Sergio Barbosa Pereira (CBG: Sergio Barbosa Pereira, 15649)
UPDATE players SET hcp_index=22.6, no_federado='15649' WHERE id=49;

-- Stefanno Dias (CBG: Stefanon de Spolavori Dias, 15855)
UPDATE players SET hcp_index=6.6, no_federado='15855' WHERE id=6;

-- Thiago Martins (CBG: Thiago Baptista Martins, 16061)
UPDATE players SET hcp_index=17.7, no_federado='16061' WHERE id=124;

-- Robert Thomas (CBG: Thomas Robert, 15778) — ATENÇÃO: nomes invertidos, confirme se é o mesmo jogador
UPDATE players SET hcp_index=23.8, no_federado='15778' WHERE id=38;

-- Vicente Jesus (CBG: Vicente Jesus de Sousa, 15463)
UPDATE players SET hcp_index=4.4, no_federado='15463' WHERE id=3;


-- ============================================================
-- CASOS INCERTOS — descomente após confirmar manualmente
-- ============================================================

-- Evandro Mendes Teixeira da Silva (CBG: Ernesto Méndes Teixeira da Silva, 16012) — confirmado pelo admin
UPDATE players SET hcp_index=27.3, no_federado='16012' WHERE id=47;

-- DB id=135 "Geremias Souza"
-- CBG 15526 "Geremias Braz" HCP=13.9
-- Mesmo primeiro nome, sobrenome diferente. Confirme se é a mesma pessoa.
-- UPDATE players SET hcp_index=13.9, no_federado='15526' WHERE id=135;


-- ============================================================
-- JOGADORES DA LIGA SEM CORRESPONDÊNCIA NA LISTA CBG
-- (sem no_federado — podem ser de outro clube ou não federados)
-- ============================================================
-- id=26  Adolfo Gentil
-- id=129 Alexsander Praxedes (Nestor)
-- id=15  Alfredo "Jakarê" Teixeira
-- id=116 Antonio Pereira da Costa
-- id=131 Celso Bueno
-- id=48  Cesar Silva
-- id=108 Daniele Santinoni
-- id=96  Elen Siqueira da Silva Garcia
-- id=122 Emanuel Pereira
-- id=73  Fabio Meirelles Gonçalves
-- id=121 Florentina Dahmen von Buchholz
-- id=130 Gabriel Calçada
-- id=90  Guilherme Rothier
-- id=60  Henrique Jatobá
-- id=123 Jean François Allard
-- id=57  Jorge Pereira de Almeida
-- id=62  João Victor Lahmann
-- id=100 Kleber Ramos
-- id=88  Laerte Fernandes de Melo
-- id=52  Leonardo de Souza Urpia
-- id=127 Léo Brasil
-- id=27  Marcelo Cruz
-- id=5   Marcelo Modesto
-- id=126 Marcelo Monteiro
-- id=98  Marian Labrador
-- id=99  María Alves Del Val
-- id=8   Miguel Santinoni
-- id=1   Patrick Amorim
-- id=102 Pedro Henrique Nordi
-- id=95  Priscila Gávio
-- id=97  Priscilla Wandelli
-- id=110 Rogerio Ferneda
-- id=86  Sean Butler
-- id=106 Tania Wang
-- id=74  Wandelli
-- id=61  Vinicius Terk Cruz
-- id=75  José Francisco
-- id=111 Carlos Hirata
