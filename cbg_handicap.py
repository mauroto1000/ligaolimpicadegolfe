"""
Consulta de Handicap Index na Confederação Brasileira de Golfe (CBG).
URL: https://scoring.cbgolfe.com.br/lists/FederatedsList_V2.aspx

Fluxo ASPX (ASP.NET WebForms):
  1. GET  → extrai __VIEWSTATE, __EVENTVALIDATION e demais campos ocultos
  2. POST → preenche o Nº Federado e dispara a busca
  3. Parse → extrai a linha da tabela com os dados do jogador
"""

import requests
from bs4 import BeautifulSoup

CBG_URL = "https://scoring.cbgolfe.com.br/lists/FederatedsList_V2.aspx"

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8",
    "Referer": CBG_URL,
}


def _extrair_campos_form(soup):
    """Retorna dict com todos os campos <input> do formulário (nome → valor)."""
    campos = {}
    for inp in soup.find_all("input"):
        nome = inp.get("name")
        if nome:
            campos[nome] = inp.get("value", "")
    return campos


def _identificar_campos(soup, campos):
    """
    Tenta identificar automaticamente os campos de NOME, Nº FEDERADO e botão.
    Retorna (campo_nome, campo_nofed, campo_botao).
    """
    campo_nome = campo_nofed = campo_botao = None

    # Prioridade: procurar por ID/name com palavras-chave
    for nome in campos:
        lower = nome.lower()
        if any(k in lower for k in ("nofed", "no_fed", "federado", "numfed", "num_fed", "txtfed", "txtnofed")):
            campo_nofed = nome
        elif any(k in lower for k in ("txtnome", "txt_nome", "nome")) and "fed" not in lower:
            campo_nome = nome

    # Fallback: usar a ordem dos <input type="text"> no formulário
    if not campo_nofed:
        text_inputs = [
            inp.get("name")
            for inp in soup.find_all("input", type="text")
            if inp.get("name")
        ]
        if len(text_inputs) >= 2:
            campo_nome = campo_nome or text_inputs[0]
            campo_nofed = text_inputs[1]
        elif len(text_inputs) == 1:
            campo_nofed = text_inputs[0]

    # Botão de busca (submit com texto "Procura" / "Pesquis" / "Busca")
    for btn in soup.find_all("input", type="submit"):
        val = btn.get("value", "")
        if any(k in val.lower() for k in ("procura", "pesquis", "busca", "search", "ok")):
            campo_botao = btn.get("name")
            if campo_botao:
                campos[campo_botao] = val
            break

    return campo_nome, campo_nofed, campo_botao


def discover_campos():
    """
    Debug: retorna todos os campos do formulário da CBG para inspeção.
    Útil para ajustar os nomes dos campos caso a consulta falhe.
    """
    session = requests.Session()
    r = session.get(CBG_URL, headers=_HEADERS, timeout=15)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    campos = _extrair_campos_form(soup)
    texto_inputs = [
        {"name": inp.get("name"), "id": inp.get("id"), "type": inp.get("type"), "value": inp.get("value", "")}
        for inp in soup.find_all("input")
        if inp.get("name")
    ]
    return {"campos": campos, "inputs": texto_inputs}


def consultar_hcp_cbg(no_federado):
    """
    Consulta o Handicap Index de um jogador na CBG pelo Nº Federado.

    Retorna dict:
        {
            'no_federado': '15480',
            'nome':        'Mauro Tomio Saito',
            'clube':       'Campo Olímpico (RJ02)',
            'hcp':         '18.8',           # string conforme retorna o site
            'hcp_float':   18.8,             # float para uso no banco
            'estado_hcp':  'Válido',
            'am_pro':      'AM',
            'sexo':        'M',
            'escalao':     'Pré-Senior',
            'estado_fed':  'Ativo',
        }
    Retorna None se o jogador não for encontrado ou ocorrer erro.
    """
    try:
        session = requests.Session()

        # 1. GET — obtém os campos ocultos do ASPX
        r = session.get(CBG_URL, headers=_HEADERS, timeout=15)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        campos = _extrair_campos_form(soup)

        # 2. Identificar campos do formulário
        campo_nome, campo_nofed, campo_botao = _identificar_campos(soup, campos)

        if not campo_nofed:
            print("[CBG] AVISO: campo Nº Federado não identificado automaticamente.")
            print("[CBG] Use discover_campos() para inspecionar o formulário.")
            return None

        # 3. Preencher e enviar
        if campo_nome:
            campos[campo_nome] = ""
        campos[campo_nofed] = str(no_federado)

        post_headers = {**_HEADERS, "Content-Type": "application/x-www-form-urlencoded"}
        r2 = session.post(CBG_URL, data=campos, headers=post_headers, timeout=15)
        r2.raise_for_status()

        # 4. Parse da tabela de resultados
        soup2 = BeautifulSoup(r2.text, "html.parser")
        no_fed_str = str(no_federado).strip()

        for table in soup2.find_all("table"):
            for row in table.find_all("tr"):
                cells = row.find_all("td")
                if not cells:
                    continue
                celula_fed = cells[0].get_text(strip=True)
                if celula_fed == no_fed_str:
                    data = [c.get_text(strip=True) for c in cells]
                    hcp_str = data[3] if len(data) > 3 else None
                    hcp_float = None
                    if hcp_str:
                        try:
                            hcp_float = float(hcp_str.replace(",", "."))
                        except ValueError:
                            pass
                    return {
                        "no_federado": data[0] if len(data) > 0 else None,
                        "nome":        data[1] if len(data) > 1 else None,
                        "clube":       data[2] if len(data) > 2 else None,
                        "hcp":         hcp_str,
                        "hcp_float":   hcp_float,
                        "estado_hcp":  data[4] if len(data) > 4 else None,
                        "am_pro":      data[5] if len(data) > 5 else None,
                        "sexo":        data[6] if len(data) > 6 else None,
                        "escalao":     data[7] if len(data) > 7 else None,
                        "estado_fed":  data[8] if len(data) > 8 else None,
                    }

        # Não encontrado na tabela
        return None

    except requests.RequestException as e:
        print(f"[CBG] Erro de rede: {e}")
        return None
    except Exception as e:
        print(f"[CBG] Erro inesperado: {e}")
        return None
