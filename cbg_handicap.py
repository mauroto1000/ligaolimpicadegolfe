"""
Consulta de Handicap Index na Confederação Brasileira de Golfe (CBG).
URL: https://scoring.cbgolfe.com.br/lists/FederatedsList_V2.aspx

A página renderiza o formulário via JavaScript, por isso usamos Playwright
(browser headless) como estratégia principal. O fallback via requests+BS4
só funciona se por algum motivo o HTML vier pré-renderizado.

Pré-requisito (executar uma vez no ambiente):
    pip install playwright
    playwright install chromium
"""

import requests
from bs4 import BeautifulSoup

CBG_ROOT    = "https://www.cbgolfe.com.br/"
CBG_SCORING = "https://scoring.cbgolfe.com.br/"
CBG_URL     = "https://scoring.cbgolfe.com.br/lists/FederatedsList_V2.aspx"
# Atalho para compatibilidade
CBG_BASE = CBG_SCORING

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8",
}


# ---------------------------------------------------------------------------
# Helpers compartilhados entre as duas estratégias
# ---------------------------------------------------------------------------

def _extrair_campos_form(soup):
    campos = {}
    for inp in soup.find_all("input"):
        nome = inp.get("name")
        if nome:
            campos[nome] = inp.get("value", "")
    return campos


def _identificar_campos(soup, campos):
    campo_nome = campo_nofed = campo_botao = None
    for nome in campos:
        lower = nome.lower()
        if any(k in lower for k in ("nofed", "no_fed", "federado", "numfed", "num_fed", "txtfed", "txtnofed")):
            campo_nofed = nome
        elif any(k in lower for k in ("txtnome", "txt_nome", "nome")) and "fed" not in lower:
            campo_nome = nome
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
    for btn in soup.find_all("input", type="submit"):
        val = btn.get("value", "")
        if any(k in val.lower() for k in ("procura", "pesquis", "busca", "search", "ok")):
            campo_botao = btn.get("name")
            if campo_botao:
                campos[campo_botao] = val
            break
    return campo_nome, campo_nofed, campo_botao


def _parse_tabela(soup, no_federado):
    """Extrai linha do jogador da tabela de resultados já parseada."""
    no_fed_str = str(no_federado).strip()
    for table in soup.find_all("table"):
        for row in table.find_all("tr"):
            cells = row.find_all("td")
            if not cells:
                continue
            if cells[0].get_text(strip=True) == no_fed_str:
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
    return None


# ---------------------------------------------------------------------------
# Estratégia 1: Playwright (headless browser, executa JavaScript)
# ---------------------------------------------------------------------------

def _consultar_via_playwright(no_federado):
    """
    Abre o site em browser headless, preenche o formulário e extrai o resultado.
    Requer: pip install playwright && playwright install chromium
    """
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.set_extra_http_headers({"Accept-Language": "pt-BR,pt;q=0.9"})
            page.goto(CBG_URL, timeout=30000)

            # Aguarda campos de texto aparecerem (renderizados por JS)
            page.wait_for_selector("input[type='text']", timeout=15000)

            # Identifica o campo de Nº Federado
            campo_nofed_el = None
            for inp in page.query_selector_all("input[type='text']"):
                name = (inp.get_attribute("name") or "").lower()
                id_attr = (inp.get_attribute("id") or "").lower()
                combined = name + id_attr
                if any(k in combined for k in ("nofed", "no_fed", "federado", "numfed", "fed")):
                    campo_nofed_el = inp
                    break

            if not campo_nofed_el:
                all_texts = page.query_selector_all("input[type='text']")
                if len(all_texts) >= 2:
                    campo_nofed_el = all_texts[1]
                elif all_texts:
                    campo_nofed_el = all_texts[0]

            if not campo_nofed_el:
                print("[CBG] Playwright: campo Nº Federado não encontrado mesmo após JS.")
                return None

            campo_nofed_el.triple_click()
            campo_nofed_el.fill(str(no_federado))

            # Localiza e clica no botão de busca
            btn = None
            for selector in ["input[type='submit']", "button[type='submit']", "input[type='button']"]:
                for b in page.query_selector_all(selector):
                    val = ((b.get_attribute("value") or "") + b.inner_text()).lower()
                    if any(k in val for k in ("procura", "pesquis", "busca", "search", "ok")):
                        btn = b
                        break
                if btn:
                    break

            if btn:
                btn.click()
            else:
                campo_nofed_el.press("Enter")

            page.wait_for_load_state("networkidle", timeout=20000)

            html = page.content()
            soup = BeautifulSoup(html, "html.parser")
            return _parse_tabela(soup, no_federado)

        except PWTimeout:
            print("[CBG] Playwright: timeout ao carregar a página.")
            return None
        finally:
            browser.close()


# ---------------------------------------------------------------------------
# Estratégia 2: requests + BeautifulSoup (fallback)
# ---------------------------------------------------------------------------

def _consultar_via_requests(no_federado):
    session = requests.Session()

    # Percorrer a cadeia de domínios para obter cookies SameSite da CBG
    for url_warmup, ref in [
        (CBG_ROOT,    None),
        (CBG_SCORING, CBG_ROOT),
        (CBG_URL,     CBG_SCORING),
    ]:
        try:
            h = {**_HEADERS}
            if ref:
                h["Referer"] = ref
            session.get(url_warmup, headers=h, timeout=15)
        except Exception:
            pass

    # GET final da lista de federados
    headers_get = {**_HEADERS, "Referer": CBG_SCORING}
    r = session.get(CBG_URL, headers=headers_get, timeout=15)
    r.raise_for_status()

    if "Err=999" in r.text or "Param Error" in r.text:
        print("[CBG] requests: erro de sessão (Err=999) — site ainda requer autenticação.")
        return None

    soup = BeautifulSoup(r.text, "html.parser")
    campos = _extrair_campos_form(soup)
    campo_nome, campo_nofed, campo_botao = _identificar_campos(soup, campos)
    if not campo_nofed:
        print("[CBG] requests: campo Nº Federado não identificado — página provavelmente requer JS.")
        return None
    if campo_nome:
        campos[campo_nome] = ""
    campos[campo_nofed] = str(no_federado)
    post_headers = {**_HEADERS, "Content-Type": "application/x-www-form-urlencoded", "Referer": CBG_URL}
    r2 = session.post(CBG_URL, data=campos, headers=post_headers, timeout=15)
    r2.raise_for_status()
    soup2 = BeautifulSoup(r2.text, "html.parser")
    return _parse_tabela(soup2, no_federado)


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------

def consultar_hcp_cbg(no_federado):
    """
    Consulta o Handicap Index de um jogador na CBG pelo Nº Federado.

    Retorna dict:
        {
            'no_federado': '15480',
            'nome':        'Mauro Tomio Saito',
            'clube':       'Campo Olímpico (RJ02)',
            'hcp':         '18.8',
            'hcp_float':   18.8,
            'estado_hcp':  'Válido',
            'am_pro':      'AM',
            'sexo':        'M',
            'escalao':     'Pré-Senior',
            'estado_fed':  'Ativo',
        }
    Retorna None se o jogador não for encontrado ou ocorrer erro.
    """
    # Tenta Playwright primeiro (lida com JS)
    try:
        return _consultar_via_playwright(no_federado)
    except ImportError:
        print("[CBG] Playwright não instalado — usando requests (pode falhar em páginas JS).")
    except Exception as e:
        print(f"[CBG] Erro com Playwright: {e} — usando requests como fallback.")

    # Fallback: requests
    try:
        return _consultar_via_requests(no_federado)
    except requests.RequestException as e:
        print(f"[CBG] Erro de rede: {e}")
        return None
    except Exception as e:
        print(f"[CBG] Erro inesperado: {e}")
        return None


def discover_campos():
    """
    Debug: retorna informações detalhadas sobre a página da CBG.
    Útil para diagnosticar alterações no formulário.
    """
    session = requests.Session()
    for url_warmup, ref in [
        (CBG_ROOT,    None),
        (CBG_SCORING, CBG_ROOT),
    ]:
        try:
            h = {**_HEADERS}
            if ref:
                h["Referer"] = ref
            session.get(url_warmup, headers=h, timeout=15)
        except Exception:
            pass
    r = session.get(CBG_URL, headers={**_HEADERS, "Referer": CBG_SCORING}, timeout=15)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    campos = _extrair_campos_form(soup)

    todos_inputs = [
        {
            "name": inp.get("name"),
            "id": inp.get("id"),
            "type": inp.get("type"),
            "value": inp.get("value", "")[:80],
        }
        for inp in soup.find_all("input")
    ]

    forms = [
        {"action": f.get("action"), "method": f.get("method"), "id": f.get("id")}
        for f in soup.find_all("form")
    ]

    import re
    scripts_src = [s.get("src") for s in soup.find_all("script") if s.get("src")]
    api_hints = []
    for s in soup.find_all("script"):
        text = s.string or ""
        matches = re.findall(r'(fetch|XMLHttpRequest|\.ajax|url\s*[:=]\s*)["\']([^"\']{5,120})["\']', text)
        api_hints.extend([m[1] for m in matches])

    html_amostra = r.text[:3000]

    return {
        "status_code": r.status_code,
        "url_final": r.url,
        "campos_hidden": campos,
        "todos_inputs": todos_inputs,
        "forms": forms,
        "scripts_src": scripts_src,
        "api_hints": api_hints,
        "html_amostra": html_amostra,
    }
