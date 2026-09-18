import json
import os

def carregar_regras(caminho_config):
    """
    Lê o arquivo regras.json e retorna lista de dicionários de regras.
    Trata: arquivo não encontrado, JSON inválido.
    """
    try:
        if not os.path.exists(caminho_config):
            print(f"Erro: Arquivo de regras não encontrado em {caminho_config}")
            return []
            
        with open(caminho_config, "r", encoding="utf-8") as f:
            dados = json.load(f)
            return dados.get("regras", [])
            
    except json.JSONDecodeError as e:
        print(f"Erro: JSON inválido no arquivo {caminho_config}: {e}")
        return []
    except Exception as e:
        print(f"Erro ao tentar carregar as regras: {e}")
        return []

def classificar_severidade(pontuacao):
    """
    Recebe pontuação numérica e retorna string de severidade.
    >= 9: CRITICA, >= 7: ALTA, >= 5: MEDIA, >= 3: BAIXA, < 3: INFO
    """
    if pontuacao >= 9:
        return "CRITICA"
    elif pontuacao >= 7:
        return "ALTA"
    elif pontuacao >= 5:
        return "MEDIA"
    elif pontuacao >= 3:
        return "BAIXA"
    else:
        return "INFO"

def avaliar_regra(regra, evento):
    """
    Avalia se um evento viola uma regra específica.
    Retorna dict de alerta ou None.
    """
    if not regra.get("ativa", False):
        return None
        
    if regra.get("fonte") != evento.get("fonte"):
        return None

    condicao = regra.get("condicao")
    
    viola_regra = False
    
    if condicao == "usuario_privilegiado":
        detalhes = evento.get("detalhes", "")
        usuario = detalhes.split("usuario=")[-1].split()[0] if "usuario=" in detalhes else ""
        if usuario in regra.get("usuarios_alvo", []):
            viola_regra = True
            
    elif condicao == "porta_critica":
        if evento.get("tipo") == "BLOCK":
            detalhes = evento.get("detalhes", "")
            dport_str = detalhes.split("dport=")[-1].split()[0] if "dport=" in detalhes else ""
            if dport_str.isdigit():
                dport = int(dport_str)
                if dport in regra.get("portas_criticas", []):
                    viola_regra = True
                    
    elif condicao in ["path_traversal", "xss_injection"]:
        detalhes = evento.get("detalhes", "")
        url = detalhes.split("url=")[-1].split()[0] if "url=" in detalhes else ""
        for padrao in regra.get("padroes", []):
            if padrao in url:
                viola_regra = True
                break
                
    elif condicao == "reconhecimento":
        detalhes = evento.get("detalhes", "")
        url = detalhes.split("url=")[-1].split()[0] if "url=" in detalhes else ""
        for url_suspeita in regra.get("urls_suspeitas", []):
            if url_suspeita in url:
                viola_regra = True
                break

    if viola_regra:
        severidade = classificar_severidade(regra.get("severidade_base", 1))
        return {
            "timestamp": evento.get("timestamp"),
            "regra_id": regra.get("id"),
            "regra_nome": regra.get("nome"),
            "severidade": severidade,
            "ip": evento.get("ip"),
            "descricao": regra.get("descricao"),
            "linha_original": evento.get("linha_original")
        }
        
    return None

def aplicar_regras(eventos, regras):
    """
    Recebe lista de eventos e lista de regras.
    Retorna lista de alertas gerados.
    Cada alerta é um dict com: timestamp, regra, severidade, ip, descricao.
    """
    alertas = []
    for evento in eventos:
        for regra in regras:
            alerta = avaliar_regra(regra, evento)
            if alerta:
                alertas.append(alerta)
    return alertas
