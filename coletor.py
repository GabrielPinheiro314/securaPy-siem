import os

def parsear_linha_auth(linha):
    """Parseia uma linha do auth.log e retorna dict normalizado."""
    partes = linha.strip().split()
    if len(partes) < 5:
        raise ValueError("Linha mal formatada (menos de 5 partes)")
    
    timestamp = f"{partes[0]} {partes[1]}"
    tipo = partes[2]
    
    usuario = ""
    ip = ""
    for parte in partes[3:]:
        if "=" in parte:
            chave, valor = parte.split("=", 1)
            if chave == "usuario":
                usuario = valor
            elif chave == "ip":
                ip = valor
                
    detalhes = f"usuario={usuario}"
    
    return {
        "timestamp": timestamp,
        "fonte": "auth",
        "tipo": tipo,
        "ip": ip,
        "detalhes": detalhes,
        "linha_original": linha.strip()
    }

def parsear_linha_firewall(linha):
    """Parseia uma linha do firewall.log e retorna dict normalizado."""
    partes = linha.strip().split()
    if len(partes) < 7:
        raise ValueError("Linha mal formatada (menos de 7 partes)")
        
    timestamp = f"{partes[0]} {partes[1]}"
    tipo = partes[2] 
    
    proto = ""
    ip_src = ""
    ip_dst = ""
    dport = ""
    
    for parte in partes[3:]:
        if "=" in parte:
            chave, valor = parte.split("=", 1)
            if chave == "proto": proto = valor
            elif chave == "src": ip_src = valor
            elif chave == "dst": ip_dst = valor
            elif chave == "dport": dport = valor
            
    detalhes = f"proto={proto} dst={ip_dst} dport={dport}"
    
    return {
        "timestamp": timestamp,
        "fonte": "firewall",
        "tipo": tipo,
        "ip": ip_src,
        "detalhes": detalhes,
        "linha_original": linha.strip()
    }

def parsear_linha_web(linha):
    """Parseia uma linha do web_access.log e retorna dict normalizado."""
    partes = linha.strip().split()
    if len(partes) < 6:
        raise ValueError("Linha mal formatada (menos de 6 partes)")
        
    timestamp = f"{partes[0]} {partes[1]}"
    tipo = partes[2]
    
    url = ""
    ip = ""
    status = ""
    
    for parte in partes[3:]:
        if "=" in parte:
            chave, valor = parte.split("=", 1)
            if chave == "url": url = valor
            elif chave == "ip": ip = valor
            elif chave == "status": status = valor
            
    detalhes = f"url={url} status={status}"
    
    return {
        "timestamp": timestamp,
        "fonte": "web",
        "tipo": tipo,
        "ip": ip,
        "detalhes": detalhes,
        "linha_original": linha.strip()
    }

def carregar_log(caminho_arquivo, fonte):
    """
    Lê um arquivo de log e retorna lista de eventos normalizados.
    - caminho_arquivo: str com o path do arquivo
    - fonte: str indicando o tipo ("auth", "firewall", "web")
    - Retorna: list[dict] com os eventos parseados
    """
    eventos = []
    try:
        if os.path.getsize(caminho_arquivo) == 0:
            print(f"Arquivo vazio: {caminho_arquivo}")
            return eventos
            
        with open(caminho_arquivo, "r", encoding="utf-8") as f:
            for num_linha, linha in enumerate(f, 1):
                linha = linha.strip()
                if not linha:
                    continue
                try:
                    if fonte == "auth":
                        evento = parsear_linha_auth(linha)
                    elif fonte == "firewall":
                        evento = parsear_linha_firewall(linha)
                    elif fonte == "web":
                        evento = parsear_linha_web(linha)
                    else:
                        raise ValueError(f"Fonte desconhecida: {fonte}")
                        
                    eventos.append(evento)
                except Exception as e:
                    print(f"Aviso: Erro ao processar linha {num_linha} em {caminho_arquivo}: {e}")
                    
    except FileNotFoundError:
        print(f"Erro: Arquivo não encontrado: {caminho_arquivo}")
    except Exception as e:
        print(f"Erro inesperado ao ler {caminho_arquivo}: {e}")
        
    return eventos

def carregar_todos_os_logs(pasta_logs):
    """
    Lê todos os arquivos de log da pasta e retorna lista unificada.
    Usa os.listdir() para encontrar os arquivos.
    """
    todos_eventos = []
    
    if not os.path.exists(pasta_logs):
        print(f"A pasta {pasta_logs} não existe.")
        return todos_eventos
        
    arquivos = os.listdir(pasta_logs)
    
    for arquivo in arquivos:
        caminho_completo = os.path.join(pasta_logs, arquivo)
        if not os.path.isfile(caminho_completo):
            continue
            
        fonte = None
        if "auth" in arquivo.lower():
            fonte = "auth"
        elif "firewall" in arquivo.lower():
            fonte = "firewall"
        elif "web" in arquivo.lower():
            fonte = "web"
            
        if fonte:
            eventos = carregar_log(caminho_completo, fonte)
            todos_eventos.extend(eventos)
        else:
            print(f"Ignorando arquivo desconhecido: {arquivo}")
            
    return todos_eventos
