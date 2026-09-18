import requests

def eh_ip_privado(ip):
    """
    Verifica se um IP é de rede privada (RFC 1918).
    Retorna True para 10.x.x.x, 172.16-31.x.x, 192.168.x.x
    """
    partes = ip.split(".")
    if len(partes) != 4:
        return False
        
    try:
        oct1 = int(partes[0])
        oct2 = int(partes[1])
        
        if oct1 == 10:
            return True
        if oct1 == 172 and 16 <= oct2 <= 31:
            return True
        if oct1 == 192 and oct2 == 168:
            return True
        if oct1 == 127: # loopback
            return True
    except:
        pass
        
    return False

def consultar_ip(ip, cache):
    """
    Consulta ipinfo.io para obter dados do IP.
    Usa cache (dict) para evitar consultas repetidas.
    Retorna dict com: ip, cidade, regiao, pais, org, hostname
    """
    if ip in cache:
        return cache[ip]
        
    if eh_ip_privado(ip):
        resultado = {
            "ip": ip,
            "cidade": "-",
            "regiao": "-",
            "pais": "Rede Interna",
            "org": "Local",
            "hostname": "-"
        }
        cache[ip] = resultado
        return resultado
        
    try:
        resposta = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if resposta.status_code == 200:
            dados = resposta.json()
            resultado = {
                "ip": ip,
                "cidade": dados.get("city", "Desconhecida"),
                "regiao": dados.get("region", "Desconhecida"),
                "pais": dados.get("country", "Desconhecido"),
                "org": dados.get("org", "Desconhecida"),
                "hostname": dados.get("hostname", "-")
            }
        elif resposta.status_code == 429:
            resultado = {"ip": ip, "erro": "Limite de requisições excedido"}
        else:
            resultado = {"ip": ip, "erro": f"Status {resposta.status_code}"}
    except requests.exceptions.Timeout:
        resultado = {"ip": ip, "erro": "Timeout na consulta"}
    except requests.exceptions.RequestException:
        resultado = {"ip": ip, "erro": "Erro de rede/API indisponível"}
        
    cache[ip] = resultado
    return resultado

def enriquecer_alertas(alertas, cache):
    """
    Recebe lista de alertas e adiciona informações de geolocalização.
    Pula IPs privados (marca como "Rede Interna").
    Retorna alertas enriquecidos.
    """
    alertas_enriquecidos = []
    for alerta in alertas:
        ip = alerta.get("ip")
        if ip:
            dados_ip = consultar_ip(ip, cache)
            # Cria uma cópia do alerta e adiciona os dados de inteligência
            alerta_novo = alerta.copy()
            alerta_novo["inteligencia"] = dados_ip
            alertas_enriquecidos.append(alerta_novo)
        else:
            alertas_enriquecidos.append(alerta)
            
    return alertas_enriquecidos

def exibir_enriquecimento(dados_ip):
    """Exibe as informações do IP de forma formatada."""
    if "erro" in dados_ip:
        print(f"  [INTELIGÊNCIA] Erro: {dados_ip['erro']}")
    elif dados_ip.get("pais") == "Rede Interna":
        print(f"  [INTELIGÊNCIA] IP de Rede Interna / Privada")
    else:
        cidade = dados_ip.get('cidade')
        pais = dados_ip.get('pais')
        org = dados_ip.get('org')
        print(f"  [INTELIGÊNCIA] Origem: {cidade}, {pais} (Provedor: {org})")
