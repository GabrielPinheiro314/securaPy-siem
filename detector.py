def detectar_brute_force(eventos, threshold=5):
    """
    Conta tentativas FAIL por IP nos eventos de auth.
    Retorna dict: {ip: {"tentativas": N, "usuarios": [...], "severidade": "..."}}
    """
    contagem = {}
    for evento in eventos:
        if evento.get("fonte") == "auth" and evento.get("tipo") == "FAIL":
            ip = evento.get("ip")
            detalhes = evento.get("detalhes", "")
            usuario = detalhes.split("usuario=")[-1].split()[0] if "usuario=" in detalhes else "desconhecido"
            
            if ip not in contagem:
                contagem[ip] = {"tentativas": 0, "usuarios": set()}
            
            contagem[ip]["tentativas"] += 1
            contagem[ip]["usuarios"].add(usuario)
            
    resultados = {}
    for ip, dados in contagem.items():
        if dados["tentativas"] >= threshold:
            sev = "MEDIA"
            if dados["tentativas"] > 20:
                sev = "CRITICA"
            elif dados["tentativas"] > 10:
                sev = "ALTA"
                
            resultados[ip] = {
                "tentativas": dados["tentativas"],
                "usuarios": list(dados["usuarios"]),
                "severidade": sev,
                "motivo": "Brute Force"
            }
            
    return resultados

def detectar_port_scan(eventos, threshold=3):
    """
    Conta portas únicas (BLOCK) por IP nos eventos de firewall.
    Retorna dict: {ip: {"portas": set(...), "quantidade": N, "severidade": "..."}}
    """
    contagem = {}
    for evento in eventos:
        if evento.get("fonte") == "firewall" and evento.get("tipo") == "BLOCK":
            ip = evento.get("ip")
            detalhes = evento.get("detalhes", "")
            try:
                porta = int(detalhes.split("dport=")[-1].split()[0])
            except:
                continue
                
            if ip not in contagem:
                contagem[ip] = set()
            contagem[ip].add(porta)
            
    resultados = {}
    for ip, portas in contagem.items():
        if len(portas) >= threshold:
            sev = "MEDIA"
            if len(portas) > 10:
                sev = "CRITICA"
            elif len(portas) > 5:
                sev = "ALTA"
                
            resultados[ip] = {
                "portas": list(portas),
                "quantidade": len(portas),
                "severidade": sev,
                "motivo": "Port Scan"
            }
            
    return resultados

def verificar_blacklist(eventos, blacklist):
    """
    Cruza IPs dos eventos com a blacklist usando operações de set.
    Retorna set de IPs maliciosos encontrados e dict com contagem por IP.
    """
    ips_eventos = {evento.get("ip") for evento in eventos if evento.get("ip")}
    ips_encontrados = ips_eventos & blacklist
    
    contagem = {}
    for ip in ips_encontrados:
        contagem[ip] = sum(1 for e in eventos if e.get("ip") == ip)
        
    return ips_encontrados, contagem

def gerar_resumo_ameacas(brute_force, port_scan, ips_blacklist, contagem_blacklist):
    """
    Consolida todas as detecções em um resumo unificado.
    IPs que aparecem em múltiplas detecções têm severidade aumentada.
    Retorna lista de dicts ordenada por severidade.
    """
    resumo = {}
    
    # Processar Brute Force
    for ip, dados in brute_force.items():
        resumo[ip] = {"motivos": [dados["motivo"]], "pontuacao": 5 if dados["severidade"] == "MEDIA" else (7 if dados["severidade"] == "ALTA" else 9)}
        
    # Processar Port Scan
    for ip, dados in port_scan.items():
        if ip not in resumo:
            resumo[ip] = {"motivos": [], "pontuacao": 0}
        resumo[ip]["motivos"].append(dados["motivo"])
        resumo[ip]["pontuacao"] += 5 if dados["severidade"] == "MEDIA" else (7 if dados["severidade"] == "ALTA" else 9)
        
    # Processar Blacklist
    for ip in ips_blacklist:
        if ip not in resumo:
            resumo[ip] = {"motivos": [], "pontuacao": 0}
        resumo[ip]["motivos"].append("IP em Blacklist")
        resumo[ip]["pontuacao"] += 8
        
    # Formatar e classificar final
    lista_resumo = []
    for ip, dados in resumo.items():
        pts = dados["pontuacao"]
        if pts >= 9: sev = "CRITICA"
        elif pts >= 7: sev = "ALTA"
        elif pts >= 5: sev = "MEDIA"
        elif pts >= 3: sev = "BAIXA"
        else: sev = "INFO"
        
        lista_resumo.append({
            "ip": ip,
            "motivos": " + ".join(dados["motivos"]),
            "pontuacao": pts,
            "severidade_final": sev
        })
        
    lista_resumo.sort(key=lambda x: x["pontuacao"], reverse=True)
    return lista_resumo
