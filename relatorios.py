import json
import os
from datetime import datetime

def exibir_menu():
    """Exibe o menu principal e retorna a opção escolhida (validada)."""
    print("\n" + "="*44)
    print("|         SecuraPy SIEM — Menu             |")
    print("+" + "-"*42 + "+")
    print("|  1. Carregar e processar logs            |")
    print("|  2. Resumo geral                         |")
    print("|  3. Filtrar eventos                      |")
    print("|  4. Buscar IP                            |")
    print("|  5. Top 10 IPs suspeitos                 |")
    print("|  6. Ver alertas por severidade           |")
    print("|  7. Enriquecer IPs suspeitos             |")
    print("|  8. Exportar relatório JSON              |")
    print("|  0. Sair                                 |")
    print("=" + "="*42 + "=")
    
    while True:
        try:
            opcao = int(input("\nEscolha uma opção: "))
            if 0 <= opcao <= 8:
                return opcao
            print("Opção inválida. Escolha um número entre 0 e 8.")
        except ValueError:
            print("Entrada inválida. Digite apenas números.")

def resumo_geral(eventos, alertas):
    """Exibe contadores gerais: eventos por fonte, alertas por severidade."""
    if not eventos:
        print("\n[!] Nenhum log carregado. Use a opção 1 primeiro.")
        return
        
    fontes = {}
    for e in eventos:
        f = e.get("fonte", "desconhecido")
        fontes[f] = fontes.get(f, 0) + 1
        
    sevs = {}
    for a in alertas:
        s = a.get("severidade", "INFO")
        sevs[s] = sevs.get(s, 0) + 1
        
    print("\n--- RESUMO GERAL ---")
    print("Total de Eventos:", len(eventos))
    for f, count in fontes.items():
        print(f"  - {f}: {count}")
        
    print("\nTotal de Alertas:", len(alertas))
    for s, count in sevs.items():
        print(f"  - {s}: {count}")

def filtrar_eventos(eventos, fonte=None, tipo=None, ip=None):
    """Retorna eventos filtrados pelos critérios. None = sem filtro."""
    filtrados = []
    for e in eventos:
        if fonte and e.get("fonte") != fonte:
            continue
        if tipo and e.get("tipo") != tipo:
            continue
        if ip and e.get("ip") != ip:
            continue
        filtrados.append(e)
    return filtrados

def buscar_ip(ip, eventos, alertas, cache_enriquecimento):
    """Exibe relatório completo de um IP: eventos, alertas, geolocalização."""
    evs = filtrar_eventos(eventos, ip=ip)
    alts = [a for a in alertas if a.get("ip") == ip]
    
    print(f"\n--- RELATÓRIO DO IP: {ip} ---")
    
    if cache_enriquecimento and ip in cache_enriquecimento:
        dados = cache_enriquecimento[ip]
        if dados.get("pais") == "Rede Interna":
            print(f"Origem: Rede Interna / Privada")
        elif "erro" not in dados:
            print(f"Origem: {dados.get('cidade')}, {dados.get('pais')} - {dados.get('org')}")
            
    print(f"\nTotal de eventos associados: {len(evs)}")
    print(f"Total de alertas gerados: {len(alts)}")
    
    if alts:
        print("\nAlertas:")
        for a in alts:
            print(f"  [{a['timestamp']}] [{a['severidade']}] {a['regra']}")

def top_ips(eventos, n=10):
    """Retorna os N IPs com mais eventos, com contagem e classificação."""
    if not eventos:
        print("\n[!] Nenhum log carregado.")
        return
        
    contagem = {}
    for e in eventos:
        ip = e.get("ip")
        if ip:
            contagem[ip] = contagem.get(ip, 0) + 1
            
    lista = sorted(contagem.items(), key=lambda item: item[1], reverse=True)[:n]
    
    print(f"\n--- TOP {n} IPs OFENSORES ---")
    for i, (ip, count) in enumerate(lista, 1):
        print(f"{i}. {ip:<15} : {count} eventos")

def exportar_relatorio_json(dados, caminho_pasta="saida"):
    """Salva relatório completo em JSON formatado."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    caminho_real = os.path.join(base_dir, caminho_pasta)
    os.makedirs(caminho_real, exist_ok=True)
    nome_arquivo = datetime.now().strftime("relatorio_%Y%m%d_%H%M%S.json")
    caminho_completo = os.path.join(caminho_real, nome_arquivo)
    
    try:
        with open(caminho_completo, 'w', encoding='utf-8') as f:
            json.dump(dados, f, indent=2, ensure_ascii=False)
        print(f"\n[OK] Relatório exportado com sucesso: {caminho_completo}")
    except Exception as e:
        print(f"\n[ERRO] Falha ao exportar relatório: {e}")

def exibir_tabela(dados_alertas):
    """Exibe uma lista de dicts (alertas) como tabela formatada no terminal."""
    if not dados_alertas:
        print("\nNenhum alerta para exibir.")
        return
        
    print(f"\n{'-'*90}")
    print(f"{'DATA/HORA':<20} | {'SEVERIDADE':<10} | {'IP ORIGEM':<15} | {'REGRA VIOLADA'}")
    print(f"{'-'*90}")
    
    for a in dados_alertas:
        ts = a.get('timestamp', '')[:19]
        sev = a.get('severidade', '')
        ip = a.get('ip', '')
        regra_nome = (a.get('regra') or a.get('nome') or a.get('descricao') or '')[:35]
        print(f"{ts:<20} | {sev:<10} | {ip:<15} | {regra_nome}")
    print(f"{'-'*90}")
