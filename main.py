import sys
from coletor import carregar_todos_os_logs
from regras import carregar_regras, aplicar_regras
from detector import (detectar_brute_force, detectar_port_scan, 
                     verificar_blacklist, gerar_resumo_ameacas)
from enriquecimento import enriquecer_alertas, consultar_ip
from relatorios import (exibir_menu, resumo_geral, filtrar_eventos, 
                       buscar_ip, top_ips, exportar_relatorio_json, exibir_tabela)

# Configurações
PASTA_LOGS = "logs"
ARQUIVO_REGRAS = "config/regras.json"
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}

def main():
    eventos = []
    alertas = []
    resumo_anomalias = []
    cache_enriquecimento = {}

    while True:
        opcao = exibir_menu()

        if opcao == 1:
            print("\n[INFO] Carregando logs...")
            eventos = carregar_todos_os_logs(PASTA_LOGS)
            print(f"[OK] {len(eventos)} eventos processados.")
            
            print("[INFO] Carregando regras...")
            regras = carregar_regras(ARQUIVO_REGRAS)
            print(f"[OK] {len(regras)} regras ativas configuradas.")
            
            print("[INFO] Analisando eventos contra regras...")
            alertas = aplicar_regras(eventos, regras)
            print(f"[OK] {len(alertas)} alertas gerados pelo Motor de Regras.")
            
            print("[INFO] Detectando anomalias complexas...")
            bf = detectar_brute_force(eventos)
            ps = detectar_port_scan(eventos)
            bl_ips, bl_cont = verificar_blacklist(eventos, BLACKLIST)
            resumo_anomalias = gerar_resumo_ameacas(bf, ps, bl_ips, bl_cont)
            print(f"[OK] {len(resumo_anomalias)} anomalias consolidadas pelo Detector.")
            
        elif opcao == 2:
            resumo_geral(eventos, alertas)
            
        elif opcao == 3:
            fonte = input("Fonte (auth/firewall/web) [Enter para todas]: ").strip() or None
            tipo = input("Tipo (FAIL/BLOCK/etc) [Enter para todos]: ").strip() or None
            filtrados = filtrar_eventos(eventos, fonte=fonte, tipo=tipo)
            print(f"\n[OK] Encontrados {len(filtrados)} eventos correspondentes.")
            for e in filtrados:
                print(e.get("linha_original"))
                
        elif opcao == 4:
            ip = input("Digite o IP para buscar: ").strip()
            buscar_ip(ip, eventos, alertas, cache_enriquecimento)
            
        elif opcao == 5:
            top_ips(eventos)
            
        elif opcao == 6:
            sev = input("Filtrar severidade (CRITICA/ALTA/MEDIA/BAIXA/INFO) [Enter para todas]: ").strip().upper()
            if sev:
                alts = [a for a in alertas if a.get("severidade") == sev]
            else:
                alts = alertas
            exibir_tabela(alts)
            
        elif opcao == 7:
            print("\n[INFO] Enriquecendo IPs suspeitos detectados (isso pode demorar alguns segundos)...")
            ips_suspeitos = {a.get("ip") for a in alertas if a.get("ip")}
            for ip in ips_suspeitos:
                consultar_ip(ip, cache_enriquecimento)
            print(f"[OK] {len(cache_enriquecimento)} IPs agora estão no cache de enriquecimento.")
            
        elif opcao == 8:
            if not eventos:
                print("\n[!] Nenhum log carregado para exportar. Use a opção 1 primeiro.")
            else:
                dados_completos = {
                    "total_eventos": len(eventos),
                    "total_alertas": len(alertas),
                    "alertas": alertas,
                    "anomalias": resumo_anomalias,
                    "enriquecimento": cache_enriquecimento
                }
                exportar_relatorio_json(dados_completos)
                
        elif opcao == 9:
            print("\n[INFO] Para testar o servidor de alertas em rede, abra um NOVO terminal e digite:")
            print("       python servidor_alertas.py")
            print("       Depois, abra OUTRO terminal e digite:")
            print("       python cliente_alertas.py\n")
            print("O menu principal continuará rodando isolado para não bloquear a interface.")
                
        elif opcao == 0:
            print("\nEncerrando SecuraPy. Até logo!")
            sys.exit(0)

if __name__ == "__main__":
    main()
