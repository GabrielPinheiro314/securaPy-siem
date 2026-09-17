import os
import sys
import coletor
import regras

def imprimir_cabecalho():
    print("="*60)
    print(" " * 15 + "SecuraPy - SIEM Simplificado")
    print("="*60)

def main():
    imprimir_cabecalho()
    
    pasta_logs = "logs"
    arquivo_regras = os.path.join("config", "regras.json")
    
    print("[*] Carregando regras de segurança...")
    lista_regras = regras.carregar_regras(arquivo_regras)
    if not lista_regras:
        print("[!] Nenhuma regra carregada. Encerrando.")
        sys.exit(1)
    print(f"[+] {len(lista_regras)} regras carregadas com sucesso.\n")
    
    print("[*] Iniciando coleta de logs...")
    eventos = coletor.carregar_todos_os_logs(pasta_logs)
    print(f"[+] {len(eventos)} eventos normalizados.\n")
    
    if not eventos:
        print("[!] Nenhum evento para processar.")
        sys.exit(0)
        
    print("[*] Analisando eventos...")
    alertas = regras.aplicar_regras(eventos, lista_regras)
    
    print(f"\n[+] Análise concluída. {len(alertas)} alertas gerados.\n")
    
    print("="*60)
    print(" " * 20 + "ALERTAS DETECTADOS")
    print("="*60)
    
    if not alertas:
        print("Nenhuma ameaça detectada.")
    else:
        for i, alerta in enumerate(alertas, 1):
            sev = alerta['severidade']
            cor = ""
            reset = "\033[0m"
            if sev == "CRITICA": cor = "\033[91m" 
            elif sev == "ALTA": cor = "\033[93m" 
            elif sev == "MEDIA": cor = "\033[94m" 
            
            print(f"{cor}[{sev}]{reset} {alerta['timestamp']} - {alerta['regra_nome']}")
            print(f"    IP Origem: {alerta['ip']}")
            print(f"    Detalhe: {alerta['descricao']}")
            print(f"    Log: {alerta['linha_original']}\n")

if __name__ == "__main__":
    main()
