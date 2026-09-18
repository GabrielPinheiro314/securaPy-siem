import socket
import threading

clientes = {}
lock = threading.Lock()

def iniciar_servidor(host="0.0.0.0", porta=9999):
    """Inicia o servidor TCP e fica aguardando conexões."""
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        servidor.bind((host, porta))
        servidor.listen()
        print(f"=== Servidor de Alertas SecuraPy ===")
        print(f"Rodando em {host}:{porta}")
        print("Aguardando conexões...\n")
        
        while True:
            conexao, endereco = servidor.accept()
            with lock:
                clientes[conexao] = endereco
            print(f"[{formatar_hora()}] Cliente conectado: {endereco[0]}:{endereco[1]}")
            
            thread = threading.Thread(target=tratar_cliente, args=(conexao, endereco))
            thread.daemon = True
            thread.start()
    except Exception as e:
        print(f"Erro no servidor: {e}")
    finally:
        servidor.close()

def tratar_cliente(conexao, endereco):
    """Gerencia comunicação com um cliente individual (roda em thread)."""
    try:
        conexao.send("Conectado ao SecuraPy SIEM.\nComandos: /status, /historico, /sair\n".encode('utf-8'))
        while True:
            mensagem = conexao.recv(1024).decode('utf-8').strip()
            if not mensagem:
                break
                
            if mensagem == "/sair":
                break
            elif mensagem == "/status":
                with lock:
                    num_clientes = len(clientes)
                conexao.send(f"Clientes conectados: {num_clientes}\n".encode('utf-8'))
            elif mensagem == "/historico":
                conexao.send("Histórico ainda não implementado (requer integração com main).\n".encode('utf-8'))
            else:
                conexao.send("Comando não reconhecido.\n".encode('utf-8'))
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        with lock:
            if conexao in clientes:
                del clientes[conexao]
        print(f"[{formatar_hora()}] Cliente desconectado: {endereco[0]}:{endereco[1]}")
        conexao.close()

def broadcast_alerta(alerta_formatado):
    """Envia um alerta formatado para todos os clientes conectados."""
    with lock:
        conexoes_mortas = []
        for conexao in clientes:
            try:
                conexao.send((alerta_formatado + "\n").encode('utf-8'))
            except:
                conexoes_mortas.append(conexao)
                
        for conexao in conexoes_mortas:
            del clientes[conexao]

def formatar_alerta(alerta_dict):
    """
    Converte dict de alerta em string formatada para exibição.
    """
    ts = alerta_dict.get("timestamp", "").split()[-1] if alerta_dict.get("timestamp") else "00:00:00"
    sev = alerta_dict.get("severidade", "INFO")
    regra = alerta_dict.get("regra", "Desconhecida")
    ip = alerta_dict.get("ip", "0.0.0.0")
    desc = alerta_dict.get("descricao", "")
    
    return f"[{ts}] [{sev}] {regra} — {ip} — {desc}"

def formatar_hora():
    from datetime import datetime
    return datetime.now().strftime("%H:%M:%S")

if __name__ == "__main__":
    iniciar_servidor()
