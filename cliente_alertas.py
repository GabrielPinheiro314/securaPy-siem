import socket
import threading
import sys

def receber_alertas(cliente):
    """Thread que recebe e exibe alertas do servidor."""
    try:
        while True:
            mensagem = cliente.recv(4096).decode('utf-8')
            if not mensagem:
                print("\nConexão encerrada pelo servidor.")
                break
            print(mensagem, end="")
    except (ConnectionResetError, ConnectionAbortedError):
        print("\nConexão perdida com o servidor.")
    except Exception as e:
        print(f"\nErro: {e}")
    finally:
        sys.exit(0)

def conectar_servidor(host="127.0.0.1", porta=9999):
    """Conecta ao servidor e fica recebendo alertas."""
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente.connect((host, porta))
        
        thread = threading.Thread(target=receber_alertas, args=(cliente,))
        thread.daemon = True
        thread.start()
        
        while True:
            comando = input()
            if comando.strip() == "/sair":
                cliente.send(comando.encode('utf-8'))
                break
            elif comando.strip():
                cliente.send(comando.encode('utf-8'))
                
    except ConnectionRefusedError:
        print(f"Não foi possível conectar ao servidor em {host}:{porta}. Ele está rodando?")
    finally:
        cliente.close()

if __name__ == "__main__":
    conectar_servidor()
