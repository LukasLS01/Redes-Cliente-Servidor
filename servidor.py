import socket
from criptografia import FerramentasCrypto
import threading
import psutil

class ServidorTCP:
    def __init__(self, host, porta):
        self.key = b"0361231230000000"  # Chave de 16 bytes para AES-128
        self.host = host
        self.porta = porta
        self.servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # CORREÇÃO 1: self.clientes agora é um dicionário {} para armazenar clientes.
        self.clientes = {}

    def iniciar_servidor(self):
        self.servidor.bind((self.host, self.porta))
        self.servidor.listen()
        print(f"Servidor escutando em {self.host}:{self.porta}")

        while True:
            cliente_socket, endereco = self.servidor.accept()
            print(f"Cliente conectado: {endereco}")
            self.clientes[endereco] = cliente_socket
            threading.Thread(target=self.atender_cliente, args=(cliente_socket, endereco), daemon=True).start()

    def atender_cliente(self, cliente_socket, endereco):
        tool = FerramentasCrypto()
        try:
            while True:
                iv = cliente_socket.recv(16)
                dados_criptografados = cliente_socket.recv(1024)
                
                # Se recv retornar vazio, o cliente desconectou
                if not iv or not dados_criptografados:
                    break
                
                comando = tool.decrypt(iv, dados_criptografados, self.key)
                print(f"Comando recebido de {endereco}: {comando}")

                if comando == "/off":
                    break
                
                resposta = self.executar_comando(comando, endereco)
                
                resposta_iv, resposta_msg = tool.encrypt(resposta, self.key)
                
                cliente_socket.send(resposta_iv)
                cliente_socket.send(resposta_msg)

        except Exception as e:
            print(f"Erro com cliente {endereco}: {e}")
        finally:
            # CORREÇÃO 2: Bloco de limpeza para remover o cliente e fechar o socket.
            print(f"Cliente {endereco} desconectado.")
            if endereco in self.clientes:
                del self.clientes[endereco]
            cliente_socket.close()
    
    def executar_comando(self, comando, endereco):
        try:
            match comando.lower().strip():
                case "cpu":
                    qtdCPU = psutil.cpu_count(logical=False)
                    return f"Quantidade de núcleos físicos da CPU: {qtdCPU}"
                case "ram":
                    memoriaLivre = psutil.virtual_memory().available / (1024 ** 3)
                    return f"Quantidade de RAM livre: {memoriaLivre:.2f} GB"
                case "disco":
                    # Funciona para Windows, Linux e macOS
                    discoLivre = psutil.disk_usage('/').free / (1024 ** 3)
                    return f"Espaço em disco livre (partição principal): {discoLivre:.2f} GB"
                case "ip":
                    ips = "Lista dos IPs de cada Interface:\n"
                    for nic, addrs in psutil.net_if_addrs().items():
                        # Pega o primeiro endereço IPv4, se existir
                        for addr in addrs:
                            if addr.family == socket.AF_INET:
                                ips += f"{nic}: {addr.address}\n"
                                break
                    return ips
                case "interfaces_desativadas":
                    interfaces = ""
                    for nome, stats in psutil.net_if_stats().items():
                         if not stats.isup:
                              interfaces += f"{nome}\n"
                    return f"Lista de interfaces desativadas:\n{interfaces if interfaces else 'Nenhuma'}"
                case "portas":
                    conexoes = psutil.net_connections()
                    portas_tcp = sorted({c.laddr.port for c in conexoes if c.status == 'LISTEN' and c.type == socket.SOCK_STREAM})
                    return f"Portas TCP em escuta (LISTEN): {portas_tcp}"
                case "clientes":
                    if not self.clientes:
                        return "Nenhum cliente conectado."
                    return "Clientes conectados:\n" + "\n".join([f"{i+1}. {ip[0]}:{ip[1]}" for i, ip in enumerate(self.clientes.keys())])
                case "help":
                    return ("Comandos disponíveis:\n"
                            "  cpu      -> Mostra a quantidade de núcleos físicos da CPU.\n"
                            "  ram      -> Mostra a quantidade de RAM livre.\n"
                            "  disco    -> Mostra o espaço em disco livre.\n"
                            "  ip       -> Lista os endereços IP de cada interface.\n"
                            "  portas   -> Lista as portas TCP abertas em modo de escuta.\n"
                            "  clientes -> Lista os clientes conectados ao servidor.\n"
                            "  sair     -> Desconecta do servidor.")
                case _:
                    return "Comando não reconhecido. Digite 'help' para ver a lista de comandos."
        except Exception as e:
            return f"Erro ao executar comando: {e}"

if __name__ == "__main__":
    servidor = ServidorTCP('0.0.0.0', 1515)
    servidor.iniciar_servidor()