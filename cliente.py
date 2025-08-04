import socket
from criptografia import FerramentasCrypto

class ClienteTCP:
    def __init__(self, host, porta):
        self.host = host
        self.porta = porta
        self.key = b"0361231230000000" # Mesma chave do servidor
        self.tool = FerramentasCrypto()

    def conectar(self):
        # O 'with' garante que o socket será fechado ao final
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((self.host, self.porta))
                print(f"Conectado ao servidor em {self.host}:{self.porta}")
                print("Digite 'help' para ajuda ou 'sair' para sair.")
                
                while True:
                    comando = input("Comando> ").strip()
                    if not comando:
                        continue
                    
                    # Envia o comando criptografado
                    iv, dados_cript = self.tool.encrypt(comando, self.key)
                    s.sendall(iv)
                    s.sendall(dados_cript)

                    if comando.lower() == "sair":
                        print("Desconectando do servidor...")
                        break
                    
                    # Recebe a resposta
                    resposta_iv = s.recv(16)
                    if not resposta_iv: # Servidor desconectou
                        print("O servidor encerrou a conexão.")
                        break

                    resposta_cript = s.recv(4096) # Aumentado para respostas maiores
                    
                    # CORREÇÃO: A chave (self.key) estava faltando na chamada de decrypt
                    resposta = self.tool.decrypt(resposta_iv, resposta_cript, self.key)
                    print("="*20 + "\nResposta do servidor:\n" + "="*20 + f"\n{resposta}\n")

            except ConnectionRefusedError:
                print(f"Erro: Não foi possível conectar ao servidor. Verifique se o servidor está rodando em {self.host}:{self.porta}")
            except ConnectionResetError:
                print("Erro: A conexão foi perdida com o servidor.")
            except Exception as e:
                print(f"Ocorreu um erro inesperado: {e}")

if __name__ == "__main__":
    cliente = ClienteTCP('127.0.0.1', 1515)
    cliente.conectar()