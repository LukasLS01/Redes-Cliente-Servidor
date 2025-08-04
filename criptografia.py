# A biblioteca pycryptodome é comumente importada como 'Crypto'
# mas também pode ser importada como 'Cryptodome' para evitar conflitos.
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
# 'from Cryptodome import Random' foi removido por não ser utilizado.

class FerramentasCrypto:
    def encrypt(self, plain_text, key):
        """
        Criptografa o texto usando AES no modo CBC.
        Gera um IV aleatório para cada criptografia.
        """
        # Cria um novo objeto de cifra AES. Um IV aleatório e seguro é gerado automaticamente.
        cipher = AES.new(key, AES.MODE_CBC)
        
        # Codifica o texto para bytes e aplica o padding para ter um tamanho de bloco válido.
        padded_data = pad(plain_text.encode("utf-8"), AES.block_size)
        
        # Criptografa os dados e retorna o IV e o texto cifrado.
        return cipher.iv, cipher.encrypt(padded_data)

    def decrypt(self, iv, enc_text, key):
        """
        Descriptografa o texto usando o IV e a chave fornecidos.
        """
        # Cria a cifra para descriptografia, usando a chave e o IV originais.
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        
        # Descriptografa os dados.
        decrypted_padded_data = cipher.decrypt(enc_text)
        
        # Remove o padding e decodifica de bytes para string.
        return unpad(decrypted_padded_data, AES.block_size).decode("utf-8")