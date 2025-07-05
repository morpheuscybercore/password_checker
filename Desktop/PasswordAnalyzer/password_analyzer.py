import requests
import hashlib
import re

#Função para verificar a força da senha
def check_password_strength(password):
    # Criterios de força
    length = len(password) >= 8
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = bool(re.search(r'[!@#$%¨&*()<>?":{}|<>]', password))

    #Pontuação (simples)
    score = sum([length, has_upper, has_lower, has_digit, has_special])

    # Retorna o resultado
    if score == 5:
        return "Forte"
    elif score >= 3:
        return "Média"
    else:
        return "Fraca"


#Função para verificar se a senha foi vazada
def check_pwned(password):
    # Hash SHA-1 da senha (em maiúsculas)
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]

    # Consulta a API do HAve I Been Pwned
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    # Verifica se o sufixo do hash está na resposta
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return f"Senha Vazada {count} vezes!"
    return "Senha segura (não encontrada em vazamentos)."

def main():
    print("Analisador de Senhas")
    password = input("Digite uma senha para análise: ")

    print("\n Resultado")
    print(f"Força: {check_password_strength(password)}")
    print(f"Vazamentos: {check_pwned(password)}")

if __name__ == "__main__":
    main()
