import re
import hashlib
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

def check_password_strength(password):
    score = 0
    criteria = [
        (len(password) >= 8, "A senha deve ter pelo menos 8 caracteres."),
        (re.search(r'[A-Z]', password), "A senha deve conter pelo menos uma letra maiúscula."),
        (re.search(r'[a-z]', password), "A senha deve conter pelo menos uma letra minúscula."),
        (re.search(r'\d', password), "A senha deve conter pelo menos um número."),
        (re.search(r'[!@#$%^&*(),.?":{}|<>]', password), "A senha deve conter pelo menos um caractere especial."),
    ]
    
    weaknesses = []
    for condition, message in criteria:
        if condition:
            score += 1
        else:
            weaknesses.append(message)
    
    strength_message = "Boa senha!" if score >= 4 else "Senha fraca, considere melhorá-la."
    return score, weaknesses, strength_message

def check_pwned_password(password):
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    first5, rest = sha1_password[:5], sha1_password[5:]
    
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{first5}")
        response.raise_for_status()  
    
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == rest:
                return f"Esta senha apareceu em vazamentos {count} vezes. Considere trocá-la."
        
        return "Esta senha não foi encontrada em vazamentos conhecidos."
    
    except requests.exceptions.RequestException as e:
        return f"Erro ao verificar a segurança da senha: {e}"

@app.route("/analyze_password", methods=["POST"])
def analyze_password():
    data = request.json
    password = data.get("password", "")
    
    score, weaknesses, strength_message = check_password_strength(password)
    pwned_message = check_pwned_password(password)
    
    return jsonify({
        "score": score,
        "strength_message": strength_message,
        "weaknesses": weaknesses,
        "pwned_message": pwned_message
    })

if __name__ == "__main__":
    app.run(debug=True)

