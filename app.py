from flask import Flask, request, render_template, jsonify
from webauthn import (generate_registration_options, 
                      options_to_json, 
                      verify_registration_response, 
                      generate_authentication_options, 
                      verify_authentication_response)
from webauthn.helpers.structs import (AuthenticatorAttachment,
                                      AuthenticatorSelectionCriteria,
                                      ResidentKeyRequirement,
                                      UserVerificationRequirement)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

app = Flask(__name__, static_url_path='/static' , static_folder='static')

# Database fittizio per la memorizzazione delle credenziali registrate
registered_credentials = {}

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')    
        
        if username in registered_credentials:
            return jsonify({'error': 'Utente già registrato.'}), 500
        # Generare le opzioni di registrazione per il client. 
        # Authenticator_selection è un attributo opzionale
        # per definire meglio l'authenticator
        options = generate_registration_options(rp_id="localhost", 
                                                rp_name="example",
                                                user_name=username, 
                                                authenticator_selection=AuthenticatorSelectionCriteria(
                                                    resident_key=ResidentKeyRequirement.REQUIRED,
                                                    user_verification=UserVerificationRequirement.PREFERRED))
        # Convertire le opzioni in JSON in quanto ci sono oggetti bytes che non possono essere serializzati
        json_options = options_to_json(options)
        
        # Restituire le opzioni al client
        response = jsonify(json_options)
        return response

    except Exception as e:
        print('Errore durante la registrazione fase 1:', e)
        return jsonify({'error': 'Errore durante la registrazione.'}), 500

@app.route('/complete-registration', methods=['POST'])
def complete_registration():
    try:
        data = request.json
       
        # Verificare le credenziali ricevute dal client
        result = verify_registration_response(credential=data.get('credential'), 
                                              expected_origin="https://localhost:5000", 
                                              expected_rp_id="localhost",
                                              expected_challenge=base64url_to_bytes(data.get("challenge")))

        # Aggiungere le credenziali al database
        registered_credentials[bytes_to_base64url(result.credential_id)] = result
        return jsonify({'success': True}), 200

    except Exception as e:
        print('Errore durante la registrazione fase 2:', e)
        return jsonify({'error': 'Errore durante la registrazione.'}), 500

@app.route('/auth', methods=['POST'])
def authenticate():
    try:
        # Generare le opzioni di autenticazione per il client
        options = generate_authentication_options(rp_id='localhost',
                                                  user_verification=UserVerificationRequirement.PREFERRED)

        # Convertire le opzioni in JSON in quanto ci sono oggetti bytes che non possono essere serializzati
        json_options = options_to_json(options)

        # Restituire le opzioni al client
        response = jsonify(json_options)
        return response

    except Exception as e:
        print('Errore durante l\'autenticazione:', e)
        return jsonify({'error': 'Errore durante l\'autenticazione.'}), 500

@app.route('/verify', methods=['POST'])
def verify():
    try:
        data = request.json

        credential = data.get('credential')
        credential_id = credential.get("id")
        # Verificare le credenziali ricevute dal client
        result = verify_authentication_response(credential=credential,
                                                expected_origin="https://localhost:5000", 
                                                expected_rp_id="localhost",
                                                expected_challenge=base64url_to_bytes(data.get("challenge")),
                                                credential_current_sign_count=registered_credentials[credential_id].sign_count,
                                                credential_public_key=registered_credentials[credential_id].credential_public_key,
                                                require_user_verification=True)

        return jsonify({'success': True}), 200

    except Exception as e:
        print('Errore durante la verifica delle credenziali:', e)
        return jsonify({'error': 'Errore durante la verifica delle credenziali.'}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, ssl_context=('server.crt', 'server.key'))
