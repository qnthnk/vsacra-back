from flask import Blueprint, send_file, make_response, request, jsonify, render_template, current_app, Response # Blueprint para modularizar y relacionar con app
from flask_bcrypt import Bcrypt                                  # Bcrypt para encriptación
from flask_jwt_extended import JWTManager ,create_access_token, jwt_required,get_jwt, get_jwt_identity   # Jwt para tokens
from models import User, Administrator, Contact, Complaint
from database import db                                          # importa la db desde database.py
from datetime import timedelta, datetime                         # importa tiempo especifico para rendimiento de token válido
from utils.clasifica_utils import  get_evaluations_of_all
from logging_config import logger
import os                                                        # Para datos .env
from dotenv import load_dotenv                                   # Para datos .env
load_dotenv()
import pandas as pd
from io import BytesIO
import openai
import random
from itsdangerous import URLSafeTimedSerializer
import requests
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import logging
from twilio.rest import Client
import os

# este pedazo es el pedo de sms por twilio
twilio_bp = Blueprint('twilio_bp', __name__)

account_sid = 'TU_ACCOUNT_SID'
auth_token = 'TU_AUTH_TOKEN'
twilio_number = 'whatsapp:+14155238886'  # Este es el número de WhatsApp de Twilio
sms_number = '+19478004275'       # Ej. +1234567890

client = Client(account_sid, auth_token)
# hasta aqui llega el pedazo de sms por twilio


api_bp = Blueprint('api_bp', __name__)
bcrypt = Bcrypt()
jwt = JWTManager()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


client = openai.OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY"),
    organization=os.environ.get("ORGANIZATION_ID")
)

CONVERTER_API_KEY = '43af89a58a6d8fd938bdd176d46766df'  
BASE_URL = os.environ.get("BASE_URL")
WEATHERAPI_KEY= os.environ.get("WEATHERAPI_KEY")
ADMIN_REQUIRED_EMAIL = 'admin@viasacra.com'  
GOOGLE_MAPS_API= os.environ.get("GOOGLE_MAPS_API")
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
s = URLSafeTimedSerializer(os.environ.get('SECRET_KEY'))

delete_tokens = set()

# ruta de twilio para WA de Ruben

@api_bp.route('/send-alert', methods=['POST'])
def send_alert():
    from twilio.rest import Client

    try:
        data = request.get_json()
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        user_id = data.get('user_id')

        if not all([latitude, longitude, user_id]):
            return jsonify({"error": "Faltan datos"}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404

        contacts = Contact.query.filter_by(user_id=user.id).all()
        if not contacts:
            return jsonify({"error": "No hay contactos de emergencia"}), 404

        # Configura tus credenciales de Twilio
        account_sid = os.environ.get("TWILIO_SID")
        auth_token = os.environ.get("TWILIO_AUTH_TOKEN")
        client = Client(account_sid, auth_token)

        # sms_number = os.environ.get("TWILIO_SMS_NUMBER")
        whatsapp_number = os.environ.get("TWILIO_WA_NUMBER")

        message_text = (
            f"🚨 ALERTA DE EMERGENCIA 🚨\n"
            f"{user.first_name} {user.first_last_name} ha enviado una alerta.\n"
            f"📍 Ubicación: https://www.google.com/maps?q={latitude},{longitude}\n"
            f"💉 Alergias: {user.allergy or 'No registradas'}\n"
            f"🩸 Tipo de sangre: {user.blood_type or 'No especificado'}"
        )

        enviados = 0
        for contact in contacts:
            # client.messages.create(body=message_text, from_=sms_number, to=contact.phone_number)
            client.messages.create(body=message_text, from_=whatsapp_number, to={contact.phone_number})
            enviados += 1

        return jsonify({"message": "Alerta enviada", "contacts_notified": enviados}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# aqui termina la ruta de twilio para WA de Ruben

@api_bp.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

@api_bp.route('/', methods=['GET'])
def handle_base():

    response_body = {
        "message": "El sever funciona ok!"
    }

    return jsonify(response_body), 200

@api_bp.route('/signup', methods=['POST'])
def sign_up():
    data = request.json
    
    # 1. Validación de reCAPTCHA
    recaptcha_token = data.get('recaptcha_token')
    if not recaptcha_token:
        return jsonify({"message": "Verificación reCAPTCHA requerida"}), 400
    
    # Verificar el token con Google
    verify_url = "https://www.google.com/recaptcha/api/siteverify"
    payload = {
        'secret': os.environ.get('RECAPTCHA_SECRET_KEY'),
        'response': recaptcha_token
    }
    response = requests.post(verify_url, data=payload)
    result = response.json()
    
    if not result.get('success'):
        return jsonify({
            "message": "Verificación reCAPTCHA fallida",
            "error_code": "invalid_recaptcha"
        }), 400
    
    # 2. Procesar datos del formulario
    first_name = data.get('first_name')
    first_last_name = data.get('first_last_name')
    second_last_name = data.get('second_last_name')
    curp = data.get('curp')
    gender = data.get('gender')
    birthdate = data.get('birthdate')
    blood_type = data.get('blood_type')
    allergy = data.get('allergy')
    disease = data.get('disease')
    email = data.get('email')
    password = data.get('password')
    phone_number = data.get('phone_number')
    facebook = data.get('facebook')
    instagram = data.get('instagram')
    x = data.get('x')
    state = data.get('state')
    colonia_mex = data.get('colonia_mex')
    street = data.get('street')
    seccion = data.get('seccion')
    house_number = data.get('house_number')
    zip_code = data.get('zip_code')
    distrito_federal = data.get('distrito_federal')
    distrito_local = data.get('distrito_local')
    nombre_municipio = data.get('nombre_municipio')
    tipo_seccion = data.get('tipo_seccion')
    latitude = data.get('latitude')
    longitude = data.get('longitude')

    # 3. Verificar si el usuario ya existe
    user_exists = User.query.filter_by(email=email).first() 
    if user_exists:
        return jsonify({"message": "Email ya registrado. Intenta con uno nuevo."}), 400
    
    # 4. Crear nuevo usuario
    password_hash = bcrypt.generate_password_hash(password)

    new_user = User(
        first_name=first_name,
        first_last_name=first_last_name,
        second_last_name=second_last_name,
        curp=curp,
        gender=gender,
        birthdate=birthdate,
        email=email,
        password=password_hash,
        phone_number=phone_number,
        facebook=facebook,
        instagram=instagram,
        x=x,
        blood_type=blood_type,
        allergy=allergy,
        disease=disease,
        state=state,
        colonia_mex=colonia_mex,
        house_number=house_number,
        street=street,
        zip_code=zip_code,
        seccion=seccion,
        distrito_federal=distrito_federal,
        distrito_local=distrito_local,
        nombre_municipio=nombre_municipio,
        tipo_seccion=tipo_seccion,
        longitude=longitude,
        latitude=latitude
    )  

    try:
        db.session.add(new_user)  
        db.session.commit()

        return jsonify({
            "user": new_user.serialize(),
            "message": "Te has registrado! Redirigiéndote al inicio de sesión" 
        }), 200
    except Exception as error:
        db.session.rollback()
        logger.error(f"Error en registro: {str(error)}")
        return jsonify({"message": "Ha ocurrido un error en el servidor"}), 500
    

@api_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    
    user_exists = User.query.filter_by(email=email).first()
    if user_exists:
        valid_password = bcrypt.check_password_hash(user_exists.password, password)
        if valid_password:
            access_token = create_access_token(identity={'email': email, 'role': 'user'})
            return jsonify({"token": access_token, "role": "user", "id":user_exists.id}), 200
        else:
            return jsonify({"message": "Contraseña inválida."}), 401

    # Verificar si es un Admin
    admin_exists = Administrator.query.filter_by(email=email).first()
    if admin_exists:
        if email != ADMIN_REQUIRED_EMAIL:
            return jsonify({"message": "Acceso denegado. Correo de admin no autorizado."}), 403

        valid_password = admin_exists.password
        if valid_password:
            access_token = create_access_token(identity={'email': email, 'role': 'admin'})
            return jsonify({"token": access_token, "role": "admin", "id":admin_exists.id}), 200
        else:
            return jsonify({"message": "Contraseña inválida."}), 401

    return jsonify({"message": "Usuario inválido."}), 404
    

@api_bp.route('/nearby_places', methods=['POST'])
def get_nearby_places():
    try:
        data = request.json
        place_type = data.get('includedTypes', [])[0]
        lat = data.get('locationRestriction', {}).get('circle', {}).get('center', {}).get('latitude')
        lng = data.get('locationRestriction', {}).get('circle', {}).get('center', {}).get('longitude')
        
        if not place_type or not lat or not lng:
            return jsonify({"error": "Faltan parámetros"}), 400

        url = f"https://places.googleapis.com/v1/places:searchNearby"
        
        headers = {
            'Content-Type': 'application/json',
            'X-Goog-Api-Key': GOOGLE_MAPS_API,
            'X-Goog-FieldMask': 'places.displayName,places.formattedAddress',
        }
        
        payload = {
            "includedTypes": [place_type],
            "locationRestriction": {
                "circle": {
                    "center": {
                        "latitude": lat,
                        "longitude": lng,
                    },
                    "radius": 5000,
                }
            },
            "maxResultCount": 10,
        }

        response = requests.post(url, json=payload, headers=headers)
        data = response.json()

        if "places" in data:
            return jsonify({"places": data["places"]})
        else:
            return jsonify({"error": "No se encontraron lugares", "data": data}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@api_bp.route('/chatbot', methods=['POST'])
def chatbot():
    data = request.json
    message = data.get("message")
    api_key=os.environ.get("OPENAI_API_KEY"),
    organization=os.environ.get("ORGANIZATION_ID")
    print(api_key, organization)
    if not message:
        return jsonify({"error": "Falta el mensaje"}), 400

    try:
        # Enviar pregunta a OpenAI
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Eres un chatbot útil que responde preguntas de manera clara."},
                {"role": "user", "content": message}
            ]
        )

        response = completion.choices[0].message.content
        return jsonify({"response": response}), 200

    except Exception as e:
        return jsonify({"error": f"Error en el chatbot: {str(e)}"}), 500

@api_bp.route('/exchange', methods=['GET'])
def converter():
    from_currency = request.args.get('from')  
    to_currency = request.args.get('to')      
    amount = float(request.args.get('amount', 1.0))  

    if not from_currency or not to_currency:
        return jsonify({'error': 'Debes proporcionar las monedas de origen (from) y destino (to)'}), 400

    try:
        response = requests.get(BASE_URL)
        data = response.json()

        if not data.get('success', False):
            return jsonify({'error': 'No se pudo obtener las tasas de cambio'}), 500

        rates = data.get('rates', {})
        if from_currency not in rates or to_currency not in rates:
            return jsonify({'error': 'Una o ambas monedas no son válidas'}), 400

        from_rate = rates[from_currency]
        to_rate = rates[to_currency]
        converted_amount = (amount / from_rate) * to_rate

        return jsonify({
            'from': from_currency,
            'to': to_currency,
            'amount': amount,
            'converted_amount': round(converted_amount, 2)
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/currency', methods=['GET'])
def currency():
    try:
        response = requests.get(BASE_URL)
        data = response.json()

        if not data.get('success', False):
            return jsonify({'error': 'No se pudo obtener las tasas de cambio'}), 500

        return jsonify({
            'monedas_soportadas': list(data.get('rates', {}).keys())
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@api_bp.route('/weather', methods=['GET'])
def obtener_clima():
    try:
        lat = request.args.get('lat')
        lon = request.args.get('lon')

        if not lat or not lon:
            return jsonify({'error': 'Debes proporcionar latitud (lat) y longitud (lon).'}), 400

        url = f'http://api.weatherapi.com/v1/current.json?key={WEATHERAPI_KEY}&q={lat},{lon}'
        response = requests.get(url)

        if response.status_code != 200:
            return jsonify({'error': 'No se pudo obtener el clima.'}), 500

        data = response.json()
        return jsonify({
            'ciudad': data['location']['name'],
            'pais': data['location']['country'],
            'region': data['location']['region'],
            'temperatura': data['current']['temp_c'],
            'humedad': data['current']['humidity'],
            'clima': data['current']['condition']['text'],
            'icono': data['current']['condition']['icon'],
            'viento': data['current']['wind_kph']
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/addcontact', methods=['POST', 'GET', 'PUT', 'DELETE'])
# @jwt_required()
def add_contact():
    data = request.get_json()

    if not data or not all(key in data for key in ['full_name', 'email', 'phone_number', 'role', 'user_id']):
        return jsonify({"error": "Missing data"}), 400

    new_contact = Contact(
        full_name=data['full_name'],
        email=data['email'],
        phone_number=data['phone_number'],
        role=data['role'],
        user_id=data['user_id']
    )

    db.session.add(new_contact)
    db.session.commit()

    return jsonify(new_contact.serialize()), 201

@api_bp.route('/complaint', methods=['POST', 'GET', 'PUT', 'DELETE'])
# @jwt_required()
def complaint():
    data = request.get_json()

    if not data or not all(key in data for key in ['cause', 'url_image_complaint', 'complaint_comment', 'status','latitude','longitude','user_id']):
        return jsonify({"error": "Missing data"}), 400

    new_complaint = Complaint(
        cause=data['cause'],
        url_image_complaint=data['url_image_complaint'],
        complaint_comment=data['complaint_comment'],
        status=data['status'],
        latitude=data.get('latitude'),
        longitude=data.get('longitude'),
        user_id=data['user_id']
    )

    db.session.add(new_complaint)
    db.session.commit()

    return jsonify(new_complaint.serialize()), 201


@api_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    delete_tokens.add(jti)
    return jsonify({"msg": "You have been logged-out"}), 200

@api_bp.route('/editcontact/<int:id>', methods=['PUT'])
def edit_contact(id):
    data = request.get_json()

    if not data:
        return jsonify({"error": "Missing data"}), 400

    contact = Contact.query.get(id)
    if not contact:
        return jsonify({"error": "Contact not found"}), 404

    contact.full_name = data.get('full_name', contact.full_name)
    contact.email = data.get('email', contact.email)
    contact.phone_number = data.get('phone_number', contact.phone_number)
    contact.role = data.get('role', contact.role)

    db.session.commit()

    return jsonify(contact.serialize()), 200

@api_bp.route('/editcomplaint/<int:id>', methods=['PUT'])
def edit_complaint(id):
    data = request.get_json()

    if not data:
        return jsonify({"error": "Missing data"}), 400

    complaint = Complaint.query.get(id)
    if not complaint:
        return jsonify({"error": "Complaint not found"}), 404

    complaint.cause = data.get('cause', complaint.cause)
    complaint.url_image_complaint = data.get('url_image_complaint', complaint.url_image_complaint)
    complaint.complaint_comment = data.get('complaint_comment', complaint.complaint_comment)
    complaint.status = data.get('status', complaint.status)
    complaint.latitude = data.get('latitude',complaint.latitude)
    complaint.longitude = data.get('longitude',complaint.longitude)

    db.session.commit()

    return jsonify(complaint.serialize()), 200

@api_bp.route('/deletecontact/<int:id>', methods=['DELETE'])
def delete_contact(id):
    contact = Contact.query.get(id)
    if not contact:
        return jsonify({"error": "Contact not found"}), 404

    db.session.delete(contact)
    db.session.commit()

    return jsonify({"message": "Contact deleted successfully"}), 200

@api_bp.route('/viewcontacts', methods=['GET'])
def view_contacts():
    user_id = request.args.get('user_id')  
    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    contacts = Contact.query.filter_by(user_id=user_id).all()
    return jsonify([contact.serialize() for contact in contacts]), 200

@api_bp.route('/viewcomplaints', methods=['GET'])
def view_complaints():
    user_id = request.args.get('user_id')  
    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    complaints = Complaint.query.filter_by(user_id=user_id).all()
    return jsonify([complaint.serialize() for complaint in complaints]), 200



@api_bp.route('/emergency-alert', methods=['POST', 'OPTIONS'])
#@jwt_required(optional=True)  # Para permitir OPTIONS sin autenticación
def send_emergency_alert():
    if request.method == 'OPTIONS':
        # Respuesta para preflight
        response = jsonify({"status": "preflight"})
        response.headers.add("Access-Control-Allow-Origin", "https://www.escudogarcia.live")
        response.headers.add("Access-Control-Allow-Headers", "Authorization, Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "POST")
        return response, 200

    # El resto de tu lógica POST normal...
    try:
        current_user = get_jwt_identity()
        user = User.query.filter_by(email=current_user['email']).first()  # Corregido para usar el email del JWT
        
        if not user:
            logger.error(f"Usuario no encontrado: {current_user}")
            return jsonify({"error": "Usuario no autorizado"}), 401

        data = request.get_json()
        if not data:
            logger.error("Solicitud sin datos JSON")
            return jsonify({"error": "Datos JSON requeridos"}), 400

        latitude = data.get('latitude', user.latitude)
        longitude = data.get('longitude', user.longitude)
        
        if not all([latitude, longitude]):
            logger.error("Faltan coordenadas de ubicación")
            return jsonify({"error": "Ubicación requerida"}), 400

        contacts = Contact.query.filter_by(user_id=user.id).all()
        if not contacts:
            logger.error(f"Usuario {user.id} no tiene contactos registrados")
            return jsonify({"error": "No hay contactos de emergencia registrados"}), 404

        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        from_email = os.environ.get('FROM_EMAIL')
        successful_emails = 0

        for contact in contacts:
            try:
                html_content = f"""
                <html>
                <body>
                <h2>🚨 Alerta de Emergencia 🚨</h2>
                <p>El usuario <strong>{user.first_name} {user.first_last_name}</strong> ha enviado una alerta.</p>
                <p><strong>Ubicación:</strong> {latitude}, {longitude}</p>
                <p>¡Por favor, verifica su situación lo antes posible!</p>
                </body>
                </html>
                </html>
                """

                message = Mail(
                    from_email=from_email,
                    to_emails=contact.email,
                    subject=f"🚨 ALERTA DE EMERGENCIA - {user.first_name} {user.first_last_name}",
                    html_content=html_content
                )

                response = sg.send(message)
                if response.status_code == 202:
                    successful_emails += 1
                    logger.info(f"Correo enviado a {contact.email}")
                else:
                    logger.error(f"Error al enviar a {contact.email}: {response.body}")

            except Exception as e:
                logger.error(f"Error con contacto {contact.email}: {str(e)}")
                continue

        response = jsonify({
            "status": "success",
            "message": "Alertas enviadas",
            "contacts_notified": successful_emails,
            "total_contacts": len(contacts)
        })
        response.headers.add("Access-Control-Allow-Origin", "https://www.escudogarcia.live")
        return response, 200

    except Exception as e:
        logger.error(f"Error en emergencia: {str(e)}", exc_info=True)
        response = jsonify({
            "status": "error",
            "message": "Error al procesar emergencia",
            "error": str(e)
        })
        response.headers.add("Access-Control-Allow-Origin", "https://www.escudogarcia.live")
        return response, 500
        
@api_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email es requerido"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404

    reset_code = str(random.randint(1000, 9999))

    user.reset_code = reset_code
    db.session.commit()

    message = Mail(
        from_email='demos@quanthink.com.mx',  
        to_emails=email,
        subject='Código de restablecimiento de contraseña',
        html_content=f'<p>Tu código de restablecimiento de contraseña es: <strong>{reset_code}</strong></p>'
    )

    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sg.send(message)
        return jsonify({"message": "Código de restablecimiento enviado"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@api_bp.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    reset_code = data.get('reset_code')
    new_password = data.get('new_password')

    if not email or not reset_code or not new_password:
        return jsonify({"error": "Todos los campos son requeridos"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404

    if user.reset_code != reset_code:
        return jsonify({"error": "Código de restablecimiento inválido"}), 400

    user.password = bcrypt.generate_password_hash(new_password)
    user.reset_code = None  
    db.session.commit()

    return jsonify({"message": "Contraseña restablecida exitosamente"}), 200 

@api_bp.route('/users', methods=['GET'])
@jwt_required()
def get_all_users():
    try:
        current_user = get_jwt_identity()
        if current_user['role'] != 'admin':
            return jsonify({"error": "Acceso no autorizado"}), 403
        
        # Obtener todos los usuarios
        users = User.query.all()
        
        # Serializar los datos de los usuarios
        users_data = [user.serialize() for user in users]
        
        return jsonify(users_data), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/get_map_url', methods=['POST'])
# @jwt_required()
def get_map_url():
    try:
        logger.info("entro en la ruta get_map_url")
        # Obtener los datos enviados desde el frontend
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({"error": "URL no proporcionada"}), 400

        # Realizar la solicitud a la URL inicial
        response = requests.get(url)
        
        if response.status_code != 200:
            return jsonify({"error": f"Error al consultar la URL: {response.status_code}"}), response.status_code

        # Parsear la respuesta JSON
        json_data = response.json()

        if not json_data or not json_data[0].get('path') or not json_data[0].get('archivo'):
            return jsonify({"error": "Respuesta JSON no válida o incompleta"}), 400

        # Construir la URL final
        base_url = "https://storage.googleapis.com/mapoteca/"
        path = json_data[0]['path'].replace(" ", "%20")  # Codificar espacios
        archivo = json_data[0]['archivo']
        final_url = f"{base_url}{path}{archivo}"
        print("ESTA ES LA URL FINAL: ",final_url)
        # Devolver la URL final
        return jsonify({"url": final_url}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@api_bp.route('/users_free', methods=['GET'])
def get_all_users_free():
    """
    Devuelve un JSON con un array de todos los usuarios serializados.
    """
    users = User.query.all()
    # serialize() ya devuelve dict, así que armamos la lista
    serialized = [u.serialize() for u in users]
    return jsonify(serialized), 200