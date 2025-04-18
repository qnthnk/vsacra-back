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

api_bp = Blueprint('api_bp', __name__)
bcrypt = Bcrypt()
jwt = JWTManager()



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

@api_bp.route('/signup', methods = ['POST'])
def sign_up():
    data = request.json
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
    city = data.get('city')
    state = data.get('state')
    address = data.get('address')
    zip_code = data.get('zip_code')
    latitude = data.get('latitude')
    longitude = data.get('longitude')

    user_exists = User.query.filter_by(email=email).first() 
    if user_exists is None:
        print(user_exists, "creando nuevo usuario")
        password_hash = bcrypt.generate_password_hash(password)
        print(password_hash, "este el password hash")

        new_user = User(
                first_name = first_name,
                first_last_name = first_last_name,
                second_last_name = second_last_name,
                curp = curp,
                gender = gender,
                birthdate = birthdate,
                email = email,
                password = password_hash,
                phone_number = phone_number,
                facebook = facebook,
                instagram = instagram,
                x = x,
                blood_type = blood_type,
                allergy = allergy,
                disease = disease,
                city = city,
                address = address,
                state = state,
                zip_code = zip_code,
                longitude = longitude,
                latitude = latitude
        )  
        print("nuevo usuario creado")
        try:
            db.session.add(new_user)  
            db.session.commit()

            
        except Exception as error:
            db.session.rollback()
            return jsonify({"message": "Ha ocurrido un error"}), 500

        return jsonify({
            "user": new_user.serialize(),
            "message": "Te has registrado! Redirigiéndote al inicio de sesión" 
        }), 200
    else:
        return jsonify({"message": "Email ya registrado. Intenta con uno nuevo."}), 400
    

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

    if not data or not all(key in data for key in ['cause', 'url_image_complaint', 'complaint_comment', 'status','latitude','longitude' 'user_id']):
        return jsonify({"error": "Missing data"}), 400

    new_complaint = Complaint(
        cause=data['cause'],
        url_image_complaint=data['url_image_complaint'],
        complaint_comment=data['complaint_comment'],
        status=data['status'],
        latitude = data.get('latitude')
        longitude = data.get('longitude')
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


@api_bp.route('/emergency', methods=['POST'])
# @jwt_required()
def send_emergency():
    data = request.json
    print("Datos recibidos en el backend:", data)  # Log de los datos recibidos

    latitude = data.get('latitude')
    longitude = data.get('longitude')
    id = data.get('id')
    print(f'esta es la longitud: {longitude}, y esta es la latitud: {latitude}')

    if not latitude or not longitude:
        return jsonify({"error": "Coordenadas no proporcionadas"}), 400
    
    
    user = User.query.get(id)

    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404

    # Obtener los contactos del usuario
    contacts = Contact.query.filter_by(user_id=user.id).all()

    if not contacts:
        return jsonify({"error": "No hay contactos de emergencia registrados"}), 404

    # Extraer los correos electrónicos de los contactos
    recipients = [contact.email for contact in contacts]

    # Crear el contenido del correo
    subject = "¡Emergencia! Necesito ayuda"
    content = f"""
    <h1>¡Emergencia!</h1>
    <p>El usuario {user.first_name} {user.first_last_name} ha activado el botón de emergencia.</p>
    <p>Sus coordenadas actuales son:</p>
    <ul>
        <li>Latitud: {latitude}</li>
        <li>Longitud: {longitude}</li>
        <li><a href="https://www.google.com/maps?q=25.76941770710694,-100.42743563520318" target="_blank">Ver ubicación en Google Maps</a></li>
    </ul>
    <p>Este es el número de teléfono que registró para emergencias: {user.phone_number}</p>
    <p>Por favor, haz contacto lo antes posible.</p>
      <p>En caso de ser requerido, estos son sus datos clínicos prioritarios:</p>
    <ul>
        <li>Tipo de sangre: {user.blood_type}</li>
        <li>Alergias: {user.allergy}</li>
        <li>Enfermedades crónicas: {user.disease}</li>
    </ul>
    """

    message = Mail(
        from_email='migrappdemo@gmail.com',  # Cambia esto por tu correo
        to_emails=recipients,  # Enviar a todos los contactos
        subject=subject,
        html_content=content
    )
    
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)

        return jsonify({"message": "Correo de emergencia enviado correctamente"}), 200
    except Exception as e:
        print("Error al enviar el correo:", str(e))
        return jsonify({"error": "Error al enviar el correo de emergencia"}), 500
    
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
        from_email='migrappdemo@gmail.com',  
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