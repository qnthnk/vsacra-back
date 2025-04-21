from models import User
from database import db
import random
from faker import Faker

def seed_users(count=80):
    """
    Genera y registra `count` usuarios aleatorios en la tabla User.
    """
    fake = Faker('es_MX')  # Localización para nombres mexicanos
    users = []
    for _ in range(count):
        user = User(
            first_name=fake.first_name(),
            first_last_name=fake.last_name(),
            second_last_name=fake.last_name(),
            curp=''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=18)),
            gender=random.choice(['M','F','']),
            birthdate=fake.date_of_birth(minimum_age=18, maximum_age=80).strftime('%Y-%m-%d'),
            email=fake.unique.email(),
            password=fake.password(length=12),
            phone_number=fake.msisdn()[:10],
            facebook=fake.user_name(),
            instagram=fake.user_name(),
            x=fake.user_name(),
            blood_type=random.choice(['A+','A-','B+','B-','AB+','AB-','O+','O-']),
            allergy=random.choice(['Frutos secos','Polen','Ninguna']),
            disease=random.choice(['Asma','Diabetes','Ninguna']),
            state=fake.state(),
            colonia_mex=fake.city(),
            house_number=str(random.randint(1, 9999)),
            street=fake.street_name(),
            seccion='',
            zip_code=fake.postcode(),
            distrito_federal='',
            distrito_local='',
            nombre_municipio=fake.city(),
            tipo_seccion='',
            latitude=str(fake.latitude()),
            longitude=str(fake.longitude())
        )
        users.append(user)

    db.session.bulk_save_objects(users)
    db.session.commit()
    print(f'Se cargaron {count} usuarios en la base de datos.')

# Para usar esta función, asegurate de instalar Faker:
#    pip install Faker
