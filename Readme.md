# 🔒 API de Autenticación con MFA

¡Que onda! Bienvenid@ al backend de nuestro sistema de autenticación creze. Este proyecto esta hecho con Django + DRF y tiene toda la onda para manejar autenticación segura con MFA 🚀

## 🔥 Que trae esta api?

- Autenticación básica con JWT
- MFA usando TOTP (como Google Authenticator, ya sabes)
- Sistema de sesiones MFA para que no te hackeen
- API REST bien documentada
- Verificación de email (para que no se metan bots)
- Tests bien completos (porque somos pros)
- Ya deployado en EC2 (¡vivito y coleando!)

## 🛠️ Pre-requisitos

- Python 3.11 o mas nuevo
- pip (el administrador de paquetes de Python)
- virtualenv (opcional pero recomendado)
- Docker y docker-compose (si quieres correrlo con containers)

## 🚀 Como correrlo en local

1. Clona el repo (si no sabes como, google es tu amigo 😉)
```bash
git clone <url-del-repo>
cd <carpeta-del-proyecto>
```

2. Crea un entorno virtual (opcional pero neta, hazlo)
```bash
python -m venv venv
# En Windows:
venv\Scripts\activate
# En Linux/Mac:
source venv/bin/activate
```

3. Instala las dependencias (toma un cafecito, puede tardar)
```bash
pip install -r requirements.txt
```

4. Crea un archivo `.env` en la raiz del proyecto con estas variables:
```
DEBUG=True
SECRET_KEY=una-clave-super-secreta-que-solo-tu-sepas
ALLOWED_HOSTS=localhost,127.0.0.1
DATABASE_URL=sqlite:///db.sqlite3
MFA_ISSUER_NAME=MiAppChida
```

5. Prepara la base de datos
```bash
python manage.py migrate
```

6. Crea un super usuario (para que puedas entrar al admin de Django)
```bash
python manage.py createsuperuser
```

7. ¡Arranca el servidor!
```bash
python manage.py runserver
```

Y listo! Tu API deberia estar corriendo en `http://localhost:8000` 🎉

## 🧪 Corriendo los tests

Tenemos tests bien chidos para asegurarnos que todo jale. Puedes correrlos asi:

```bash
# Correr todos los tests
python manage.py test authentication.tests

# O si quieres ser mas especifico:
python manage.py test authentication.tests.test_models    # Solo tests de modelos
python manage.py test authentication.tests.test_views     # Solo tests de views
python manage.py test authentication.tests.test_serializers # Solo tests de serializers
```

Si ves que todo esta en verde, ¡vamos bien! 🟢

## 🐳 ¿Prefieres Docker?

Tambien puedes usar Docker si eres de los cool:

```bash
# Para desarrollo
docker-compose up --build
```

## 🚀 Ambiente de Producción
Tenemos el proyecto corriendo en EC2 (¡yuju!). Esta es la info importante:

- URL: http://api.hermesagc.com
- Instancia: AWS EC2 (t2.micro porque humildad ante todo 😅)
- Esta corriendo con Docker Compose


## 📝 Endpoints principales

- `POST /api/auth/signup/`: Registra un usuario nuevo
- `POST /api/auth/login/`: Login normal
- `GET /api/auth/setup-mfa/`: Configura MFA para un usuario
- `POST /api/auth/verify-mfa/`: Verifica el código MFA
- `GET /api/auth/verify-email/<token>/`: Verifica el email del usuario

## 🤔 Problemas comunes

- Si te sale error de CORS, revisa que estes usando los headers correctos
- Si el MFA no funciona, asegurate que la hora de tu compu este bien (si, en serio)
- Si no te llegan los emails, es porque no lo hemos dado de alta (ses lo tengo nomás de prueba)
- Si los tests fallan, revisa que tengas todas las dependencias instaladas

## 👀 Tips

- Usa Postman o Insomnia para probar los endpoints
- No te olvides de activar el entorno virtual antes de correr el servidor

## 🚧 Que falta?

- Mas tests de integracion
- Mejorar el performance en producción
- Configurar auto-scaling en AWS

¿Preguntas? ¡Mandame un mensajito! Y si encuentras un bug, ya sabes... abre un issue 😉

## 📊 Estatus actual

- Tests: ✅ Pasando
- Coverage: 85% (podria estar mejor, pero no esta mal)
- Producción: ✅ Funcionando
- Último deploy: 20/12/2024