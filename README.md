# Demo Server

Servidor base con FastAPI preparado para añadir un módulo de autenticación con usuarios,
refresh tokens, migraciones y utilidades de seguridad.

## Stack

- FastAPI
- SQLAlchemy 2.0 async
- PostgreSQL + asyncpg
- Alembic
- Pydantic v2 + Pydantic Settings
- Passlib + Argon2
- python-jose
- pytest + pytest-asyncio + httpx
- Docker + Docker Compose
- ruff + mypy

## Características

Incluye la estructura base del proyecto, settings centralizados, modelos `User` y
`RefreshToken`, schemas Pydantic, hashing Argon2, creación y validación de JWT, handlers
de excepciones de dominio, health check, Docker y migración inicial.

La siguiente fase añadirá endpoints de auth, servicios, repositorios, dependencias de usuario
actual y tests de integración de los flujos de autenticación.

## Decisiones técnicas

Argon2 se usa para contraseñas porque es resistente a ataques con hardware especializado.
Los refresh tokens se guardan hasheados con SHA-256 para no persistir tokens planos. La app
usa SQLAlchemy async y asyncpg para evitar bloquear el servidor en operaciones de base de datos.
Alembic mantiene el schema versionado desde el inicio.

## Estructura

```text
app/
  main.py
  core/
  auth/
  db/
alembic/
  versions/
tests/
```

## Variables de Entorno

Copia `.env.example` a `.env` y ajusta los valores:

```bash
cp .env.example .env
```

En producción cambia siempre `SECRET_KEY`.

## Ejecución con Docker

```bash
docker-compose up --build
```

La API queda disponible en `http://localhost:8000`.

## Ejecución Local

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
copy .env.example .env
alembic upgrade head
uvicorn app.main:app --reload
```

## Migraciones

```bash
alembic upgrade head
alembic revision --autogenerate -m "message"
```

## Tests y Calidad

```bash
pytest
ruff check .
mypy app/
```

## Roadmap

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /auth/me`
- Capa `service.py` y `repository.py`
- Dependencias `get_current_user` y `require_role`
