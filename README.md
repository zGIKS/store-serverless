# API minimalista en Go + PostgreSQL

API CRUD de productos con migraciones automáticas, auth por username/password (usuario único), JWT corto con refresh rotation, rate limit de login, bloqueo temporal por intentos fallidos y observabilidad básica.

## Endpoints

- `GET /health` -> estado de servicio (DB check)
- `POST /auth/login` -> devuelve `access_token` + `refresh_token`
- `POST /auth/refresh` -> rota `refresh_token` y devuelve nuevos tokens
- `POST /auth/logout` -> revoca `refresh_token` actual
- `GET /products` -> público
- `POST /products` -> requiere `Authorization: Bearer <access_token>`
- `PUT /products/{id}` -> requiere token
- `DELETE /products/{id}` -> requiere token
- `POST /media/upload` -> requiere token, sube archivo y devuelve `secure_url`

## Seguridad aplicada

- Rate limit en login por IP (`LOGIN_RATE_LIMIT_MAX` / ventana `LOGIN_RATE_LIMIT_WINDOW_SECONDS`).
- Bloqueo temporal por intentos fallidos por username (`LOGIN_MAX_ATTEMPTS`, `LOGIN_LOCK_MINUTES`).
- Access token corto (default 15 min) + refresh token con rotación (default 7 días).
- Validación estricta de payload y `image_url` (solo `http/https`, ASCII, sin espacios ni caracteres raros).
- En `POST /products` y `PUT /products/{id}` la imagen se sube a Cloudinary y se guarda `secure_url`.

## Variables de entorno

```env
DATABASE_URL=postgresql://USER:PASSWORD@HOST/DB?sslmode=require
PORT=8080
JWT_SECRET=replace_with_long_random_secret
CLOUDINARY_URL=cloudinary://API_KEY:API_SECRET@CLOUD_NAME
ADMIN_USERNAME=admin_secure_name
ADMIN_PASSWORD=replace_with_strong_password

# Opcionales
APP_ENV=production
SENTRY_DSN=
RUN_MIGRATIONS_ON_STARTUP=true
CRON_SECRET=replace_with_long_random_secret
AUTH_REFRESH_TOKEN_RETENTION_DAYS=14
AUTH_LOGIN_ATTEMPT_RETENTION_DAYS=30
AUTH_CLEANUP_BATCH_SIZE=500
DB_MAX_OPEN_CONNS=10
DB_MAX_IDLE_CONNS=5
DB_CONN_MAX_LIFETIME_MINUTES=30
DB_CONN_MAX_IDLE_TIME_MINUTES=10
LOGIN_RATE_LIMIT_MAX=10
LOGIN_RATE_LIMIT_WINDOW_SECONDS=60
LOGIN_MAX_ATTEMPTS=5
LOGIN_LOCK_MINUTES=15
ACCESS_TOKEN_TTL_MINUTES=15
REFRESH_TOKEN_TTL_HOURS=168
```

## Ejecutar local

```bash
go mod tidy
go run ./cmd/api
```

## Deploy en Vercel

- El proyecto ya incluye `api/index.go` y `vercel.json` para enrutar todo a una sola función Go.
- Configura en Vercel las mismas variables de entorno de la sección anterior.
- Recomendado en Vercel: `RUN_MIGRATIONS_ON_STARTUP=false` y ejecutar migraciones fuera del request path.
- Si quieres aplicar migraciones desde runtime, habilita `RUN_MIGRATIONS_ON_STARTUP=true` (puede aumentar cold start).
- El cleanup diario de auth ya está configurado en `vercel.json` (04:00 UTC) hacia `GET /internal/maintenance/cleanup`.
- Para que el cron sea seguro, define `CRON_SECRET` en Vercel (la plataforma enviará `Authorization: Bearer <CRON_SECRET>`).
- El rate limit de login usa Postgres (`auth_login_ip_limits`), por lo que funciona de forma consistente en múltiples instancias serverless.
- Ajusta el pool de DB con `DB_MAX_OPEN_CONNS`, `DB_MAX_IDLE_CONNS`, `DB_CONN_MAX_LIFETIME_MINUTES` y `DB_CONN_MAX_IDLE_TIME_MINUTES` según tu plan de Neon.

## Login y uso

```bash
TOKENS=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin_secure_name","password":"replace_with_strong_password"}')

ACCESS=$(echo "$TOKENS" | jq -r .access_token)
REFRESH=$(echo "$TOKENS" | jq -r .refresh_token)

curl -X POST http://localhost:8080/products \
  -H "Authorization: Bearer ${ACCESS}" \
  -H "Content-Type: application/json" \
  -d '{"title":"Producto","description":"Desc","price":15,"image_url":"https://example.com/a.png"}'

curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"${REFRESH}\"}"
```
