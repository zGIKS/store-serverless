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
