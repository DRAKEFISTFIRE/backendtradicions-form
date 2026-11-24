# Tradicions de Mataró — backend con JSON privado por usuario

## Qué hace
- Login con Google OAuth.
- Crea un archivo `data/users/<identificador-hash>/records.json` para cada usuario.
- Guarda los adjuntos en la carpeta privada `uploads/` de ese mismo usuario.
- El navegador nunca recibe la ruta física ni puede elegir el JSON de otro usuario.
- Los endpoints `/api/records` solo leen y modifican los datos del usuario de la sesión.

## Instalación
1. Instala Node.js 20 o superior.
2. Copia tu `index.html` dentro de `public/`.
3. Duplica `.env.example` como `.env`.
4. En Google Cloud Console, crea credenciales OAuth de tipo aplicación web.
5. Añade esta URI autorizada de redirección:
   `http://localhost:3000/auth/google/callback`
6. Rellena `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` y `SESSION_SECRET`.
7. En esta carpeta ejecuta:

   ```bash
   npm install
   npm start
   ```

8. Abre `http://localhost:3000`.

## Endpoints que espera el frontend
- `GET /auth/google`
- `GET /api/me`
- `POST /api/logout`
- `GET /api/records`
- `POST /api/records` — JSON o multipart (`record` + `files`)
- `DELETE /api/records/:id`
- `GET /api/files/:recordId/:filename` — adjunto protegido por sesión

El frontend debe enviar las peticiones con `credentials: "same-origin"`.

## Dónde se guardan los datos
Ejemplo:
```
data/
  users/
    8a... (hash del ID interno de Google)
      records.json
      uploads/
        uuid.pdf
        uuid.jpg
```
No muevas `data/` dentro de `public/`. No configures el servidor web para publicar esa carpeta.

## Importante antes de producción
Esta versión guarda los datos en JSON local y usa el almacén de sesiones MemoryStore integrado en express-session, adecuado solo para pruebas/desarrollo. Para producción:
- usa HTTPS;
- configura un almacén de sesiones persistente (Redis o base de datos);
- añade protección CSRF/rate limiting y copias de seguridad;
- limita y valida los tipos de archivo permitidos;
- usa almacenamiento persistente si el hosting tiene disco efímero;
- si varias peticiones pueden escribir simultáneamente el mismo JSON, usa bloqueo de escritura o una base de datos.

El JSON no es accesible por URL, pero el administrador del servidor y cualquier proceso con acceso al disco sí pueden leerlo. `data/` está excluido de Git mediante `.gitignore`.
# backendtradicions-form
