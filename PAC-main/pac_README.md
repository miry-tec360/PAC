# PAC SCIM 2.0 Server

Servidor SCIM 2.0 para la integración entre **Okta** y la plataforma **PAC** (Plataforma de Atención al Cliente) de Falabella. Implementado en Python/Flask con backend Oracle, siguiendo la misma estructura base del SAT SCIM Server.

---

## Arquitectura general

```
Okta (Identity Provider)
        │
        │  SCIM 2.0 over HTTPS
        │  Bearer Token Auth
        ▼
PAC SCIM 2.0 Server  (Flask, puerto 6001)
        │
        │  oracledb
        ▼
Oracle DB  (schema: PACCLPR)
  └── PAC_USUARIO   ← tabla única de usuarios y roles
```

---

## Diferencias clave respecto a SAT SCIM

| Aspecto | SAT | PAC |
|---|---|---|
| Tabla principal | SGDT947 + SGDT958 | PAC_USUARIO (tabla única) |
| Identificador login | RUT sin DV | RUT + DV sin guion (ej: `209053438`) |
| Fuente del userName | `user.login` derivado | `user.extensionAttribute1` |
| Relación usuario-rol | SGDT958 separada | Columna `C_ROL` en PAC_USUARIO |
| Estado activo | FECBAJA = `0001-01-01` | `C_EST = 1` |
| Estado inactivo | FECBAJA = fecha actual | `C_EST = 0` |
| Puerto por defecto | 6000 | 6001 |

---

## Roles disponibles

| C_ROL | Nombre |
|---|---|
| 1 | Admin. CMR |
| 2 | Reportes |
| 4 | Consulta |
| 24 | GERENTE CMR |
| 25 | RR.CC. con FE/VT |
| 26 | Jefe y Supervisor |
| 27 | Gerente Zonal |
| 28 | Administrador Usuarios |
| 64 | Admin. PAC |
| 187 | Backoffice Copro |
| 200 | RR.CC. por Contingencia |
| 201 | RR.CC. sin FE/VT AUTENTIA |
| 207 | FALABELLA CONNECT |
| 227 | RR.CC. sin FE/VT TOC |
| 307 | RRCC Firma Electronica - Convivencia TOC Autentia |

### Mapeo title → rol (Sucursal)

| Title en Okta | C_ROL | Nombre Rol |
|---|---|---|
| Agente | 26 | Jefe y Supervisor |
| Ejecutivo(A) Integral | 25 | RR.CC. con FE/VT |
| Gerente De Sucursales | 27 | Gerente Zonal |
| Gerente Zonal | 27 | Gerente Zonal |
| Supervisor (A) De Sucursal | 26 | Jefe y Supervisor |

### Mapeo title → rol (Contact Center)

| Title en Okta | C_ROL | Nombre Rol |
|---|---|---|
| Ejecutivo de Atención de Canales Digitales | 201 | RR.CC. sin FE/VT AUTENTIA |
| Ejecutivo(A) Banca Telefonica | 201 | RR.CC. sin FE/VT AUTENTIA |
| Supervisor Atencion Canales Digitales | 26 | Jefe y Supervisor |
| Supervisor Banca Telefonica | 26 | Jefe y Supervisor |
| Supervisor SAC | 26 | Jefe y Supervisor |

Si no hay match, el rol por defecto es `4` (Consulta).

---

## Mapeo Okta → BD

| Variable Okta | Columna BD | Notas |
|---|---|---|
| `user.extensionAttribute1` | `A_LOGIN_USR` | RUT+DV sin guion (ej: `209053438`) |
| `firstName` + `lastName` | `A_NOMBRE_USR` | Nombre completo en MAYÚSCULAS |
| `email` | `A_EMAIL_USR` | Correo corporativo |
| `roles[].value` o `codigoRol` | `C_ROL` | Código numérico del rol |
| `active` | `C_EST` | 1=ACTIVO, 0=INACTIVO |
| RUT sin DV | `C_ID_USR` | Número sin dígito verificador |
| DV | `C_DIGID_USR` | Dígito verificador |

### Ciclo de vida de estados

| Evento | Estado Okta | `C_EST` en PAC |
|---|---|---|
| Alta | STAGED / PENDING / ACTIVE | 1 (ACTIVO) |
| Actualización | ACTIVE / PENDING / STAGED | 1 (ACTIVO) |
| Baja | SUSPEND / DEACTIVATED / DELETED | 0 (INACTIVO) |

---

## Custom schema

Namespace: `urn:okta:pac:1.0:user:custom`

| Atributo | Tipo | Mutabilidad | Descripción |
|---|---|---|---|
| `rutSinDv` | string | readWrite | RUT sin dígito verificador |
| `dv` | string | readOnly | Dígito verificador |
| `codigoRol` | string | readWrite | Código numérico del rol PAC |
| `nombreRol` | string | readOnly | Nombre del rol |
| `login` | string | readOnly | RUT+DV (A_LOGIN_USR) |
| `userchangepwd` | boolean | readWrite | `true` para gatillar cambio de contraseña |

---

## Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| `GET` | `/` | Health check básico |
| `GET` | `/healthz` | Verifica conexión a Oracle |
| `GET` | `/scim/v2/ServiceProviderConfig` | Capacidades del servidor |
| `GET` | `/scim/v2/Schemas` | Esquemas soportados |
| `GET` | `/scim/v2/ResourceTypes` | Tipos de recursos |
| `GET` | `/scim/v2/Roles` | Lista todos los roles |
| `GET` | `/scim/v2/Roles/{id}` | Obtiene un rol por código |
| `GET` | `/scim/v2/Users` | Lista usuarios con paginación/filtro |
| `GET` | `/scim/v2/Users/{id}` | Obtiene usuario por C_USR |
| `POST` | `/scim/v2/Users` | Crea usuario |
| `PUT` | `/scim/v2/Users/{id}` | Reemplaza usuario completo |
| `DELETE` | `/scim/v2/Users/{id}` | Baja lógica (`C_EST = 0`) |

---

## Instalación

```bash
git clone <repo_url>
cd pac-scim-server

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
# Editar .env con valores reales

python pac_app.py
```

---

## Variables de entorno

| Variable | Default | Descripción |
|---|---|---|
| `SCIM_HOST` | `0.0.0.0` | Interfaz de escucha |
| `SCIM_PORT` | `6001` | Puerto |
| `SCIM_BASE_URL` | `http://localhost:6001/scim/v2` | URL base pública |
| `SCIM_BEARER_TOKEN` | *(requerido)* | Token de autenticación |
| `ORACLE_USER` | | Usuario Oracle |
| `ORACLE_PASSWORD` | | Contraseña Oracle |
| `ORACLE_DSN` | | DSN de conexión |
| `PAC_SCHEMA_OWNER` | `PACCLPR` | Schema Oracle de PAC |
| `PAC_DEFAULT_ROLE_CODE_IF_UNMAPPED` | `4` | Rol si no hay match por title |
| `PAC_DEFAULT_PASSWORD_HASH` | `oNQnP7E2v3OZs+xUoiJugQ==` | Hash contraseña genérica al crear |

---

## Contraseñas genéricas disponibles

Al crear un usuario, se asigna automáticamente una contraseña genérica. Informar al usuario su contraseña en texto plano:

| Texto plano | Hash en BD |
|---|---|
| `R2FdDWgVnt` | `oNQnP7E2v3OZs+xUoiJugQ==` |
| `XF7WjKXEzU` | `73utdAnS4saVkrvVk+W3Tw==` |
| `AU79WgrJ9E` | `UL7eBlchW/WxN2erH4i4Tw==` |
| `rNqWUxha79` | `0ZEf3ViB8xiJs+niqAjS6w==` |
| `tvR5yNXEKY` | `CM8vUPgNA9MC9WY5WpmZ9A==` |

---

## Estructura de archivos

```
pac-scim-server/
├── pac_app.py          ← Entrypoint Flask + endpoints SCIM
├── pac_config.py       ← Config, roles hardcodeados, mapeo title→rol
├── db_pac.py           ← Repositorio Oracle (queries, upsert, baja)
├── pac_schema.py       ← Serialización SCIM (user_to_scim, role_to_scim)
├── pac_utils.py        ← Validación RUT, derivación de rol, utilidades
├── logger_config.py    ← Logging estructurado (compartido con SAT SCIM)
├── requirements.txt    ← Dependencias
├── .env                ← Variables de entorno (no commitear)
└── logs/
    └── pac-scim-server.log
```

---

## Consideraciones para producción

- Confirmar si existe una SEQUENCE en Oracle para `C_USR` o si se usa `MAX(C_USR)+1`
- Confirmar columnas exactas de `PAC_USUARIO` en el ambiente real
- Validar el comportamiento de `userchangepwd` con el equipo PAC
- Probar siempre en QA antes de ejecutar contra productivo
- Rotar el `SCIM_BEARER_TOKEN` periódicamente y actualizarlo en Okta
