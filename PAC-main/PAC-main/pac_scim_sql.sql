-- =============================================================
-- PAC SCIM 2.0 - Scripts de validación y soporte para BD Oracle
-- Schema: PACCLPR
-- Tabla:  PACCLPR.PAC_USUARIO
-- =============================================================

-- -------------------------------------------------------------
-- 1. VALIDAR EXISTENCIA DE USUARIO POR LOGIN (RUT+DV)
--    Usado en: GET /scim/v2/Users?filter=userName eq "209053438"
-- -------------------------------------------------------------
SELECT C_USR, C_ID_USR, C_DIGID_USR, C_ROL, C_EST,
       A_NOMBRE_USR, A_LOGIN_USR, A_EMAIL_USR
FROM PACCLPR.PAC_USUARIO
WHERE A_LOGIN_USR = :login;
-- :login = user.extensionAttribute1 (RUT completo con DV, ej: 209053438)


-- -------------------------------------------------------------
-- 2. OBTENER USUARIO POR C_USR (PK interna)
--    Usado en: GET /scim/v2/Users/{id}
-- -------------------------------------------------------------
SELECT C_USR, C_ID_USR, C_DIGID_USR, C_ROL, C_EST,
       A_NOMBRE_USR, A_LOGIN_USR, A_EMAIL_USR,
       D_CREAC_USR, D_MODIF_USR
FROM PACCLPR.PAC_USUARIO
WHERE C_USR = :c_usr;


-- -------------------------------------------------------------
-- 3. LISTAR USUARIOS CON PAGINACIÓN
--    Usado en: GET /scim/v2/Users?startIndex=1&count=100
-- -------------------------------------------------------------
SELECT * FROM (
    SELECT q.*, ROW_NUMBER() OVER (ORDER BY q.C_USR) AS RN
    FROM (
        SELECT C_USR, C_ID_USR, C_DIGID_USR, C_ROL, C_EST,
               A_NOMBRE_USR, A_LOGIN_USR, A_EMAIL_USR
        FROM PACCLPR.PAC_USUARIO
    ) q
)
WHERE RN > :offset AND RN <= :limit;
-- :offset = startIndex - 1
-- :limit  = startIndex - 1 + count


-- -------------------------------------------------------------
-- 4. CONTAR TOTAL DE USUARIOS (para totalResults en ListResponse)
-- -------------------------------------------------------------
SELECT COUNT(1) AS TOTAL
FROM PACCLPR.PAC_USUARIO;


-- -------------------------------------------------------------
-- 5. OBTENER SIGUIENTE VALOR DE CORRELATIVO C_USR
--    Usado en: POST /scim/v2/Users (crear usuario)
--    IMPORTANTE: Confirmar si existe una SEQUENCE en producción.
--    Si no existe, usar este fallback.
-- -------------------------------------------------------------
SELECT NVL(MAX(C_USR), 0) + 1 AS NEXT_C_USR
FROM PACCLPR.PAC_USUARIO;

-- Si existe sequence, usar:
-- SELECT PACCLPR.SEQ_PAC_USUARIO.NEXTVAL AS NEXT_C_USR FROM DUAL;


-- -------------------------------------------------------------
-- 6. CREAR USUARIO (ALTA)
--    Usado en: POST /scim/v2/Users
--    Estado Okta: STAGED / PENDING / ACTIVE → C_EST = 1
-- -------------------------------------------------------------
INSERT INTO PACCLPR.PAC_USUARIO (
    C_USR, C_ID_USR, C_DIGID_USR, C_TIPO_ID, C_ROL,
    C_PAIS, C_EST, C_CORR_COD, C_SUC,
    A_NOMBRE_USR, A_DESC_USR, N_FONO_USR,
    A_LOGIN_USR, A_PASS_USR,
    D_CREAC_USR, D_MODIF_USR,
    A_EMAIL_USR, C_MOD_USR, A_DESMOD_USR, C_PERMISO_USR
) VALUES (
    :c_usr,          -- Correlativo siguiente (ver query 5)
    :c_id_usr,       -- RUT sin DV           (ej: 20905343)
    :c_digid_usr,    -- DV                   (ej: 8)
    1,               -- C_TIPO_ID por defecto
    :c_rol,          -- Código rol           (ej: 25, 26, 27...)
    'cl',            -- País por defecto
    1,               -- C_EST = 1 (ACTIVO)
    601,             -- C_CORR_COD por defecto (entrada Siebel/PAC)
    '000000',        -- C_SUC por defecto (Ahumada)
    :a_nombre_usr,   -- firstName + " " + lastName en MAYÚSCULAS
    '1',             -- A_DESC_USR por defecto
    0,               -- N_FONO_USR por defecto
    :a_login_usr,    -- RUT completo con DV  (ej: 209053438)
    :a_pass_usr,     -- Hash contraseña genérica
    TO_DATE(SYSDATE, 'YYYY-MM-DD HH24:MI:SS'),
    TO_DATE(SYSDATE, 'YYYY-MM-DD HH24:MI:SS'),
    :a_email_usr,    -- Email del usuario
    0,               -- C_MOD_USR por defecto
    'Creacion',      -- A_DESMOD_USR por defecto
    0                -- C_PERMISO_USR por defecto
);


-- -------------------------------------------------------------
-- 7. ACTUALIZAR USUARIO (atributos Okta → BD)
--    Usado en: PUT /scim/v2/Users/{id}
--    Estado Okta: ACTIVE / PENDING / STAGED → C_EST = 1
-- -------------------------------------------------------------
UPDATE PACCLPR.PAC_USUARIO
SET A_NOMBRE_USR  = :a_nombre_usr,   -- firstName + " " + lastName MAYÚSCULAS
    A_EMAIL_USR   = :a_email_usr,
    C_ROL         = :c_rol,
    D_MODIF_USR   = TO_DATE(SYSDATE, 'YYYY-MM-DD HH24:MI:SS')
WHERE C_USR       = :c_usr
  AND A_LOGIN_USR = :a_login_usr;


-- -------------------------------------------------------------
-- 8. BAJA DE USUARIO (desactivar)
--    Usado en: DELETE /scim/v2/Users/{id}
--    Estado Okta: SUSPEND / DEACTIVATED / DELETED → C_EST = 0
-- -------------------------------------------------------------
UPDATE PACCLPR.PAC_USUARIO
SET C_EST        = 0,
    D_MODIF_USR  = TO_DATE(SYSDATE, 'YYYY-MM-DD HH24:MI:SS')
WHERE C_USR       = :c_usr
  AND A_LOGIN_USR = :a_login_usr;


-- -------------------------------------------------------------
-- 9. REACTIVAR USUARIO
--    Usado en: PUT /scim/v2/Users/{id} cuando active=true
--    y el usuario estaba dado de baja (C_EST = 0)
-- -------------------------------------------------------------
UPDATE PACCLPR.PAC_USUARIO
SET C_EST        = 1,
    D_MODIF_USR  = TO_DATE(SYSDATE, 'YYYY-MM-DD HH24:MI:SS')
WHERE C_USR       = :c_usr
  AND A_LOGIN_USR = :a_login_usr;


-- -------------------------------------------------------------
-- 10. CAMBIO DE CONTRASEÑA GENÉRICA
--     Usado cuando userchangepwd = true en Okta
--     Las contraseñas genéricas disponibles son:
--       R2FdDWgVnt  →  oNQnP7E2v3OZs+xUoiJugQ==
--       XF7WjKXEzU  →  73utdAnS4saVkrvVk+W3Tw==
--       AU79WgrJ9E  →  UL7eBlchW/WxN2erH4i4Tw==
--       rNqWUxha79  →  0ZEf3ViB8xiJs+niqAjS6w==
--       tvR5yNXEKY  →  CM8vUPgNA9MC9WY5WpmZ9A==
-- -------------------------------------------------------------
UPDATE PACCLPR.PAC_USUARIO
SET A_PASS_USR   = :a_pass_usr,   -- Hash genérico (ver tabla arriba)
    D_MODIF_USR  = TO_DATE(SYSDATE, 'YYYY-MM-DD HH24:MI:SS')
WHERE C_USR       = :c_usr
  AND C_EST       = 1;


-- -------------------------------------------------------------
-- 11. VERIFICAR EXISTENCIA ANTES DE INSERT (evitar duplicados)
-- -------------------------------------------------------------
SELECT COUNT(1) AS TOTAL
FROM PACCLPR.PAC_USUARIO
WHERE A_LOGIN_USR = :login;


-- -------------------------------------------------------------
-- 12. VERIFICAR EXISTENCIA POR C_USR (para GET por id)
-- -------------------------------------------------------------
SELECT COUNT(1) AS TOTAL
FROM PACCLPR.PAC_USUARIO
WHERE C_USR = :c_usr;
