from __future__ import annotations

import random
from typing import Optional, Union, Any, Dict, List, Tuple

import oracledb

from pac_config import Config
from logger_config import get_logger, safe_json, sanitize_binds
from pac_utils import build_login, build_nombre_usr, role_code_from_title, role_record_from_code, validate_rut_dv

LOGGER = get_logger("db_pac")


class PacOracleRepo:
    def __init__(self) -> None:
        if Config.ORACLE_THICK_MODE and Config.ORACLE_CLIENT_LIB_DIR:
            oracledb.init_oracle_client(lib_dir=Config.ORACLE_CLIENT_LIB_DIR)
            LOGGER.info("ORACLE_CLIENT_INIT | thick_mode=true | lib_dir=%s", Config.ORACLE_CLIENT_LIB_DIR)
        else:
            LOGGER.info("ORACLE_CLIENT_INIT | thick_mode=false")

    # Contraseñas genericas disponibles para usuarios nuevos
    _PASSWORD_POOL = [
        "oNQnP7E2v3OZs+xUoiJugQ==",   # R2FdDWgVnt
        "73utdAnS4saVkrvVk+W3Tw==",   # XF7WjKXEzU
        "UL7eBlchW/WxN2erH4i4Tw==",   # AU79WgrJ9E
        "0ZEf3ViB8xiJs+niqAjS6w==",   # rNqWUxha79
        "CM8vUPgNA9MC9WY5WpmZ9A==",   # tvR5yNXEKY
        "++qoOIKx9spFb9mMmqTIMw==",   # bCv4nTwdvc
        "TU5JzCyv41rVoJvkTy9jYw==",   # DZg54jRNtA
        "Z5/ag8LeZVDdVFykfSGtEQ==",   # uAjxtRQkz5
        "tnTy5MToR+18sBeYFttnew==",   # ubE2J97Fc5
        "ts2QwJpwwnnWHvzrxMxSHA==",   # T9g4PJw9E7
        "uBshpgwm73H6ADDdIIy//Q==",   # Ka5MsBJ2BC
    ]

    @classmethod
    def _random_password(cls) -> str:
        """Retorna un hash de password generico aleatorio del pool disponible."""
        return random.choice(cls._PASSWORD_POOL)

    @property
    def table(self) -> str:
        return f"{Config.PAC_SCHEMA_OWNER}.PAC_USUARIO"

    def _connect(self):
        return oracledb.connect(
            user=Config.ORACLE_USER,
            password=Config.ORACLE_PASSWORD,
            dsn=Config.ORACLE_DSN,
        )

    @staticmethod
    def _row_to_dict(cursor, row) -> Dict[str, Any]:
        return {d[0]: row[i] for i, d in enumerate(cursor.description)}

    @staticmethod
    def _log_sql(sql: str, binds: Dict[str, Any] | None = None) -> None:
        LOGGER.info(
            "SQL_EXECUTE | sql=%s | binds=%s",
            " ".join(line.strip() for line in sql.strip().splitlines()),
            safe_json(sanitize_binds(binds)),
        )

    def _fetch_one(self, sql: str, binds: Dict[str, Any] | None = None) -> Optional[Dict[str, Any]]:
        self._log_sql(sql, binds)
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(sql, binds or {})
            row = cur.fetchone()
            return self._row_to_dict(cur, row) if row else None

    def _fetch_all(self, sql: str, binds: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
        self._log_sql(sql, binds)
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(sql, binds or {})
            return [self._row_to_dict(cur, row) for row in cur.fetchall()]

    def healthcheck(self) -> bool:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1 FROM DUAL")
            row = cur.fetchone()
            ok = bool(row and row[0] == 1)
            LOGGER.info("HEALTHCHECK_DB | ok=%s", ok)
            return ok

    def list_roles(self, start_index: int = 1, count: int = Config.SCIM_DEFAULT_PAGE_SIZE) -> Tuple[List[Dict[str, Any]], int]:
        values = list(Config.PAC_ROLES.values())
        total = len(values)
        offset = max(start_index - 1, 0)
        limit = offset + max(1, min(count, Config.SCIM_MAX_PAGE_SIZE))
        return values[offset:limit], total

    def get_role(self, role_id: str) -> Optional[Dict[str, Any]]:
        try:
            return Config.PAC_ROLES.get(int(role_id))
        except (ValueError, TypeError):
            return None

    def _build_scim_user_model(self, row: Dict[str, Any]) -> Dict[str, Any]:
        c_est = int(row.get("C_EST") or 0)
        active = c_est == 1
        role_code = int(row.get("C_ROL") or Config.PAC_DEFAULT_ROLE_CODE_IF_UNMAPPED)
        role_info = role_record_from_code(role_code)
        login = str(row.get("A_LOGIN_USR") or "")
        c_id_usr = str(row.get("C_ID_USR") or "")
        c_digid = str(row.get("C_DIGID_USR") or "")

        nombre_completo = str(row.get("A_NOMBRE_USR") or "").strip()
        partes = nombre_completo.split(" ", 1)
        first_name = partes[0] if partes else ""
        last_name  = partes[1] if len(partes) >= 2 else first_name

        return {
            "id": str(row["C_USR"]),
            "externalId": login,
            "userName": login,
            "firstName": first_name,
            "lastName": last_name,
            "email": str(row.get("A_EMAIL_USR") or ""),
            "active": active,
            "custom": {
                "rutSinDv": c_id_usr,
                "dv": c_digid,
                "codigoRol": str(role_code),
                "nombreRol": role_info["name"],
                "login": login,
            },
        }

    def get_user_by_login(self, login: str) -> Optional[Dict[str, Any]]:
        sql = f"""
            SELECT C_USR, C_ID_USR, C_DIGID_USR, C_ROL, C_EST,
                   A_NOMBRE_USR, A_LOGIN_USR, A_EMAIL_USR
            FROM {self.table}
            WHERE A_LOGIN_USR = :login
        """
        row = self._fetch_one(sql, {"login": login})
        return self._build_scim_user_model(row) if row else None

    def get_user(self, c_usr: str) -> Optional[Dict[str, Any]]:
        sql = f"""
            SELECT C_USR, C_ID_USR, C_DIGID_USR, C_ROL, C_EST,
                   A_NOMBRE_USR, A_LOGIN_USR, A_EMAIL_USR
            FROM {self.table}
            WHERE C_USR = :c_usr
        """
        row = self._fetch_one(sql, {"c_usr": c_usr})
        return self._build_scim_user_model(row) if row else None

    def list_users(
        self,
        start_index: int = 1,
        count: int = Config.SCIM_DEFAULT_PAGE_SIZE,
        filter_attr: str | None = None,
        filter_value: str | None = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        start_index = max(1, int(start_index))
        count = max(1, min(int(count), Config.SCIM_MAX_PAGE_SIZE))
        offset = start_index - 1

        base_where = ""
        binds: Dict[str, Any] = {}

        if filter_attr and filter_value:
            if filter_attr in ("userName", "A_LOGIN_USR"):
                base_where = "WHERE A_LOGIN_USR = :filter_value"
                binds["filter_value"] = filter_value
            else:
                raise ValueError(f"Filtro no soportado para Users: {filter_attr}")

        sql_count = f"SELECT COUNT(1) AS TOTAL FROM {self.table} {base_where}"
        sql_page = f"""
            SELECT * FROM (
                SELECT q.*, ROW_NUMBER() OVER (ORDER BY q.C_USR) AS RN
                FROM (
                    SELECT C_USR, C_ID_USR, C_DIGID_USR, C_ROL, C_EST,
                           A_NOMBRE_USR, A_LOGIN_USR, A_EMAIL_USR
                    FROM {self.table}
                    {base_where}
                ) q
            )
            WHERE RN > :offset AND RN <= :limit
        """
        total_row = self._fetch_one(sql_count, binds)
        page_binds = dict(binds)
        page_binds["offset"] = offset
        page_binds["limit"] = offset + count
        rows = self._fetch_all(sql_page, page_binds)

        total = int(total_row["TOTAL"] if total_row else 0)
        return [self._build_scim_user_model(r) for r in rows], total

    def _next_c_usr(self, cur) -> int:
        # Intentar con secuencia de produccion primero
        # Si no existe, usar MAX(C_USR)+1 como fallback
        try:
            cur.execute(f"SELECT {Config.PAC_SCHEMA_OWNER}.SEQ_PAC_USUARIO.NEXTVAL FROM DUAL")
        except Exception:
            cur.execute(f"SELECT NVL(MAX(C_USR), 0) + 1 AS NEXT_C_USR FROM {self.table}")
        return int(cur.fetchone()[0])

    def upsert_user(self, data: Dict[str, Any]) -> Dict[str, Any]:
        custom = data.get("custom") or {}
        rut_raw = str(custom.get("rutSinDv") or "").strip()
        dv_raw  = str(custom.get("dv") or "").strip()
        # userName puede venir como login completo (ej: "981291409") o como RUT con DV (ej: "98129140-9")
        username_raw = str(data.get("userName") or "").strip()

        if rut_raw and dv_raw:
            # Custom schema trae rut y dv separados - caso ideal
            rut_sin_dv = rut_raw
            dv = dv_raw.upper()
            login = f"{rut_sin_dv}{dv}"
        elif username_raw:
            import re as _re
            # Si contiene guion → formatear como RUT con DV (ej: "20905343-8" o "9765432-K")
            if "-" in username_raw:
                rut_sin_dv, dv = validate_rut_dv(username_raw)
                login = f"{rut_sin_dv}{dv}"
            # Si termina en K → login completo con DV alfabetico (ej: "9765432K")
            elif username_raw.upper().endswith("K"):
                login = username_raw.upper()
                rut_sin_dv = login[:-1]
                dv = "K"
            # Solo digitos → puede ser login completo o RUT sin DV
            elif username_raw.isdigit():
                # Verificar si el ultimo digito es el DV correcto
                rut_candidate = username_raw[:-1]
                dv_candidate = username_raw[-1]
                import sys as _sys
                _sys.path.insert(0, "/mnt/user-data/uploads")
                try:
                    from pac_utils import _calc_dv as _cdv
                    if _cdv(rut_candidate) == dv_candidate:
                        # Ultimo digito es DV correcto → es login completo
                        login = username_raw
                        rut_sin_dv = rut_candidate
                        dv = dv_candidate
                    else:
                        # No es DV correcto → es RUT sin DV, calcular
                        rut_sin_dv, dv = validate_rut_dv(username_raw)
                        login = f"{rut_sin_dv}{dv}"
                except Exception:
                    rut_sin_dv, dv = validate_rut_dv(username_raw)
                    login = f"{rut_sin_dv}{dv}"
            else:
                rut_sin_dv, dv = validate_rut_dv(username_raw)
                login = f"{rut_sin_dv}{dv}"
        else:
            raise ValueError("Se requiere userName o rutSinDv para identificar el usuario PAC.")

        nombre = build_nombre_usr(data.get("firstName"), data.get("lastName"))
        email = str(data.get("email") or custom.get("email") or "").strip()
        active = bool(data.get("active", True))
        c_est = 1 if active else 0

        role_from_payload = custom.get("codigoRol")
        role_code = int(role_from_payload) if role_from_payload else role_code_from_title(data.get("title"))
        role_info = role_record_from_code(role_code)

        if not nombre:
            raise ValueError("firstName es obligatorio para PAC.")

        LOGGER.info(
            "PAC_UPSERT_START | login=%s | nombre=%s | active=%s | role_code=%s",
            login, nombre, active, role_info["code"],
        )

        existing = self.get_user_by_login(login)

        with self._connect() as conn, conn.cursor() as cur:
            if existing:
                # UPDATE
                sql = f"""
                    UPDATE {self.table}
                    SET A_NOMBRE_USR = :nombre,
                        A_EMAIL_USR  = :email,
                        C_ROL        = :c_rol,
                        C_EST        = :c_est,
                        D_MODIF_USR  = SYSDATE
                    WHERE C_USR       = :c_usr
                      AND A_LOGIN_USR = :login
                """
                binds = {
                    "nombre": nombre,
                    "email": email,
                    "c_rol": role_info["code"],
                    "c_est": c_est,
                    "c_usr": int(existing["id"]),
                    "login": login,
                }
                self._log_sql(sql, binds)
                cur.execute(sql, binds)
            else:
                # INSERT
                c_usr = self._next_c_usr(cur)
                sql = f"""
                    INSERT INTO {self.table} (
                        C_USR, C_ID_USR, C_DIGID_USR, C_TIPO_ID, C_ROL,
                        C_PAIS, C_EST, C_CORR_COD, C_SUC,
                        A_NOMBRE_USR, A_DESC_USR, N_FONO_USR,
                        A_LOGIN_USR, A_PASS_USR,
                        D_CREAC_USR, D_MODIF_USR,
                        A_EMAIL_USR, C_MOD_USR, A_DESMOD_USR, C_PERMISO_USR
                    ) VALUES (
                        :c_usr, :c_id_usr, :c_digid_usr, 1, :c_rol,
                        :c_pais, :c_est, :c_corr_cod, :c_suc,
                        :nombre, '1', 0,
                        :login, :a_pass_usr,
                        SYSDATE,
                        SYSDATE,
                        :email, 0, 'Creacion', 0
                    )
                """
                binds = {
                    "c_usr": c_usr,
                    "c_id_usr": int(rut_sin_dv),
                    "c_digid_usr": dv,
                    "c_rol": role_info["code"],
                    "c_pais": Config.PAC_DEFAULT_PAIS,
                    "c_est": c_est,
                    "c_corr_cod": Config.PAC_DEFAULT_CORR_COD,
                    "c_suc": Config.PAC_DEFAULT_SUC,
                    "nombre": nombre,
                    "login": login,
                    "a_pass_usr": self._random_password(),
                    "email": email,
                }
                self._log_sql(sql, binds)
                cur.execute(sql, binds)

            conn.commit()
            LOGGER.info("DB_COMMIT | action=UPSERT_PAC_USER | login=%s", login)

        user = self.get_user_by_login(login)
        if not user:
            raise RuntimeError(f"No fue posible recuperar el usuario PAC '{login}' después del upsert.")
        return user

    def deactivate_user(self, c_usr: str) -> None:
        existing = self.get_user(c_usr)
        if not existing:
            raise ValueError(f"Usuario PAC '{c_usr}' no encontrado.")
        with self._connect() as conn, conn.cursor() as cur:
            sql = f"""
                UPDATE {self.table}
                SET C_EST       = 0,
                    D_MODIF_USR = SYSDATE
                WHERE C_USR       = :c_usr
                  AND A_LOGIN_USR = :login
            """
            binds = {"c_usr": int(c_usr), "login": existing["userName"]}
            self._log_sql(sql, binds)
            cur.execute(sql, binds)
            conn.commit()
            LOGGER.info("DB_COMMIT | action=DEACTIVATE_PAC_USER | c_usr=%s", c_usr)

    def change_password(self, c_usr: str, password_hash: str) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            sql = f"""
                UPDATE {self.table}
                SET A_PASS_USR  = :pass_usr,
                    D_MODIF_USR = SYSDATE
                WHERE C_USR = :c_usr
                  AND C_EST = 1
            """
            binds = {"pass_usr": password_hash, "c_usr": int(c_usr)}
            self._log_sql(sql, binds)
            cur.execute(sql, binds)
            conn.commit()
            LOGGER.info("DB_COMMIT | action=CHANGE_PASSWORD_PAC_USER | c_usr=%s", c_usr)