from __future__ import annotations
from typing import Optional, Union, Any, Dict, List, Tuple
import os
from dotenv import load_dotenv

load_dotenv()


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


class Config:
    HOST = os.getenv("SCIM_HOST", "0.0.0.0")
    PORT = int(os.getenv("SCIM_PORT", "6000"))
    BASE_URL = os.getenv("SCIM_BASE_URL", "http://10.70.255.115:6000/scim/v2").rstrip("/")
    BEARER_TOKEN = os.getenv("SCIM_BEARER_TOKEN", "")
    CUSTOM_SCHEMA = os.getenv("OKTA_CUSTOM_SCHEMA", "urn:okta:pac:1.0:user:custom")

    ORACLE_USER = os.getenv("ORACLE_USER", "")
    ORACLE_PASSWORD = os.getenv("ORACLE_PASSWORD", "")
    ORACLE_DSN = os.getenv("ORACLE_DSN", "")
    ORACLE_THICK_MODE = _as_bool(os.getenv("ORACLE_THICK_MODE"), False)
    ORACLE_CLIENT_LIB_DIR = os.getenv("ORACLE_CLIENT_LIB_DIR", "").strip() or None

    SCIM_DEBUG = _as_bool(os.getenv("SCIM_DEBUG"), False)
    SCIM_LOG_LEVEL = os.getenv("SCIM_LOG_LEVEL", "DEBUG" if SCIM_DEBUG else "INFO").upper()
    SCIM_LOG_DIR = os.getenv("SCIM_LOG_DIR", "logs")
    SCIM_LOG_FILE = os.getenv("SCIM_LOG_FILE", "pac-scim-server.log")
    SCIM_LOG_BACKUP_COUNT = max(1, int(os.getenv("SCIM_LOG_BACKUP_COUNT", "30")))
    SCIM_MAX_PAGE_SIZE = max(1, min(int(os.getenv("SCIM_MAX_PAGE_SIZE", "200")), 1000))
    SCIM_DEFAULT_PAGE_SIZE = max(1, min(int(os.getenv("SCIM_DEFAULT_PAGE_SIZE", "100")), SCIM_MAX_PAGE_SIZE))

    PAC_SCHEMA_OWNER = os.getenv("PAC_SCHEMA_OWNER", "PACCLPR")
    PAC_DEFAULT_CORR_COD = int(os.getenv("PAC_DEFAULT_CORR_COD", "601"))
    PAC_DEFAULT_SUC = os.getenv("PAC_DEFAULT_SUC", "000000")
    PAC_DEFAULT_PAIS = os.getenv("PAC_DEFAULT_PAIS", "cl")
    PAC_DEFAULT_ROLE_CODE_IF_UNMAPPED = int(os.getenv("PAC_DEFAULT_ROLE_CODE_IF_UNMAPPED", "4"))

    # Contraseñas genéricas disponibles (texto plano → hash)
    PAC_DEFAULT_PASSWORD_HASH = os.getenv(
        "PAC_DEFAULT_PASSWORD_HASH",
        "oNQnP7E2v3OZs+xUoiJugQ==",   # texto plano: R2FdDWgVnt
    )

    PAC_ROLES = {
        1:   {"code": 1,   "name": "Admin. CMR"},
        2:   {"code": 2,   "name": "Reportes"},
        4:   {"code": 4,   "name": "Consulta"},
        24:  {"code": 24,  "name": "GERENTE CMR"},
        25:  {"code": 25,  "name": "RR.CC. con FE/VT"},
        26:  {"code": 26,  "name": "Jefe y Supervisor"},
        27:  {"code": 27,  "name": "Gerente Zonal"},
        28:  {"code": 28,  "name": "Administrador Usuarios"},
        64:  {"code": 64,  "name": "Admin. PAC"},
        187: {"code": 187, "name": "Backoffice Copro"},
        200: {"code": 200, "name": "RR.CC. por Contingencia"},
        201: {"code": 201, "name": "RR.CC. sin FE/VT AUTENTIA"},
        207: {"code": 207, "name": "FALABELLA CONNECT"},
        227: {"code": 227, "name": "RR.CC. sin FE/VT TOC"},
        307: {"code": 307, "name": "RRCC Firma Electronica - Convivencia TOC Autentia"},
    }

    # Mapeo title/cargo → código de rol
    PAC_TITLE_ROLE_MAP = {
        # Sucursal
        "agente": 26,
        "ejecutivo(a) integral": 25,
        "gerente de sucursales": 27,
        "gerente zonal": 27,
        "supervisor (a) de sucursal": 26,
        # Contact Center
        "ejecutivo de atención de canales digitales": 201,
        "ejecutivo(a) banca telefonica": 201,
        "supervisor atencion canales digitales": 26,
        "supervisor banca telefonica": 26,
        "supervisor sac": 26,
    }