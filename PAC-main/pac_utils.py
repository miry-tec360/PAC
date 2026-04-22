from __future__ import annotations

import re
from typing import Optional, Union, Any, Dict, List, Tuple

from stdnum.cl import rut as std_rut

from pac_config import Config


def compact_spaces(value: str | None) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip())


def normalize_upper(value: str | None) -> str:
    return compact_spaces(value).upper()


def _calc_dv(rut_digits: str) -> str:
    reversed_digits = list(reversed(rut_digits))
    factors = [2, 3, 4, 5, 6, 7, 2, 3]
    total = sum(int(d) * f for d, f in zip(reversed_digits, factors))
    remainder = 11 - (total % 11)
    if remainder == 11:
        return "0"
    if remainder == 10:
        return "K"
    return str(remainder)


def validate_rut_dv(rut_str: str) -> Tuple[str, str]:
    """
    Acepta RUT con o sin DV.
    - Sin DV (solo dígitos): calcula el DV automáticamente.
    - Con DV (ej: 20905343-8 o 209053438): valida con python-stdnum.
    Retorna (rut_sin_dv, dv).
    """
    if not rut_str or not isinstance(rut_str, str):
        raise ValueError(f"RUT inválido: '{rut_str}'")

    cleaned = rut_str.strip().replace(".", "").replace(" ", "")

    if cleaned.isdigit():
        dv = _calc_dv(cleaned)
        return cleaned, dv

    try:
        compact = std_rut.compact(cleaned)
        validated = std_rut.validate(compact)
    except Exception as exc:
        raise ValueError(f"RUT inválido o DV incorrecto: '{rut_str}'") from exc

    rut = validated[:-1]
    dv = validated[-1].upper()
    return rut, dv


def build_login(rut_str: str) -> str:
    """
    Construye el A_LOGIN_USR (RUT+DV sin guion).
    Ej: '20905343-8' → '209053438'
        '20905343'   → '209053438' (calcula DV)
    """
    rut, dv = validate_rut_dv(rut_str)
    return f"{rut}{dv}"


def normalize_title(title: str | None) -> str:
    return compact_spaces(title).lower()


def role_code_from_title(title: str | None) -> int:
    normalized = normalize_title(title)
    if not normalized:
        return Config.PAC_DEFAULT_ROLE_CODE_IF_UNMAPPED
    return Config.PAC_TITLE_ROLE_MAP.get(normalized, Config.PAC_DEFAULT_ROLE_CODE_IF_UNMAPPED)


def role_record_from_code(code: int | str | None) -> Dict[str, Any]:
    try:
        key = int(code or 0)
    except (ValueError, TypeError):
        key = 0
    return Config.PAC_ROLES.get(key) or Config.PAC_ROLES[Config.PAC_DEFAULT_ROLE_CODE_IF_UNMAPPED]


def build_nombre_usr(first_name: str | None, last_name: str | None) -> str:
    """
    A_NOMBRE_USR = firstName + " " + lastName en mayúsculas.
    Ej: 'JOHANN VALENZUELA GARRIDO'
    """
    parts = [normalize_upper(first_name), normalize_upper(last_name)]
    return " ".join(p for p in parts if p)