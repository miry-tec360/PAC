from __future__ import annotations

import time
from typing import Any, Dict

from flask import Flask, g, jsonify, request

from pac_config import Config
from db_pac import PacOracleRepo
from logger_config import get_logger, safe_json, sanitize_headers
from pac_schema import (
    SCIM_ERROR, SCIM_LIST_RESPONSE,
    resource_types, role_to_scim, schemas,
    service_provider_config, user_to_scim,
)

app = Flask(__name__)
repo = PacOracleRepo()
LOGGER = get_logger("pac_app")


def parse_pagination():
    try:
        start_index = int(request.args.get("startIndex", 1))
        count = int(request.args.get("count", Config.SCIM_DEFAULT_PAGE_SIZE))
    except Exception:
        start_index, count = 1, Config.SCIM_DEFAULT_PAGE_SIZE
    return max(1, start_index), min(max(1, count), Config.SCIM_MAX_PAGE_SIZE)


def parse_filter(filter_expr: str):
    try:
        parts = filter_expr.split(" eq ")
        if len(parts) != 2:
            return None, None
        return parts[0].strip(), parts[1].strip().strip('"')
    except Exception:
        return None, None


def list_response(resources, total, start_index, count):
    payload = {
        "schemas": [SCIM_LIST_RESPONSE],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": len(resources),
        "Resources": resources,
    }
    return jsonify(payload)


def scim_error(detail, status=400, scimType=None):
    err = {"schemas": [SCIM_ERROR], "detail": detail, "status": str(status)}
    if scimType:
        err["scimType"] = scimType
    log_level = LOGGER.error if status >= 500 else LOGGER.warning
    log_level("SCIM_ERROR | status=%s | detail=%s", status, detail)
    return jsonify(err), status


def _error(message: str, status_code: int):
    payload = {"schemas": [SCIM_ERROR], "detail": message, "status": str(status_code)}
    log_level = LOGGER.error if status_code >= 500 else LOGGER.warning
    log_level("ERROR_RESPONSE | status=%s | detail=%s", status_code, message)
    return jsonify(payload), status_code


def _extract_primary_role(payload: Dict[str, Any]) -> str:
    roles = payload.get("roles") or []
    if not roles:
        return ""
    primary = next((r for r in roles if r.get("primary") is True), None)
    selected = primary or roles[0]
    return str(selected.get("value") or "").strip()


def _extract_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    extension = payload.get(Config.CUSTOM_SCHEMA) or {}
    name = payload.get("name") or {}
    emails = payload.get("emails") or []
    email = next((e["value"] for e in emails if e.get("primary")), "")
    if not email and emails:
        email = emails[0].get("value", "")

    # Rol: roles[] tiene precedencia sobre codigoRol del custom schema
    role_from_roles = _extract_primary_role(payload)
    role_from_schema = str(extension.get("codigoRol") or "").strip()
    codigo_rol = role_from_roles or role_from_schema

    data = {
        "userName": str(payload.get("userName") or "").strip(),
        "externalId": str(payload.get("externalId") or "").strip(),
        "firstName": str(name.get("givenName") or "").strip(),
        "lastName": str(name.get("familyName") or "").strip(),
        "title": str(payload.get("title") or "").strip(),
        "email": email,
        "active": bool(payload.get("active", True)),
        "custom": {
            "rutSinDv": str(extension.get("rutSinDv") or "").strip(),
            "dv": str(extension.get("dv") or "").strip(),
            "codigoRol": codigo_rol,
            "userchangepwd": bool(extension.get("userchangepwd", False)),
        },
    }
    LOGGER.info(
        "PAYLOAD_NORMALIZED | input=%s | normalized=%s | role_source=%s",
        safe_json(payload), safe_json(data),
        "roles[]" if role_from_roles else "codigoRol",
    )
    return data


@app.before_request
def _log_request():
    g.start_time = time.time()
    request_id = request.headers.get("X-Request-Id") or f"req-{int(g.start_time * 1000)}"
    g.request_id = request_id
    raw_body = request.get_data(cache=True, as_text=True)
    json_body = request.get_json(silent=True)
    body_for_log = json_body if json_body is not None else (raw_body or None)
    LOGGER.info(
        "REQUEST_IN | request_id=%s | method=%s | path=%s | remote_addr=%s | headers=%s | body=%s",
        request_id, request.method, request.path, request.remote_addr,
        safe_json(sanitize_headers(dict(request.headers))), safe_json(body_for_log),
    )


@app.before_request
def _require_token():
    if request.path in {"/healthz", "/"}:
        return None
    auth = request.headers.get("Authorization", "")
    if not Config.BEARER_TOKEN:
        return _error("SCIM_BEARER_TOKEN no configurado.", 500)
    if auth != f"Bearer {Config.BEARER_TOKEN}":
        return _error("Unauthorized", 401)
    return None


@app.after_request
def _log_response(response):
    duration_ms = round((time.time() - getattr(g, "start_time", time.time())) * 1000, 2)
    LOGGER.info(
        "RESPONSE_OUT | request_id=%s | status=%s | duration_ms=%s | body=%s",
        getattr(g, "request_id", "n/a"), response.status_code, duration_ms,
        response.get_data(as_text=True),
    )
    return response


@app.get("/")
def root():
    return jsonify({"service": "PAC SCIM 2.0", "status": "ok"})


@app.get("/healthz")
def healthz():
    try:
        return jsonify({"ok": repo.healthcheck()})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503


@app.get("/scim/v2/ServiceProviderConfig")
def get_spc():
    return jsonify(service_provider_config())


@app.get("/scim/v2/ResourceTypes")
def get_resource_types():
    data = resource_types()
    return jsonify({"Resources": data, "totalResults": len(data),
                    "itemsPerPage": len(data), "startIndex": 1,
                    "schemas": [SCIM_LIST_RESPONSE]})


@app.get("/scim/v2/Schemas")
def get_schemas():
    data = schemas()
    return jsonify({"Resources": data, "totalResults": len(data),
                    "itemsPerPage": len(data), "startIndex": 1,
                    "schemas": [SCIM_LIST_RESPONSE]})


@app.get("/scim/v2/Groups")
def list_groups():
    payload = {
        "schemas": [SCIM_LIST_RESPONSE],
        "totalResults": 0,
        "startIndex": 1,
        "itemsPerPage": 0,
        "Resources": [],
    }
    return jsonify(payload)


@app.get("/scim/v2/Roles")
def list_roles():
    try:
        start_index, count = parse_pagination()
        filter_expr = request.args.get("filter", "").strip()
        if filter_expr:
            attr, value = parse_filter(filter_expr)
            if attr == "id":
                role = repo.get_role(value)
                resources = [role_to_scim(role, Config.BASE_URL)] if role else []
                return list_response(resources, len(resources), 1, len(resources))
            return scim_error("Filtro no soportado para Roles.", 400, "invalidFilter")
        rows, total = repo.list_roles(start_index, count)
        return list_response([role_to_scim(r, Config.BASE_URL) for r in rows], total, start_index, count)
    except Exception as exc:
        LOGGER.exception("Error en GET /Roles")
        return scim_error(str(exc), 500)


@app.get("/scim/v2/Roles/<role_id>")
def get_role(role_id: str):
    role = repo.get_role(role_id)
    if not role:
        return _error("Role not found", 404)
    return jsonify(role_to_scim(role, Config.BASE_URL))


@app.get("/scim/v2/Users")
def list_users():
    try:
        start_index, count = parse_pagination()
        filter_expr = request.args.get("filter", "").strip()
        filter_attr, filter_value = (parse_filter(filter_expr) if filter_expr else (None, None))
        rows, total = repo.list_users(start_index=start_index, count=count,
                                      filter_attr=filter_attr, filter_value=filter_value)
        resources = [user_to_scim(r, Config.BASE_URL) for r in rows]
        return list_response(resources, total if not filter_expr else len(resources), start_index, count)
    except ValueError as exc:
        return scim_error(str(exc), 400, "invalidFilter")
    except Exception as exc:
        LOGGER.exception("Error en GET /Users")
        return scim_error(str(exc), 500)


@app.get("/scim/v2/Users/<user_id>")
def get_user(user_id: str):
    user = repo.get_user(user_id)
    if not user:
        return _error("User not found", 404)
    return jsonify(user_to_scim(user, Config.BASE_URL))


@app.post("/scim/v2/Users")
def create_user():
    payload = request.get_json(force=True, silent=False) or {}
    data = _extract_payload(payload)
    try:
        user = repo.upsert_user(data)
        return jsonify(user_to_scim(user, Config.BASE_URL)), 201
    except ValueError as exc:
        return _error(str(exc), 400)
    except Exception as exc:
        LOGGER.exception("USER_CREATE_ERROR")
        return _error(str(exc), 500)


@app.put("/scim/v2/Users/<user_id>")
def replace_user(user_id: str):
    payload = request.get_json(force=True, silent=False) or {}
    data = _extract_payload(payload)
    data["userName"] = data.get("userName") or user_id
    try:
        user = repo.upsert_user(data)
        return jsonify(user_to_scim(user, Config.BASE_URL))
    except ValueError as exc:
        return _error(str(exc), 400)
    except Exception as exc:
        LOGGER.exception("USER_REPLACE_ERROR")
        return _error(str(exc), 500)


@app.delete("/scim/v2/Users/<user_id>")
def delete_user(user_id: str):
    try:
        repo.deactivate_user(user_id)
        return "", 204
    except ValueError as exc:
        return _error(str(exc), 404)
    except Exception as exc:
        LOGGER.exception("USER_DELETE_ERROR")
        return _error(str(exc), 500)


if __name__ == "__main__":
    LOGGER.info("PAC_APP_START | host=%s | port=%s | base_url=%s", Config.HOST, Config.PORT, Config.BASE_URL)
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.SCIM_DEBUG)