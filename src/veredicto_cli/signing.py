"""Firma criptográfica (ed25519) de los certificados de VEREDICTO.

Dos capas de integridad, no confundirlas:

  1. Hash encadenado (`certificate_sha256`): SHA-256 del JSON canónico del
     certificado. Detecta alteraciones, pero no identifica a nadie:
     cualquiera puede regenerarlo.
  2. Firma ed25519 (este módulo, opcional): el emisor firma con su clave
     privada el mismo payload canónico. El certificado incluye la clave
     pública y su huella (SHA-256 de los 32 bytes crudos de la clave).
     La firma prueba que el certificado lo emitió el poseedor de esa
     clave privada y que el contenido no se alteró desde la firma.

Modelo de confianza honesto: verificar contra la clave pública *incluida*
en el certificado prueba integridad + posesión de la clave, pero NO que
la clave pertenezca a quien dice ser — un atacante puede firmar con SU
propia clave y la verificación contra la clave incluida pasará. Por eso
`verify` muestra la huella y acepta `--pubkey`: el tercero debe
contrastar la huella (o la clave) por un canal de confianza.

La librería `cryptography` es una dependencia OPCIONAL (extra `sign`).
Sin ella el CLI funciona como antes: certificados con hash encadenado y
`signature.status == "unsigned"`. Nunca se degrada en silencio: si se
pide firmar (con `--key` o `VEREDICTO_KEY`) y no se puede, es un error.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

ALGORITHM = "ed25519"
STATUS_SIGNED = "signed"
STATUS_UNSIGNED = "unsigned"

# Campos que no forman parte del payload canónico: el propio hash
# encadenado y el bloque de firma. Excluir `signature` hace que añadir o
# quitar la firma no cambie el hash encadenado (capas independientes).
_EXCLUDED = ("certificate_sha256", "signature")

PRIVATE_KEY_FILENAME = "veredicto-private.pem"
PUBLIC_KEY_FILENAME = "veredicto-public.pem"
ENV_KEY_VAR = "VEREDICTO_KEY"


class SigningError(Exception):
    """No se pudo firmar/verificar por configuración o entorno."""


# ---------------------------------------------------------------------------
# Canonicalización (fuente única: la usan el hash encadenado y la firma)
# ---------------------------------------------------------------------------

def canonical_payload(cert: dict) -> bytes:
    """JSON canónico del certificado sin los campos de integridad/firma."""
    payload = {k: v for k, v in cert.items() if k not in _EXCLUDED}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def chain_hash(cert: dict) -> str:
    return hashlib.sha256(canonical_payload(cert)).hexdigest()


# ---------------------------------------------------------------------------
# Disponibilidad de la librería
# ---------------------------------------------------------------------------

def _load_cryptography():
    try:
        import cryptography  # noqa: F401
    except ImportError as exc:
        raise SigningError(
            "la librería 'cryptography' no está instalada: la firma es "
            "opcional y se instala con  pip install \"veredicto-cli[sign]\""
        ) from exc
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.hazmat.primitives import serialization
    return Ed25519PrivateKey, Ed25519PublicKey, serialization


def signing_available() -> bool:
    try:
        _load_cryptography()
    except SigningError:
        return False
    return True


# ---------------------------------------------------------------------------
# Claves: generación, guardado, carga
# ---------------------------------------------------------------------------

def public_key_fingerprint(raw_public: bytes) -> str:
    """Huella de una clave pública ed25519: SHA-256 de sus 32 bytes crudos."""
    return hashlib.sha256(raw_public).hexdigest()


def _raw_public_bytes(public_key, serialization) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def generate_keypair() -> Tuple[bytes, bytes, str]:
    """Genera un par ed25519: (PEM privado PKCS8, PEM público, huella)."""
    Ed25519PrivateKey, _Pub, serialization = _load_cryptography()
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = public_key_fingerprint(
        _raw_public_bytes(private_key.public_key(), serialization))
    return private_pem, public_pem, fingerprint


def write_keypair(out_dir) -> Tuple[Path, Path, str]:
    """Escribe el par de claves en `out_dir`.

    La privada nace con permisos 0600 y NUNCA se imprime. Si ya existe
    una privada en el destino, se rechaza (no destruir una identidad
    existente por accidente).
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    private_pem, public_pem, fingerprint = generate_keypair()
    priv_path = out / PRIVATE_KEY_FILENAME
    pub_path = out / PUBLIC_KEY_FILENAME
    try:
        fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise SigningError(
            f"ya existe una clave privada en {priv_path}: no se sobrescribe "
            "(borrarla a mano si de verdad se quiere una identidad nueva)"
        ) from exc
    with os.fdopen(fd, "wb") as fh:
        fh.write(private_pem)
    os.chmod(priv_path, 0o600)
    pub_path.write_bytes(public_pem)
    return priv_path, pub_path, fingerprint


def load_private_key(path):
    """Carga una clave privada ed25519 desde un PEM. SigningError si no."""
    Ed25519PrivateKey, _Pub, serialization = _load_cryptography()
    p = Path(path)
    if not p.is_file():
        raise SigningError(f"clave privada no encontrada: {p}")
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise SigningError(f"no se pudo leer la clave privada {p}: {exc}") from exc
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise SigningError(
            f"la clave privada {p} no es un PEM válido (o lleva contraseña, "
            f"que no se soporta): {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningError(f"la clave privada {p} no es ed25519")
    return key


def _public_key_from_pem(pem: bytes):
    _Priv, Ed25519PublicKey, serialization = _load_cryptography()
    try:
        key = serialization.load_pem_public_key(pem)
    except ValueError as exc:
        raise SigningError(f"la clave pública no es un PEM válido: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SigningError("la clave pública no es ed25519")
    return key


def resolve_key_path(explicit=None) -> Optional[str]:
    """Ruta de la clave privada: --key explícita o $VEREDICTO_KEY."""
    if explicit:
        return str(explicit)
    env = os.environ.get(ENV_KEY_VAR)
    return env if env else None


# ---------------------------------------------------------------------------
# Firmar y verificar certificados
# ---------------------------------------------------------------------------

def sign_block(cert: dict, private_key) -> dict:
    """Bloque `signature` para `cert`, firmando su payload canónico."""
    _Priv, _Pub, serialization = _load_cryptography()
    public_key = private_key.public_key()
    raw_public = _raw_public_bytes(public_key, serialization)
    signature = private_key.sign(canonical_payload(cert))
    return {
        "status": STATUS_SIGNED,
        "algorithm": ALGORITHM,
        "public_key": base64.b64encode(raw_public).decode("ascii"),
        "public_key_fingerprint": public_key_fingerprint(raw_public),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def unsigned_block() -> dict:
    return {"status": STATUS_UNSIGNED}


@dataclass
class VerifyResult:
    status: str            # "valid" | "invalid" | "unsigned" | "unverifiable"
    detail: str
    fingerprint: Optional[str] = None


def verify_certificate(cert: dict,
                       expected_public_pem: Optional[bytes] = None
                       ) -> VerifyResult:
    """Verifica la firma de un certificado.

    Orden de chequeos (fail-closed, el primer fallo manda):
      1. ¿Lleva bloque de firma firmado? Si no → "unsigned".
      2. Hash encadenado intacto (si no, el contenido cambió tras emitir).
      3. La huella declarada coincide con la clave pública incluida.
      4. Si se da una clave pública de confianza (`expected_public_pem`),
         la incluida debe ser ESA (es lo que ata la firma a una identidad).
      5. La firma ed25519 valida sobre el payload canónico.
    """
    sig = cert.get("signature")
    if not isinstance(sig, dict) or sig.get("status") != STATUS_SIGNED:
        return VerifyResult(
            "unsigned",
            "el certificado no lleva firma: solo tiene el hash encadenado "
            "de integridad, sin identidad del emisor")
    if cert.get("certificate_sha256") != chain_hash(cert):
        return VerifyResult(
            "invalid",
            "el hash encadenado no coincide: el contenido del certificado "
            "fue alterado después de emitirse")
    if not signing_available():
        return VerifyResult(
            "unverifiable",
            "el certificado está firmado pero falta la librería "
            "'cryptography' para comprobar la firma: "
            "pip install \"veredicto-cli[sign]\"")
    _Priv, Ed25519PublicKey, _ser = _load_cryptography()
    try:
        raw_public = base64.b64decode(sig["public_key"], validate=True)
        signature = base64.b64decode(sig["signature"], validate=True)
    except (KeyError, ValueError) as exc:
        return VerifyResult(
            "invalid", f"bloque de firma mal formado (base64): {exc}")
    fingerprint = public_key_fingerprint(raw_public)
    if sig.get("public_key_fingerprint") != fingerprint:
        return VerifyResult(
            "invalid",
            "la huella declarada no coincide con la clave pública incluida")
    if sig.get("algorithm") != ALGORITHM:
        return VerifyResult(
            "invalid", f"algoritmo de firma no soportado: {sig.get('algorithm')}")
    if expected_public_pem is not None:
        try:
            expected_key = _public_key_from_pem(expected_public_pem)
        except SigningError as exc:
            return VerifyResult("unverifiable", str(exc))
        _P, _U, ser2 = _load_cryptography()
        if _raw_public_bytes(expected_key, ser2) != raw_public:
            return VerifyResult(
                "invalid",
                "la clave pública incluida NO es la clave de confianza "
                "indicada: la firma puede ser válida, pero no de ese emisor",
                fingerprint)
    try:
        public_key = Ed25519PublicKey.from_public_bytes(raw_public)
    except ValueError as exc:
        return VerifyResult(
            "invalid", f"clave pública ed25519 no válida: {exc}", fingerprint)
    from cryptography.exceptions import InvalidSignature
    try:
        public_key.verify(signature, canonical_payload(cert))
    except InvalidSignature:
        return VerifyResult(
            "invalid",
            "la firma ed25519 no valida sobre el contenido: el certificado "
            "fue alterado tras firmarse (o no lo firmó esa clave)",
            fingerprint)
    return VerifyResult(
        "valid",
        "firma ed25519 válida: el contenido no se alteró desde la firma "
        "y lo firmó el poseedor de la clave privada de esta pública",
        fingerprint)
