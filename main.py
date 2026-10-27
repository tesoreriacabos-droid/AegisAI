"""
AI-SHIELD PRODUCTION API (Render Deployment Ready)
SaaS Web API for Autonomous AI Swarm Defense and Adaptive Security.
"""

import os
import sqlite3
import re
import datetime
import math
import secrets
from typing import Dict, Tuple, List, Optional
from fastapi import FastAPI, Depends, HTTPException, Security, Status, Request
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

# Database location (Render Persistent Disk or local volume)
DB_PATH = os.getenv("DATABASE_PATH", "ai_security_audit.db")
ADMIN_MASTER_KEY = os.getenv("ADMIN_MASTER_KEY", "shield-admin-secret-key-2026")

# Security Header Configuration
API_KEY_HEADER = APIKeyHeader(name="X-API-KEY", auto_error=False)

app = FastAPI(
    title="AI-SHIELD Security Engine API",
    description="Production-grade adaptive security, PHP/RCE defense, and AI Swarm mitigation middleware.",
    version="2.5.0"
)


# --- DATABASE INITIALIZATION & MANAGEMENT ---

class AISecurityDatabase:
    """Handles persistence, tenant management, audit logging, and dynamic rule learning."""

    @staticmethod
    def initialize_db():
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            
            # API Tenant Management (SaaS Billing/Access)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_clients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_name TEXT NOT NULL,
                    api_key TEXT UNIQUE NOT NULL,
                    tier TEXT DEFAULT 'PRO',
                    active INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL
                )
            """)

            # Threat Audit Registry
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS registro_ataques (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip_origen TEXT DEFAULT '127.0.0.1',
                    client_key TEXT NOT NULL,
                    prompt_original TEXT NOT NULL,
                    amenazas_detectadas TEXT NOT NULL,
                    nivel_riesgo TEXT NOT NULL,
                    accion_defensiva TEXT NOT NULL
                )
            """)
            
            # Swarm Intelligence Reputation Tracker
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS control_agentes_swarm (
                    ip_origen TEXT PRIMARY KEY,
                    intentos_maliciosos INTEGER DEFAULT 1,
                    ultimo_intento TEXT NOT NULL,
                    score_reputacion REAL DEFAULT 100.0,
                    estado TEXT DEFAULT 'MONITOREADO'
                )
            """)

            # Dynamically Synthesized Rules
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS firmas_dinamicas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    categoria TEXT NOT NULL,
                    patron_regex TEXT NOT NULL,
                    fecha_creacion TEXT NOT NULL
                )
            """)
            conn.commit()

    @staticmethod
    def validate_api_key(api_key: str) -> Optional[Dict]:
        if not api_key:
            return None
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT client_name, tier, active FROM api_clients WHERE api_key = ?", (api_key,))
            row = cursor.fetchone()
            if row and row[2] == 1:
                return {"client_name": row[0], "tier": row[1]}
        return None

    @staticmethod
    def register_client(client_name: str, tier: str = "PRO") -> str:
        new_key = f"aishield_live_{secrets.token_hex(16)}"
        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO api_clients (client_name, api_key, tier, created_at)
                VALUES (?, ?, ?, ?)
            """, (client_name, new_key, tier, created_at))
            conn.commit()
        return new_key

    @staticmethod
    def log_attack(ip_origen: str, client_key: str, prompt: str, amenazas: List[str], riesgo: str, accion: str):
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        amenazas_str = ", ".join(amenazas)
        
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO registro_ataques (timestamp, ip_origen, client_key, prompt_original, amenazas_detectadas, nivel_riesgo, accion_defensiva)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, ip_origen, client_key, prompt, amenazas_str, riesgo, accion))
            
            cursor.execute("SELECT intentos_maliciosos, score_reputacion FROM control_agentes_swarm WHERE ip_origen = ?", (ip_origen,))
            row = cursor.fetchone()
            
            penalty = 45.0 if "CRÍTICO" in riesgo else 20.0
            
            if row:
                intentos = row[0] + 1
                new_score = max(0.0, row[1] - penalty)
                status = "BLOQUEADO_PERMANENTE" if new_score <= 10.0 or intentos >= 4 else "MONITOREADO"
                cursor.execute("""
                    UPDATE control_agentes_swarm 
                    SET intentos_maliciosos = ?, ultimo_intento = ?, score_reputacion = ?, estado = ?
                    WHERE ip_origen = ?
                """, (intentos, timestamp, new_score, status, ip_origen))
            else:
                new_score = max(0.0, 100.0 - penalty)
                cursor.execute("""
                    INSERT INTO control_agentes_swarm (ip_origen, intentos_maliciosos, ultimo_intento, score_reputacion, estado)
                    VALUES (?, 1, ?, ?, 'MONITOREADO')
                """, (ip_origen, timestamp, new_score))
            conn.commit()

    @staticmethod
    def is_ip_blocked(ip_origen: str) -> bool:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT estado, score_reputacion FROM control_agentes_swarm WHERE ip_origen = ?", (ip_origen,))
            row = cursor.fetchone()
            if row:
                return row[0] == 'BLOQUEADO_PERMANENTE' or row[1] <= 10.0
        return False

    @staticmethod
    def save_dynamic_rule(categoria: str, patron_regex: str):
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO firmas_dinamicas (categoria, patron_regex, fecha_creacion) VALUES (?, ?, ?)",
                           (categoria, patron_regex, timestamp))
            conn.commit()

    @staticmethod
    def load_dynamic_rules() -> List[Tuple[str, str]]:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT categoria, patron_regex FROM firmas_dinamicas")
            return cursor.fetchall()


# --- ENGINE & ADAPTIVE MODULES ---

class AdaptiveLearningModule:
    @staticmethod
    def calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        frequencies = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1
        entropy = 0.0
        for count in frequencies.values():
            p = count / len(text)
            entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def inspect_payload(cls, prompt: str) -> Tuple[bool, str, str]:
        entropy = cls.calculate_entropy(prompt)
        if entropy > 4.85 and len(prompt) > 30:
            tokens = re.findall(r'[A-Za-z0-9+/=]{10,}', prompt)
            if tokens:
                return True, "ADAPTIVE_OBFUSCATION", re.escape(tokens[0][:12])
        return False, "", ""


class AIDefenseEngine:
    PATRONES_ESTATICOS = {
        "PROMPT_INJECTION": [
            r"ignore previous instructions",
            r"olvida tus instrucciones anteriores",
            r"system prompt",
            r"actúa como un hacker",
            r"bypass safety"
        ],
        "CODE_INJECTION": [
            r"rm -rf", r"drop table", r"exec\(", r"eval\(", r"<script>", r"import os"
        ],
        "PHP_RCE_VECTORS": [
            r"\<\?php", r"system\s*\(", r"passthru\s*\(", r"shell_exec\s*\(", r"assert\s*\("
        ],
        "CVE_EXPLOITS_2026": [
            r"cve-2026-109618", r"cve-2026-109619", r"php\?cmd=", r"auto_prepend_file"
        ]
    }

    @classmethod
    def get_all_rules(cls) -> Dict[str, List[str]]:
        rules = {cat: list(pats) for cat, pats in cls.PATRONES_ESTATICOS.items()}
        for cat, patron in AISecurityDatabase.load_dynamic_rules():
            if cat not in rules:
                rules[cat] = []
            rules[cat].append(patron)
        return rules

    @classmethod
    def sanitize(cls, text: str, rules: Dict[str, List[str]]) -> str:
        clean = text
        for patterns in rules.values():
            for pat in patterns:
                try:
                    clean = re.sub(pat, "[BLOQUEADO POR AI-SHIELD]", clean, flags=re.IGNORECASE)
                except re.error:
                    continue
        return clean

    @classmethod
    def process_request(cls, ip_origen: str, client_key: str, prompt: str) -> Tuple[bool, str, Dict]:
        if AISecurityDatabase.is_ip_blocked(ip_origen):
            return False, "[ACCESO DENEGADO: IP BLOQUEADA POR ENJAMBRE MALICIOSO]", {
                "blocked": True,
                "risk": "CRÍTICO",
                "threats": ["SWARM_IP_BLACKLISTED"]
            }

        detected_threats = []
        rules = cls.get_all_rules()
        lower_prompt = prompt.lower()

        for category, patterns in rules.items():
            for pat in patterns:
                try:
                    if re.search(pat, lower_prompt):
                        detected_threats.append(f"{category}:{pat}")
                except re.error:
                    continue

        is_anomalous, cat_anomalous, new_pattern = AdaptiveLearningModule.inspect_payload(prompt)
        if is_anomalous:
            detected_threats.append(f"ADAPTIVE_ENGINE:{cat_anomalous}")
            AISecurityDatabase.save_dynamic_rule(cat_anomalous, new_pattern)

        is_safe = len(detected_threats) == 0

        if not is_safe:
            is_critical = any(c in t for t in detected_threats for c in ["PHP_RCE", "CVE", "CODE", "ADAPTIVE"])
            risk_level = "CRÍTICO" if is_critical else "ALTO"
            action = "NEUTRALIZED_AND_LOGGED"

            AISecurityDatabase.log_attack(ip_origen, client_key, prompt, detected_threats, risk_level, action)
            sanitized_prompt = cls.sanitize(prompt, cls.get_all_rules())

            return False, sanitized_prompt, {
                "blocked": True,
                "risk": risk_level,
                "threats": detected_threats
            }

        return True, prompt, {"blocked": False, "risk": "NONE", "threats": []}


# --- API SCHEMAS ---

class InspectRequest(BaseModel):
    prompt: str = Field(..., example="Calcula la ruta logistica optima entre San Jose del Cabo y La Paz.")
    source_ip: Optional[str] = Field("127.0.0.1", example="192.168.1.100")

class InspectResponse(BaseModel):
    is_safe: bool
    sanitized_prompt: str
    report: Dict

class RegisterClientRequest(BaseModel):
    admin_key: str
    client_name: str
    tier: Optional[str] = "PRO"


# --- AUTHENTICATION DEPENDENCY ---

async def verify_api_key(api_key: str = Security(API_KEY_HEADER)):
    if not api_key:
        raise HTTPException(
            status_code=Status.HTTP_401_UNAUTHORIZED,
            detail="API Key missing in 'X-API-KEY' header."
        )
    client_data = AISecurityDatabase.validate_api_key(api_key)
    if not client_data:
        raise HTTPException(
            status_code=Status.HTTP_403_FORBIDDEN,
            detail="Invalid or inactive API Key."
        )
    return {"api_key": api_key, **client_data}


# --- API ENDPOINTS ---

@app.on_event("startup")
def startup_event():
    AISecurityDatabase.initialize_db()


@app.get("/")
def health_check():
    return {
        "status": "online",
        "service": "AI-SHIELD Adaptive Security Engine",
        "version": "2.5.0",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


@app.post("/v1/inspect", response_model=InspectResponse)
def inspect_payload_endpoint(
    payload: InspectRequest,
    request: Request,
    auth: dict = Depends(verify_api_key)
):
    ip_to_check = payload.source_ip if payload.source_ip != "127.0.0.1" else request.client.host
    is_safe, sanitized, report = AIDefenseEngine.process_request(
        ip_origen=ip_to_check,
        client_key=auth["api_key"],
        prompt=payload.prompt
    )
    return {
        "is_safe": is_safe,
        "sanitized_prompt": sanitized,
        "report": report
    }


@app.post("/v1/admin/create-client")
def create_client_endpoint(payload: RegisterClientRequest):
    if payload.admin_key != ADMIN_MASTER_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized Admin Master Key.")
    
    generated_key = AISecurityDatabase.register_client(payload.client_name, payload.tier)
    return {
        "status": "success",
        "client_name": payload.client_name,
        "api_key": generated_key,
        "tier": payload.tier
    }