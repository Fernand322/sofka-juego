// Netlify Function: /api/validate  (vía redirect en netlify.toml)
// Node 18 por defecto en Netlify (ok)

const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

let CATALOG = null; // cache en memoria (por instancia)

function loadCatalog() {
    if (CATALOG) return CATALOG;
    const file = path.join(__dirname, "candles.json");
    CATALOG = JSON.parse(fs.readFileSync(file, "utf8"));
    return CATALOG;
}

// Normaliza texto: sin acentos, trim y minúsculas
function normalize(s = "") {
    return s
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .replace(/\s+/g, " ")
        .trim()
        .toLowerCase();
}

// Firma opcional (HMAC) para endurecer IDs en QR (puede activarse más adelante)
function verifySig(id, sig, secret) {
    if (!secret) return true; // si no configuraste secreto, no exigimos firma
    if (!id || !sig) return false;
    const h = crypto.createHmac("sha256", secret).update(id).digest("hex");
    return crypto.timingSafeEqual(Buffer.from(h), Buffer.from(sig));
}

function genCode(id) {
    const rand = Math.random().toString(36).slice(2, 8).toUpperCase();
    return `SOFKA-${id}-${rand}`;
}

exports.handler = async (event) => {
    // CORS básico (si el front está en el mismo dominio, podés omitir)
    const headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };
    if (event.httpMethod === "OPTIONS") {
        return { statusCode: 200, headers, body: "" };
    }

    if (event.httpMethod !== "POST") {
        return {
            statusCode: 405,
            headers,
            body: JSON.stringify({ error: "Only POST" }),
        };
    }

    try {
        const SECRET = process.env.SOFKA_SECRET || ""; // opcional por ahora
        const body = JSON.parse(event.body || "{}");
        const { id, guess, sig } = body;

        if (!id || !guess) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: "Faltan parámetros: id, guess" }),
            };
        }

        if (!verifySig(id, sig, SECRET)) {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ error: "Firma inválida" }),
            };
        }

        const catalog = loadCatalog();
        const record = catalog[id];
        if (!record) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ error: "ID no registrado" }),
            };
        }

        const g = normalize(guess);
        const target = normalize(record.aroma);
        let ok = g === target;

        if (!ok && Array.isArray(record.synonyms)) {
            ok = record.synonyms.map(normalize).includes(g);
        }

        if (!ok) {
            return {
                statusCode: 200,
                headers,
                body: JSON.stringify({ ok: false }),
            };
        }

        // Ganó → generamos código (almacenamiento: por ahora, sólo devolución al cliente)
        const code = genCode(id);
        const days = record.validDays || 7;
        const expiresAt = Date.now() + days * 24 * 60 * 60 * 1000;

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                ok: true,
                discount: record.discount || 10,
                code,
                expiresAt,
            }),
        };
    } catch (e) {
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ error: "Error interno", detail: e.message }),
        };
    }
};
