const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const logAudit = require('./auditHelper');
const crypto = require('crypto'); // Necesario para la biometría

const router = express.Router();

// ==========================================
// RUTAS DE AUTENTICACIÓN Y SEGURIDAD
// ==========================================

router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress;

    try {
        const userResult = await pool.query('SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL', [email]);
        if (userResult.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

        const user = userResult.rows[0];

        // Control: Cuenta deshabilitada (Práctica 13)
        if (!user.is_active) {
            await logAudit(user.id, user.username, 'INTENTO_LOGIN_CUENTA_DESHABILITADA', ip);
            return res.status(403).json({ error: 'Cuenta deshabilitada. Contacte al administrador.' });
        }

        // Control: Bloqueo temporal por intentos fallidos
        if (user.locked_until && new Date(user.locked_until) > new Date()) {
            return res.status(423).json({ error: 'Cuenta bloqueada temporalmente por múltiples intentos fallidos.' });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);

        if (!validPassword) {
            const attempts = (user.failed_attempts || 0) + 1;
            let lockedUntil = null;
            if (attempts >= 5) {
                lockedUntil = new Date(Date.now() + 15 * 60000); // 15 min de bloqueo
                await logAudit(user.id, user.username, 'BLOQUEO_CUENTA_POR_INTENTOS', ip);
            }
            await pool.query('UPDATE users SET failed_attempts = $1, locked_until = $2 WHERE id = $3', [attempts, lockedUntil, user.id]);
            return res.status(401).json({ error: 'Contraseña incorrecta' });
        }

        // Éxito: Resetear intentos y actualizar "Último inicio de sesión" (Práctica 13)
        await pool.query(
            'UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = $1', 
            [user.id]
        );
        
        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET || 'supersecreto', { expiresIn: '1h' });
        await logAudit(user.id, user.username, 'INICIO_SESION_EXITOSO', ip);

        res.json({ 
            token, 
            user: { 
                id: user.id, 
                username: user.username, 
                role: user.role,
                requires_password_change: user.requires_password_change 
            } 
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// ==========================================
// MIDDLEWARE DE PRIVILEGIOS (Solo Admin)
// ==========================================
const verifyAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(403).json({ error: 'Token no proporcionado' });
    
    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET || 'supersecreto', (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Token inválido o expirado' });
        if (decoded.role !== 'admin') return res.status(403).json({ error: 'Privilegios insuficientes' });
        req.user = decoded;
        next();
    });
};

// ==========================================
// MÓDULO ADMINISTRATIVO (Prácticas 11, 12, 13)
// ==========================================

// Obtener tabla de usuarios con datos de Práctica 13
router.get('/admin/users', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT id, username, email, role, is_active, last_login, requires_password_change 
            FROM users 
            WHERE deleted_at IS NULL 
            ORDER BY id ASC
        `);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Error obteniendo usuarios' });
    }
});

// Obtener bitácora de auditoría
router.get('/admin/logs', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Error obteniendo bitácora' });
    }
});

// Asignar Roles / Grupos
router.put('/admin/users/:id/role', verifyAdmin, async (req, res) => {
    const { role } = req.body;
    const { id } = req.params;
    const ip = req.ip || req.connection.remoteAddress;

    try {
        await pool.query('UPDATE users SET role = $1 WHERE id = $2', [role, id]);
        await logAudit(req.user.id, `Admin_${req.user.id}`, `CAMBIO_GRUPO_A_${role.toUpperCase()}_USUARIO_${id}`, ip);
        res.json({ message: 'Rol actualizado' });
    } catch (error) {
        res.status(500).json({ error: 'Error actualizando rol' });
    }
});

// Habilitar / Deshabilitar cuentas
router.put('/admin/users/:id/status', verifyAdmin, async (req, res) => {
    const { is_active } = req.body;
    const { id } = req.params;
    const ip = req.ip || req.connection.remoteAddress;

    try {
        await pool.query('UPDATE users SET is_active = $1 WHERE id = $2', [is_active, id]);
        const accion = is_active ? 'HABILITO' : 'DESHABILITO';
        await logAudit(req.user.id, `Admin_${req.user.id}`, `SE_${accion}_USUARIO_${id}`, ip);
        res.json({ message: 'Estado de cuenta actualizado' });
    } catch (error) {
        res.status(500).json({ error: 'Error actualizando estado' });
    }
});

// Eliminación lógica de cuenta
router.delete('/admin/users/:id', verifyAdmin, async (req, res) => {
    const { id } = req.params;
    const ip = req.ip || req.connection.remoteAddress;

    try {
        await pool.query('UPDATE users SET deleted_at = CURRENT_TIMESTAMP, is_active = false WHERE id = $1', [id]);
        await logAudit(req.user.id, `Admin_${req.user.id}`, `ELIMINACION_LOGICA_USUARIO_${id}`, ip);
        res.json({ message: 'Usuario eliminado del sistema' });
    } catch (error) {
        res.status(500).json({ error: 'Error eliminando usuario' });
    }
});

// ==========================================
// RUTAS PARA BIOMETRÍA (WEBAUTHN - HUELLA/ROSTRO)
// ==========================================

const currentChallenges = {};

router.post('/webauthn/register/options', (req, res) => {
    const { userId, username } = req.body;

    // Detectar el dominio exacto desde donde el frontend hace la petición (Vercel o localhost)
    const origin = req.headers.origin || 'http://localhost:4200';
    const rpId = new URL(origin).hostname; 

    // Generar un desafío aleatorio criptográfico
    const challenge = crypto.randomBytes(32).toString('base64');
    currentChallenges[userId] = challenge;

    // Configurar las opciones con el RP ID exacto
    const options = {
        challenge: challenge,
        rp: {
            name: "IndieHub",
            id: rpId // ¡Soluciona el SecurityError de Vercel!
        },
        user: {
            id: userId.toString(),
            name: username,
            displayName: username
        },
        pubKeyCredParams: [
            { type: "public-key", alg: -7 },   // ES256
            { type: "public-key", alg: -257 }, // RS256
            { type: "public-key", alg: -37 }   // PS256 (Soluciona la advertencia)
        ],
        timeout: 60000,
        authenticatorSelection: {
            authenticatorAttachment: "platform", 
            userVerification: "preferred"
        },
        attestation: "none"
    };

    res.json(options);
});

router.post('/webauthn/register/verify', async (req, res) => {
    const { userId, credential } = req.body;

    try {
        const publicKeyBuffer = Buffer.from(credential.response.clientDataJSON, 'base64');

        await pool.query(
            'INSERT INTO authenticators (id, user_id, public_key, counter) VALUES ($1, $2, $3, $4)',
            [credential.id, userId, publicKeyBuffer, 0]
        );

        delete currentChallenges[userId];

        res.json({ verified: true, message: 'Huella registrada con éxito' });
    } catch (error) {
        console.error('Error guardando huella en BD:', error);
        res.status(500).json({ error: 'Error al verificar la huella' });
    }
});

module.exports = router;