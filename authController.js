const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const logAudit = require('./auditHelper');

router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress;

    try {
        const userResult = await pool.query('SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL', [email]);
        if (userResult.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

        const user = userResult.rows[0];

        // Control de Seguridad: Verificación de cuenta bloqueada o inactiva
        if (!user.is_active) return res.status(403).json({ error: 'Cuenta desactivada por el administrador.' });
        if (user.locked_until && new Date(user.locked_until) > new Date()) {
            return res.status(423).json({ error: 'Cuenta bloqueada temporalmente por múltiples intentos fallidos.' });
        }

        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            // Incrementar intentos fallidos
            const attempts = user.failed_attempts + 1;
            let lockedUntil = null;
            if (attempts >= 5) {
                lockedUntil = new Date(Date.now() + 15 * 60000); // Bloqueo de 15 minutos
                await logAudit(user.id, user.username, 'BLOQUEO_CUENTA', ip);
            }
            await pool.query('UPDATE users SET failed_attempts = $1, locked_until = $2 WHERE id = $3', [attempts, lockedUntil, user.id]);
            return res.status(401).json({ error: 'Contraseña incorrecta' });
        }

        // Resetear intentos y generar token
        await pool.query('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1', [user.id]);
        
        // Control de Seguridad: Expiración de sesión en JWT (1 hora)
        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        
        // Registrar Auditoría
        await logAudit(user.id, user.username, 'INICIO_SESION', ip);

        res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
    } catch (error) {
        res.status(500).json({ error: 'Error del servidor' });
    }
});