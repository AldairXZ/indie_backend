const pool = require('./db');

const logAudit = async (userId, username, action, ip) => {
    try {
        await pool.query(
            'INSERT INTO audit_logs (user_id, username, action, ip_address) VALUES ($1, $2, $3, $4)',
            [userId, username, action, ip]
        );
    } catch (error) {
        console.error('Error al registrar auditoría:', error);
    }
};

module.exports = logAudit;