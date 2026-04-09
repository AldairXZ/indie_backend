const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const pool = require('./db');

dotenv.config();

const app = express();

app.use(cors({
  origin: ['https://indie-angular.vercel.app', 'http://localhost:4200'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));

app.use(express.json());

const verifyToken = (req, res, next) => {
  const bearerHeader = req.headers['authorization'];
  if (!bearerHeader) return res.status(403).json({ message: 'Token requerido' });
  
  const token = bearerHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Token inválido' });
    req.user = decoded;
    next();
  });
};

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { rows: users } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (users.length === 0) return res.status(401).json({ message: 'Credenciales inválidas' });
    
    const user = users[0];
    if (password !== user.password_hash) return res.status(401).json({ message: 'Credenciales inválidas' });
    
    const { rows: permissionsRows } = await pool.query(`
      SELECT p.name 
      FROM permissions p
      JOIN user_permissions up ON p.id = up.permission_id
      WHERE up.user_id = $1
    `, [user.id]);
    
    const permissions = permissionsRows.map(row => row.name);
    
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email, permissions },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({ token, user: { id: user.id, username: user.username, email: user.email, permissions } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    if (!email.endsWith('@uteq.edu.mx')) {
      return res.status(400).json({ message: 'El correo debe pertenecer al dominio @uteq.edu.mx' });
    }

    const { rows: existing } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existing.length > 0) {
      return res.status(400).json({ message: 'Este correo ya se encuentra registrado' });
    }

    const { rows: result } = await pool.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id',
      [username, email, password]
    );

    const userId = result[0].id;
    const permissions = role === 'developer' ? ['download_games', 'publish_games', 'view_analytics'] : ['download_games'];

    for (const perm of permissions) {
      await pool.query(
        'INSERT INTO user_permissions (user_id, permission_id) SELECT $1, id FROM permissions WHERE name = $2',
        [userId, perm]
      );
    }

    res.status(201).json({ id: userId, username, message: 'Usuario registrado exitosamente' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/users/me', verifyToken, async (req, res) => {
  try {
    const { username, email } = req.body;
    await pool.query('UPDATE users SET username = $1, email = $2 WHERE id = $3', [username, email, req.user.id]);
    res.json({ message: 'Perfil actualizado correctamente' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/users/me', verifyToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.user.id]);
    res.json({ message: 'Cuenta eliminada correctamente' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/categories', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM categories');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/games', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.id, p.title, p.description, p.price, p.download_url, p.image_url as imagen, c.name as category, u.username as developer
      FROM products p
      JOIN categories c ON p.category_id = c.id
      JOIN users u ON p.developer_id = u.id
    `);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/my-games', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.*, c.name as category 
      FROM products p 
      JOIN categories c ON p.category_id = c.id 
      WHERE p.developer_id = $1
    `, [req.user.id]);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/games', verifyToken, async (req, res) => {
  try {
    const { categoryId, title, description, price, downloadUrl, imageUrl } = req.body;
    const developerId = req.user.id;

    if (!req.user.permissions.includes('publish_games')) {
      return res.status(403).json({ message: 'No tienes permiso para publicar juegos' });
    }

    const { rows } = await pool.query(
      'INSERT INTO products (developer_id, category_id, title, description, price, download_url, image_url) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
      [developerId, categoryId, title, description, price, downloadUrl, imageUrl]
    );

    res.status(201).json({ id: rows[0].id, message: 'Juego publicado exitosamente' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/games/:id', verifyToken, async (req, res) => {
  try {
    const gameId = req.params.id;
    const developerId = req.user.id;
    const { title, description, price, downloadUrl, imageUrl } = req.body;

    if (!req.user.permissions.includes('publish_games')) {
      return res.status(403).json({ message: 'No tienes permiso para gestionar juegos' });
    }

    const { rows: game } = await pool.query('SELECT developer_id FROM products WHERE id = $1', [gameId]);
    
    if (game.length === 0 || game[0].developer_id !== developerId) {
      return res.status(403).json({ message: 'Acceso denegado' });
    }

    await pool.query(
      'UPDATE products SET title = $1, description = $2, price = $3, download_url = $4, image_url = $5 WHERE id = $6',
      [title, description, price, downloadUrl, imageUrl, gameId]
    );

    res.json({ message: 'Juego actualizado exitosamente' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/games/:id', verifyToken, async (req, res) => {
  try {
    const gameId = req.params.id;
    const developerId = req.user.id;

    if (!req.user.permissions.includes('publish_games')) {
      return res.status(403).json({ message: 'No tienes permiso para gestionar juegos' });
    }

    const { rows: game } = await pool.query('SELECT developer_id FROM products WHERE id = $1', [gameId]);
    
    if (game.length === 0) {
      return res.status(404).json({ message: 'Juego no encontrado' });
    }
    
    if (game[0].developer_id !== developerId) {
      return res.status(403).json({ message: 'Solo puedes eliminar tus propios juegos' });
    }

    await pool.query('DELETE FROM products WHERE id = $1', [gameId]);
    res.json({ message: 'Juego eliminado exitosamente' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/library', verifyToken, async (req, res) => {
  try {
    const { productId } = req.body;
    const userId = req.user.id;
    
    await pool.query('INSERT INTO library (user_id, product_id) VALUES ($1, $2) ON CONFLICT (user_id, product_id) DO NOTHING', [userId, productId]);
    
    res.json({ message: 'Juego añadido a tu biblioteca' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/library', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.*, c.name as category, l.acquired_at
      FROM products p 
      JOIN library l ON p.id = l.product_id 
      JOIN categories c ON p.category_id = c.id
      WHERE l.user_id = $1
      ORDER BY l.acquired_at DESC
    `, [req.user.id]);
    
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/wishlist', verifyToken, async (req, res) => {
  try {
    const { productId } = req.body;
    const userId = req.user.id;
    
    await pool.query('INSERT INTO wishlist (user_id, product_id) VALUES ($1, $2) ON CONFLICT (user_id, product_id) DO NOTHING', [userId, productId]);
    res.json({ message: 'Añadido a tu lista de deseos' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/wishlist', verifyToken, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.*, c.name as category, w.added_at
      FROM products p 
      JOIN wishlist w ON p.id = w.product_id 
      JOIN categories c ON p.category_id = c.id
      WHERE w.user_id = $1
      ORDER BY w.added_at DESC
    `, [req.user.id]);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/wishlist/:productId', verifyToken, async (req, res) => {
  try {
    const productId = req.params.productId;
    const userId = req.user.id;
    
    await pool.query('DELETE FROM wishlist WHERE user_id = $1 AND product_id = $2', [userId, productId]);
    res.json({ message: 'Eliminado de tu lista de deseos' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

let currentRegisteringChallenge = null;

app.post('/api/webauthn/register/options', async (req, res) => {
    const { userId, username } = req.body;
    const challenge = crypto.randomBytes(32);
    currentRegisteringChallenge = challenge.toString('base64');

    const options = {
        challenge: currentRegisteringChallenge,
        rp: { name: "IndieHub UTEQ", id: "indie-angular.vercel.app" },
        user: { id: userId.toString(), name: username, displayName: username },
        pubKeyCredParams: [{ alg: -7, type: "public-key" }],
        timeout: 60000,
        attestation: "direct",
        authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" }
    };
    res.json(options);
});

app.post('/api/webauthn/register/verify', async (req, res) => {
    const { userId, credential } = req.body;
    const id = credential.id;
    const publicKey = Buffer.from(credential.response.attestationObject, 'base64');

    await pool.query(
        'INSERT INTO authenticators (id, user_id, public_key, counter) VALUES ($1, $2, $3, $4)',
        [id, userId, publicKey, 0]
    );

    currentRegisteringChallenge = null;
    res.json({ verified: true });
});

let currentLoginChallenge = null;

app.post('/api/webauthn/login/options', async (req, res) => {
    const challenge = crypto.randomBytes(32);
    currentLoginChallenge = challenge.toString('base64');

    const options = {
        challenge: currentLoginChallenge,
        timeout: 60000,
        userVerification: "required"
    };
    res.json(options);
});

app.post('/api/webauthn/login/verify', async (req, res) => {
    try {
        const { credential } = req.body;
        const id = credential.id;

        const { rows: authenticators } = await pool.query('SELECT * FROM authenticators WHERE id = $1', [id]);
        
        if (authenticators.length === 0) {
            return res.status(401).json({ message: 'Credencial biométrica no encontrada' });
        }

        const userId = authenticators[0].user_id;
        const { rows: users } = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
        
        if (users.length === 0) return res.status(401).json({ message: 'Usuario no encontrado' });

        const user = users[0];

        const { rows: permissionsRows } = await pool.query(`
          SELECT p.name 
          FROM permissions p
          JOIN user_permissions up ON p.id = up.permission_id
          WHERE up.user_id = $1
        `, [user.id]);
        
        const permissions = permissionsRows.map(row => row.name);
        
        const token = jwt.sign(
          { id: user.id, username: user.username, email: user.email, permissions },
          process.env.JWT_SECRET,
          { expiresIn: '24h' }
        );
        
        res.json({ token, user: { id: user.id, username: user.username, email: user.email, permissions } });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/games/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query(`
      SELECT p.*, c.name as category, u.username as developer
      FROM products p
      JOIN categories c ON p.category_id = c.id
      JOIN users u ON p.developer_id = u.id
      WHERE p.id = $1
    `, [id]);

    if (rows.length === 0) return res.status(404).json({ message: 'Juego no encontrado' });
    res.json(rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get('/api/2fa/setup', async (req, res) => {
  try {
    const { userId } = req.query; // En producción usa el ID del JWT
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(userId, 'IndieHub', secret);
    const qrImageUrl = await QRCode.toDataURL(otpauth);

    await pool.query('UPDATE users SET two_factor_secret = $1 WHERE id = $2', [secret, userId]);

    res.json({ qrImageUrl, secret });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/2fa/verify', async (req, res) => {
  const { userId, token } = req.body;
  const { rows } = await pool.query('SELECT two_factor_secret FROM users WHERE id = $1', [userId]);
  
  const isValid = authenticator.check(token, rows[0].two_factor_secret);

  if (isValid) {
    await pool.query('UPDATE users SET two_factor_enabled = TRUE WHERE id = $1', [userId]);
    res.json({ message: '2FA Activado correctamente' });
  } else {
    res.status(400).json({ message: 'Código inválido' });
  }
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'tu_correo_proyecto@gmail.com', // Tu correo real
    pass: 'tu_contraseña_de_aplicacion'   // Tu contraseña de aplicación de Google
  }
});

// Almacén temporal para los códigos generados
const codigos2FA = new Map();

// 2. Ruta para ENVIAR el correo
app.post('/api/2fa/send-email', async (req, res) => {
  const { email } = req.body;
  
  // Generar un código aleatorio de 6 dígitos
  const codigo = Math.floor(100000 + Math.random() * 900000).toString();
  
  // Guardar el código temporalmente asociado a ese correo
  codigos2FA.set(email, codigo);

  // Configurar el diseño del correo
  const mailOptions = {
    from: 'IndieHub Security <tu_correo_proyecto@gmail.com>',
    to: email,
    subject: '🔒 Tu código de seguridad de IndieHub',
    html: `
      <h2>Autenticación en IndieHub</h2>
      <p>Has solicitado activar la verificación en dos pasos. Tu código de seguridad es:</p>
      <h1 style="color: #6366f1; letter-spacing: 5px;">${codigo}</h1>
      <p>Si no solicitaste esto, ignora este mensaje.</p>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ message: 'Correo enviado exitosamente' });
  } catch (error) {
    console.error("Error enviando correo:", error);
    res.status(500).json({ error: 'No se pudo enviar el correo' });
  }
});

// 3. Ruta para VERIFICAR el código
app.post('/api/2fa/verify', async (req, res) => {
  const { userId, email, code } = req.body;
  
  // Buscar si el código que guardamos coincide con el que mandó el usuario
  const codigoGuardado = codigos2FA.get(email);

  if (codigoGuardado && codigoGuardado === code) {
    // ¡Es correcto! Actualizamos la base de datos de Supabase
    await pool.query('UPDATE users SET two_factor_enabled = TRUE WHERE id = $1', [userId]);
    
    // Borramos el código por seguridad
    codigos2FA.delete(email); 
    
    res.json({ message: '2FA Activado correctamente' });
  } else {
    res.status(400).json({ message: 'Código inválido o expirado' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));