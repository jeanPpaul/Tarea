const jwt = require('jsonwebtoken');

// Con este middleware se verificará la validez del JWT en las solicitudes
const authenticateToken = (req, res, next) => {
    // Se obtiene el token del HTTP header 'Authorization'
    // Los tokens se envían en el formato "Bearer <TOKEN_JWT>"
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    // Verifica si existe el token
    if (token == null) {
        return res.status(401).json({
            error: 'Token de autenticación requerido'
        });
    }

    // Verifica el JWT
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {

        // Si hay un error al verificar
        if (err) {
            console.error('JWT error de verificación:', err);
            return res.status(403).json({
                error: 'Token inválido o expirado'
            });
        }

        // Si el token es válido
        req.user = user;

        // Continúa con la siguiente función
        next();
    });
};

// EXPORTAR EL MIDDLEWARE
module.exports = authenticateToken;