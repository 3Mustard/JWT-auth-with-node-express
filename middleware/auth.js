const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function(req, res, next) {
  // Get token from header
  const token = req.header('x-auth-token');

  // If there is no token return 401
  if (!token) {
    return res.status(401).json({ msg: 'No token, authorization denied' }); // Status 401: invalid auth credentials
  }

  // Verify token 
  try {
    const decoded = jwt.verify(token, config.get('jwtSecret'));

    req.user = decoded.user; // req.user can be used by routes that call this middleware
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid'}); // Status 401: invalid auth credentials
  }
}
