exports.errorHandler = (err, req, res, next) => {
  console.error(err.stack); // Registrar el stack trace para depuración

  // Manejar errores de validación de Mongoose
  if (err.name === 'ValidationError') {
    return res.status(400).json({ message: 'Datos inválidos', errors: err.errors });
  }

  // Manejar errores de duplicado de clave en Mongoose
  if (err.code && err.code === 11000) {
    return res.status(400).json({ message: 'Duplicado detectado. El registro ya existe.' });
  }

  // Manejar errores de autenticación o autorización
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ message: 'No autorizado' });
  }

  // Si no se manejó el error anteriormente, responder con un error genérico del servidor
  res.status(500).json({ message: err.message || 'Error del servidor' });
};
