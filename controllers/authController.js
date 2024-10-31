const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

exports.registerUser = [
  // Validaciones
  body('username').notEmpty().withMessage('El nombre de usuario es obligatorio.'),
  body('email').isEmail().withMessage('Debes proporcionar un correo electrónico válido.'),
  body('password').isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres.'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Las contraseñas no coinciden.');
    }
    return true;
  }),

  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;

    try {
      // Verificar si el usuario ya existe
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: 'El correo electrónico ya está registrado.' });
      }

      // Hashear la contraseña
      const hashedPassword = await bcrypt.hash(password, 10);

      // Crear un nuevo usuario
      const newUser = new User({
        username,
        email,
        password: hashedPassword
      });

      await newUser.save();

      // Generar token JWT
      const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

      // Enviar la respuesta con el token
      res.status(201).json({ message: 'Usuario registrado correctamente.', token });
    } catch (error) {
      console.error('Error registrando el usuario:', error);
      res.status(500).json({ message: 'Error registrando el usuario.', error: error.message });
    }
  }
];
