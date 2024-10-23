const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const dotenv = require('dotenv');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const morgan = require('morgan');
const helmet = require('helmet');

// Cargar variables de entorno
dotenv.config();

const app = express();

// Middleware para logging y seguridad
app.use(morgan('dev'));
app.use(helmet());

// Configuración de CORS
app.use(cors({
  origin: 'http://localhost:4321',
  credentials: true,
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Conectar a MongoDB
mongoose.connect('mongodb://localhost:27017/mi_base_de_datos', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Conexión exitosa a MongoDB'))
  .catch(err => console.error('Error conectando a MongoDB', err));

// Definir esquemas y modelos
const usuarioSchema = new mongoose.Schema({
  googleId: String,
  username: String,
  email: { type: String, required: true, unique: true },
  telefono: String,
  password: { type: String, required: false },
  profilePic: String,
  bio: String,
  status: String,
});

const Usuario = mongoose.model('Usuario', usuarioSchema);

// Definir esquema y modelo para recetas
const recipeSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  ingredients: { type: [String], required: true },
  steps: { type: [String], required: true },
  rating: { type: Number, min: 0, max: 5 } // Asegurar que el rating esté entre 0 y 5
});

const Recipe = mongoose.model('Recipe', recipeSchema);

// Configuración de express-session
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
}));

// Configuración de express-session
app.use(session({
  secret: 'your-secret-key', // Cambia esto por una clave secreta segura
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Cambia a true si usas HTTPS
    httpOnly: true,
    sameSite: 'lax',
  },
}));

// Inicializar Passport y sesiones
app.use(passport.initialize());
app.use(passport.session());


// Configuración de Passport para Google OAuth
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await Usuario.findOne({ googleId: profile.id });
    if (!user) {
      user = new Usuario({
        googleId: profile.id,
        username: profile.displayName,
        email: profile.emails[0].value,
        profilePic: profile._json.picture,
        bio: '',
        status: 'Online'
      });
      await user.save();
    }
    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await Usuario.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

// Middleware para proteger rutas
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ message: 'No autorizado, por favor inicia sesión' });
}

// Ruta para obtener datos del perfil del usuario
app.get('/profile-data', ensureAuthenticated, async (req, res) => {
  try {
    const user = await Usuario.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'Usuario no encontrado.' });

    res.json({
      profilePic: user.profilePic || '',
      userName: user.username || '',
      email: user.email || '',
      phone: user.telefono || '',
      status: user.status || 'Offline',
      bio: user.bio || '',
      interactionHistory: 'Sin interacciones recientes',
      preferences: {
        interests: ['AI', 'Technology'],
        notifications: true,
        language: 'es',
      },
    });
  } catch (error) {
    console.error('Error obteniendo los datos del perfil:', error);
    res.status(500).json({ message: 'Error al obtener los datos del perfil.' });
  }
});

// Rutas para Google OAuth
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
  res.redirect('http://localhost:4321/Profile');
});
// Ruta para el inicio de sesión manual
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Buscar al usuario por el nombre de usuario
    const user = await Usuario.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: 'Usuario no encontrado.' });
    }

    // Verificar la contraseña
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Contraseña incorrecta.' });
    }

    // Iniciar sesión al usuario
    req.login(user, (err) => {
      if (err) return res.status(500).json({ message: 'Error al iniciar sesión.' });

      // Redirigir al perfil del usuario después del inicio de sesión exitoso
      return res.status(200).json({ message: 'Inicio de sesión exitoso.' });
    });
  } catch (error) {
    console.error('Error en el login:', error);
    res.status(500).json({ message: 'Error al iniciar sesión.' });
  }
});


// Ruta para cerrar sesión
app.post('/logout', (req, res) => {
  req.logout((err) => {
    if (err) return res.status(500).json({ message: 'Error cerrando sesión' });
    res.sendStatus(200);
  });
});

// Ruta POST para insertar datos de registro manual en la base de datos
app.post('/sign-up', [
  body('username').notEmpty().withMessage('El nombre de usuario es obligatorio.'),
  body('email').isEmail().withMessage('Debes proporcionar un correo electrónico válido.'),
  body('telefono').notEmpty().withMessage('El teléfono es obligatorio.'),
  body('password').isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres.'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error('Las contraseñas no coinciden.');
    }
    return true;
  })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, email, telefono, password } = req.body;

  try {
    // Verificar si el usuario ya existe en la base de datos
    const usuarioExistente = await Usuario.findOne({ email });
    if (usuarioExistente) {
      return res.status(400).json({ message: 'El correo electrónico ya está registrado.' });
    }

    // Cifrar la contraseña antes de guardarla
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear el nuevo usuario en la base de datos
    const nuevoUsuario = new Usuario({
      username,
      email,
      telefono,
      password: hashedPassword
    });

    await nuevoUsuario.save();

    // Iniciar sesión automáticamente después del registro
    req.login(nuevoUsuario, (err) => {
      if (err) {
        console.error('Error al iniciar sesión después del registro:', err);
        return res.status(500).json({ message: 'Error al iniciar sesión después del registro.' });
      }
      // Si el inicio de sesión es exitoso, enviar una respuesta exitosa
      res.status(201).json({ message: 'Usuario registrado y autenticado correctamente.' });
    });
  } catch (error) {
    console.error('Error guardando el usuario:', error);
    res.status(500).json({ message: 'Error guardando el usuario en la base de datos.', error: error.message });
  }
});



// ---- NUEVAS RUTAS PARA RECETAS ----

// Ruta para obtener todas las recetas
app.get('/recipes', async (req, res) => {
  try {
    const recipes = await Recipe.find();
    res.json(recipes);
  } catch (err) {
    console.error('Error obteniendo recetas:', err);
    res.status(500).json({ message: 'Error al obtener recetas.', error: err.message });
  }
});

// Ruta para agregar una nueva receta
app.post('/recipes', async (req, res) => {
  try {
    const { name, description, ingredients, steps, rating } = req.body;

    // Validar que los datos necesarios estén presentes
    if (!name || !description || !ingredients || !steps) {
      return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
    }

    const newRecipe = new Recipe({ name, description, ingredients, steps, rating });
    await newRecipe.save();
    res.status(201).json({ message: 'Receta creada', recipe: newRecipe });
  } catch (err) {
    console.error('Error creando receta:', err);
    res.status(500).json({ message: 'Error al crear la receta', error: err.message });
  }
});

// Iniciar servidor
app.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000');
});
