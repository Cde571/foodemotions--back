const express = require('express');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const dotenv = require('dotenv');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// Cargar variables de entorno
dotenv.config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Conectar a MongoDB
mongoose.connect('mongodb://localhost:27017/mi_base_de_datos', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => {
    console.log('Conexión exitosa a MongoDB');
  })
  .catch((err) => {
    console.error('Error conectando a MongoDB', err);
  });

// Definir un esquema y modelo de usuario
const usuarioSchema = new mongoose.Schema({
  googleId: String,
  username: String,
  email: String,
  telefono: String,
  password: { type: String, required: false },
  profilePic: String,
  bio: String,
  status: String,
});

const Usuario = mongoose.model('Usuario', usuarioSchema);

// Configuración de CORS
app.use(cors({
  origin: 'http://localhost:4321',
  credentials: true // Permitir que el frontend envíe cookies
}));

// Configuración de express-session
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}));

// Inicializa Passport y usa sesiones
app.use(passport.initialize());
app.use(passport.session());

// Configuración de Passport para Google OAuth
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/callback"
}, async function (accessToken, refreshToken, profile, done) {
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

passport.serializeUser((user, done) => {
  done(null, user.id);
});

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
    const user = await Usuario.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado.' });
    }

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
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function (req, res) {
    // Redirigir al perfil del usuario después de una autenticación exitosa
    res.redirect('http://localhost:4321/Profile');
  }
);

app.post('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ message: 'Error cerrando sesión' });
    }
    res.sendStatus(200);
  });
});

// Ruta POST para insertar datos de registro manual en la base de datos
app.post('/sign-up', async (req, res) => {
  const { username, email, telefono, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'Las contraseñas no coinciden.' });
  }

  try {
    const usuarioExistente = await Usuario.findOne({ email });
    if (usuarioExistente) {
      return res.status(400).json({ message: 'El correo electrónico ya está registrado.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const nuevoUsuario = new Usuario({
      username,
      email,
      telefono,
      password: hashedPassword
    });

    await nuevoUsuario.save();

    res.status(200).json({ message: 'Usuario registrado correctamente.' });
  } catch (error) {
    res.status(500).json({ message: 'Error guardando el usuario.', error });
  }
});

// Iniciar servidor
app.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000');
});
