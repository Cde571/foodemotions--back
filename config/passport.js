// passport.js
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const dotenv = require('dotenv');
const Usuario = require('./models/User'); // Ajusta la ruta según tu estructura de archivos

dotenv.config();

// Configurar Google Strategy
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
          firstName: profile.name.givenName,
          lastName: profile.name.familyName,
          email: profile.emails[0].value,
          profilePic: profile._json.picture,
          status: 'Online'
        });
        await user.save();
      }
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));

// Serializar el usuario en la sesión
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserializar el usuario desde la sesión
passport.deserializeUser(async (id, done) => {
  try {
    const user = await Usuario.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

module.exports = passport;
