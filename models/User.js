const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true }, // Cambiado para que coincida con el registro
  firstName: { type: String }, // Opcional si no se usa en el registro manual
  lastName: { type: String }, // Opcional si no se usa en el registro manual
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    match: /.+\@.+\..+/ // Validación de formato de correo
  },
  telefono: { // Cambiado de "phone" a "telefono" para coincidir con el registro
    type: String, 
    required: true, 
    match: /^\d{10}$/ // Validación para un número de teléfono de 10 dígitos
  },
  password: { type: String, required: true },
  profilePic: { type: String, default: '' }, // Opcional
  bio: { type: String, default: '' }, // Opcional
  status: { 
    type: String, 
    default: 'Offline' // Valor por defecto
  },
}, { timestamps: true }); // Agregar timestamps (createdAt y updatedAt)

// Hash de la contraseña antes de guardar
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Método para comparar contraseñas
userSchema.methods.comparePassword = async function(password) {
  return await bcrypt.compare(password, this.password);
};

// Virtual para el nombre completo (si estás utilizando firstName y lastName)
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

module.exports = mongoose.model('User', userSchema);
