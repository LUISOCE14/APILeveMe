import mongoose from "mongoose";
import bcrypt from "bcrypt";

const UserSchema = new mongoose.Schema({
  nombreCompleto:{
    type: String,
    required: false
  },
  edad:{
    type: Number,
    required: false,
  },
  email :{
    type: String,
    required: true,
    trim: true,
    unique: true,
  },
  avatar:{
    type: String,
  },
  password: {
    type: String,
    required: true,
  },
  preferenciasPrecio:{
    type:  Number,
    required: false,
  },
  intereses:[{
    type: mongoose.Schema.Types.ObjectId,
    ref: "Interese",
    required: true,
  }],
  date: {
    type: Date,
    default: Date.now,
  },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
});


UserSchema.methods.comparePassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

// Asumiendo que ya tienes este método para agregar intereses
UserSchema.statics.agregarIntereses = async function (idUsuario, interesesIds) {
  return this.updateOne(
    { _id: idUsuario },
    { $push: { intereses: { $each: interesesIds } } }
  );
};

UserSchema.methods.generatePasswordResetToken = function() {
  this.resetPasswordToken = Math.random().toString(36).slice(-8);
  this.resetPasswordExpires = Date.now() + 3600000; // 1 hour
};
export const UserModel = mongoose.model("User", UserSchema);
