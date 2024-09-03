import { UserModel } from "../models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import nodemailer from "nodemailer";

dotenv.config({
  path: "../.env",
});

export const iniciarSesion = async (req, res) => {
  const { email, password } = req.body;
  // Convertir el correo electrónico a minúsculas para evitar duplicados
  const lowerCaseEmail = email.toLowerCase();
  try {
    // Verificar que el usuario exista

    const user = await UserModel.findOne({ email: lowerCaseEmail });

    if (!user) {
      return res.status(400).json({ msg: "Usuario no encontrado" });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ msg: "Contraseña incorrecta" });
    }

    const usuarioConIntereses = await UserModel.findById(user._id)
    .populate("intereses")
    .exec();

    const intereses = usuarioConIntereses.intereses.map(interes => interes.nombre)

    // Include only necessary user information in the payload (e.g., user ID)
    const payload = {
      user: {
        id: user.id,
      },
    };

    //Creacion del token
    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      {
        expiresIn: "24h",
      },
      (err, token) => {
        if (err) {
          return res
            .status(500)
            .json({ msg: "Error al generar el token", error: err });
        }

        // Solo se incluye el ID del usuario en la respuesta
        res.status(200).json({
          success: true,
          token, // Este es el token JWT que el cliente debe almacenar y utilizar en futuras solicitudes
          user: {
            id: payload.user.id, // Solo se devuelve el ID del usuario
            nombre: user.nombreCompleto,
            intereses: intereses, // Solo se devuelve el nombre del usuario
            price: user.preferenciasPrecio
          },
        });
      }
    );
  } catch (err) {
    res.status(500).send("Error en el servidor");
  }
};

export const registrarUsuario = async (req, res) => {
  // Obtener los datos del usuario a registrar
  const { Usuario } = req.body;
   const email = Usuario.correo;
   Usuario.correo = email.toLowerCase();

  try {
    const existingUser = await UserModel.findOne({ email: Usuario.correo });
    if (existingUser) {
      return res.status(409).json({ msg: "El correo electronico ya existe" });
    }
    //encriptando la contraseña
    const hashedPassword = await bcrypt.hash(Usuario.password, 10);
    //Insertando el usuario en la base de datos
    const newUser = await UserModel.create({
      nombreCompleto: Usuario.nombre,
      edad: Usuario.edad,
      email: Usuario.correo,
      avatar:
        "https://objetivoligar.com/wp-content/uploads/2017/03/blank-profile-picture-973460_1280-768x768.jpg",
      password: hashedPassword,
      preferenciasPrecio: Usuario.preferenciasPrecio,
      intereses: Usuario.intereses,
    });

    if(!newUser){
      return res.status(500).json({ msg: "Error al crear el usuario" });
    }

    const usuarioConIntereses = await UserModel.findById(newUser._id)
    .populate("intereses")
    .exec();

    const intereses = usuarioConIntereses.intereses.map(interes => interes.nombre)



    // Crear el payload del token
    const payload = {
      user: {
        id: newUser._id, // Solo se devuelve el ID del usuario
      },
    };

    //Creacion del token
    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      {
        expiresIn: "24h",
      },
      (err, token) => {
        if (err) {
          return res
            .status(500)
            .json({ msg: "Error al generar el token", error: err });
        }

        // Solo se incluye el ID del usuario en la respuesta

        res.status(200).json({
          success: true,
          token, // Este es el token JWT que el cliente debe almacenar y utilizar en futuras solicitudes
          user: {
            id: newUser._id,
            nombre: newUser.nombreCompleto,
            intereses: intereses,
            price: newUser.preferenciasPrecio  
          },
        });
      }
    );
  } catch (err) {
    // Handle specific errors (e.g., validation errors)
    if (err.name === "ValidationError") {
      return res.status(400).json({ msg: err.msg });
    }
    console.error(err); // Only log the error for debugging, not the hashed password
    res.status(500).send("Error en el servidor");
  }
};

export const cerrarSesion = async (req, res) => {
  try {
    try {
      const { token } = req.headers.authorization;
      if (!token) {
        return res.status(401).json({ msg: "No token provided." });
      }

      // Verifica el token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const userId = decoded.userId;

      // Busca el usuario en la base de datos
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ msg: "User not found." });
      }

      // Aquí puedes decidir si quieres eliminar el token del usuario o simplemente marcarlo como inválido
      // Por ejemplo, eliminando todos los tokens asociados al usuario
      await User.updateOne({ _id: userId }, { $set: { tokens: [] } });

      res.status(200).json({ msg: "Session closed successfully." });
    } catch (error) {
      console.error(error);
      res.status(500).json({ msg: "Server error." });
    }
  } catch (err) {
    console.error(err); // Only log the error for debugging, not the hashed password
    res.status(500).send("Error en el servidor");
  }
};

export const solicitarRecuperacionContrasena = async (req, res) => {
  const { email } = req.body;
  const lowerCaseEmail = email.toLowerCase();

  try {
    const user = await UserModel.findOne({ email: lowerCaseEmail });
    if (!user) {
      return res.status(404).json({ msg: "Usuario no encontrado" });
    }

    user.generatePasswordResetToken();
    await user.save();

    // Configuración actualizada del transporter
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false, // true para 465, false para otros puertos
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      },
      tls: {
        rejectUnauthorized: false
      }
    });

    // Verificar la conexión
    transporter.verify(function(error, success) {
      if (error) {
        console.log(error);
      } else {
        console.log("Servidor listo para enviar mensajes");
      }
    });

    // Enviar el correo
    let info = await transporter.sendMail({
      from: `"Tu Aplicación" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: "Recuperación de contraseña",
      text: `Tu código de recuperación es: ${user.resetPasswordToken}\nEste código expirará en 1 hora.`
    });

    console.log("Mensaje enviado: %s", info.messageId);

    res.status(200).json({ msg: "Se ha enviado un correo con las instrucciones para recuperar tu contraseña" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Error en el servidor", error: err.message });
  }
};

export const cambiarContrasena = async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    // Buscar al usuario por el token de reseteo
    const user = await UserModel.findOne({ 
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ msg: "Token inválido o expirado" });
    }

    // Verificar que la nueva contraseña sea diferente de la actual
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({ msg: "La nueva contraseña debe ser diferente de la actual" });
    }

    // Encriptar la nueva contraseña
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Actualizar la contraseña y limpiar los campos de recuperación
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

    res.status(200).json({ msg: "Contraseña actualizada correctamente" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Error en el servidor", error: err.message });
  }
};