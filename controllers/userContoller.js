import { UserModel } from "../models/User.js";
import dotenv from "dotenv";
import validator from "validator";
import mongoose from "mongoose";
import { InteresModel } from "../models/Intereses.js";
import { ProgresoModel } from "../models/progreso.js";
import { mensajeCompletados } from "../services/mensajesProgreso.js";

dotenv.config({
  path: "../.env",
});

export const ObtenerDatosUsuario = async (req, res) => {
  try {
    const idUser = req.params.idUser;

    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Extrae el token del encabezado Authorization

    if (!token) {
      return res.status(401).json({ msg: "Token de acceso no proporcionado." });
    }

    // Verifica si idUser es una cadena vacía además de verificar que no sea nulo o 'undefined'
    if (typeof idUser !== "string" || !validator.isMongoId(idUser)) {
      return res.status(400).json({ msg: "ID de usuario inválido." });
    }
    // Aquí asumimos que tienes una función para buscar al usuario por ID en tu modelo de usuarios.
    // Debes reemplazar esta parte con la lógica real de búsqueda en tu base de datos.
    const user = await UserModel.findById(idUser).populate("intereses").exec();

    if (!user) {
      return res.status(404).json({ msg: "Usuario no encontrado." });
    }
    res.json({ user, password: undefined }); // Elimina la contraseña antes de devolver los datos del usuario
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Error interno del servidor." });
  }
};

export const actualizarFoto = async (req, res) => {
  const { id, avatar } = req.body;
  try {
    if (typeof id !== "string" || !validator.isMongoId(id)) {
      return res.status(400).json({ msg: "ID de usuario inválido." });
    }
    if (!validator.isURL(avatar)) {
      return res
        .status(400)
        .json({ msg: "Debes proporcionar la url de la imagen." });
    }
    const user = await UserModel.findByIdAndUpdate(
      id,
      { avatar },
      { new: true }
    );

    if (!user) {
      return res
        .status(404)
        .json({ msg: "No se puedo actualizar la foto de perfil." });
    } else {
      res
        .status(200)
        .json({ msg: "Foto de perfil fue actualizada correctamente." });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Error interno del servidor." });
  }
};

export const obtenerIntereses = async (req, res) => {
  const idUser = req.params.idUser;

  try {
    // Busca el usuario por ID
    //const user = await UserModel.findById(idUser);
    const usuarioConIntereses = await UserModel.findById(idUser)
      .populate("intereses")
      .exec();

    if (typeof idUser !== "string" || !validator.isMongoId(idUser)) {
      return res.status(400).json({ msg: "ID de usuario inválido." });
    }

    if (!usuarioConIntereses) {
      return res.status(404).json({ msg: "Usuario no encontrado." });
    }

    // Devuelve los intereses del usuario
    return res.json({ intereses: usuarioConIntereses.intereses });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Error interno del servidor." });
  }
};

export const obtenerTodosLosIntereses = async (req, res) => {
  try {
    const intereses = await InteresModel.find();
    if (!intereses || intereses.length === 0) {
      return res.status(404).json({ msg: "No se encontraron intereses." });
    }

    res.status(200).json(intereses);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      msg: "Error interno del servidor al intentar obtener todos los intereses.",
    });
  }
};

export const actualizarIntereses = async (req, res) => {
  const { idUser, intereses } = req.body;

  try {
    // Verificar si el ID del usuario es válido
    if (typeof idUser !== "string" || !validator.isMongoId(idUser)) {
      return res.status(400).json({ msg: "ID de usuario inválido." });
    }

    if (intereses.length <= 0) {
      return res
        .status(400)
        .json({ msg: "Debes especificar al menos un interés." });
    }
    // Buscar al usuario por ID
    const user = await UserModel.findByIdAndUpdate(
      idUser,
      { intereses },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ msg: "Usuario no encontrado." });
    }

    res.status(200).json({ msg: "Intereses actualizados exitosamente." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Error interno del servidor." });
  }
};

export const agregarIntereses = async (req, res) => {
  const { idUsuario, interesesIds } = req.body;

  try {
    const existingIntereses = await UserModel.findById(idUsuario).select(
      "intereses"
    );
    if (!existingIntereses) {
      return res.status(404).json({ msg: "Usuario no encontrado." });
    }

    let interesesYaExisten = [];
    for (let interesId of interesesIds) {
      const indice = existingIntereses.intereses.indexOf(interesId);
      if (indice > -1) {
        interesesYaExisten.push(interesId); // Agrega el ID del interés que ya existe
      }
    }

    if (interesesYaExisten.length === 0) {
      // Si no hay intereses duplicados, procede a agregar los nuevos intereses
      const updatedUser = await UserModel.agregarIntereses(
        idUsuario,
        interesesIds
      );
      return res.json({
        msg: "Intereses agregados exitosamente.",
        intereses: updatedUser.intereses,
      });
    } else {
      // Si hay intereses duplicados, envía un mensaje indicando cuáles son
      return res.status(409).json({
        msg: "Algunos intereses ya están asociados con el usuario.",
        interesesDuplicados: interesesYaExisten,
      });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Error interno del servidor." });
  }
};

export const eliminarIntereses = async (req, res) => {
  const { idUsuario, idInteres } = req.body;

  try {
    if (typeof idUsuario !== "string" || !validator.isMongoId(idUsuario)) {
      return res.status(400).json({ msg: "ID de usuario inválido." });
    }

    // Verifica si idInteres es una cadena vacía además de verificar que no sea nulo o 'undefined'
    if (typeof idInteres !== "string" || !validator.isMongoId(idInteres)) {
      return res.status(400).json({ msg: "ID de interés inválido." });
    }

    const user = await UserModel.findByIdAndUpdate(
      idUsuario,
      { $pull: { intereses: idInteres } },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ msg: "Usuario o interés no encontrado." });
    }

    res.status(200).json({ msg: "Interés eliminado exitosamente." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Error interno del servidor." });
  }
};

export const ObtenerProgresoUsuario = async (req, res) => {
  const { idUser, fecha } = req.body;



  try {
    if (typeof idUser !== "string" || !validator.isMongoId(idUser)) {
      return res.status(400).json({ msg: "ID de usuario inválido." });
    }
    if (!fecha || typeof fecha !== "string" || !validator.isDate(fecha)) {
      return res
        .status(400)
        .json({ msg: "Debes proporcionar una fecha válida." });
    }

    const progreso = await ProgresoModel.findOne({
      idUsuario: idUser,
      date: fecha,
    }).exec();

    if (!progreso) {
      return res.json({
        msg: "Hoy no registraste actividades, pero no te desanimes. La constancia es la clave del éxito, ¡sigue adelante!",
        estado: 0,
      });
    }

    const porcentaje2 = calcularProgreso(progreso);
    const incompletas =
      progreso.actividadesTotal - progreso.actividadesCompletadas;
    const mensaje = mensajeCompletados(
      progreso.actividadesTotal,
      progreso.actividadesCompletadas,
      progreso.todasCompletadas
    );
    const newProgreso = [{
      actividadesTotal: progreso.actividadesTotal,
      actividadesCompletada: progreso.actividadesCompletadas,
      actividadesIncompletas: incompletas,
      porcentaje: porcentaje2,
      mensaje: mensaje,
    }];
    return res.json(newProgreso);

  } catch (error) {
    console.error("Error en ObtenerProgresoUsuario:", error);
    return res.status(500).json({ msg: "Error interno del servidor." });
  }
};

const calcularProgreso = agenda => {
  const porcentaje =
    (agenda.actividadesCompletadas / agenda.actividadesTotal) * 100;

  return porcentaje;
};
