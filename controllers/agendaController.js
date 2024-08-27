import mongoose from "mongoose";
import { AgendaModel } from "../models/agenda.js";
import jwt from "jsonwebtoken";
import validator from "validator"; // Asegúrate de tener 'validator' instalado
import { UserModel } from "../models/User.js";

export const obtenerAgendaUser = async (req, res) => {
  try {
    const idUsu = req.params.idUser;

    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({ msg: "Token de acceso no proporcionado." });
    }

    if (typeof idUsu !== "string" || !validator.isMongoId(idUsu)) {
      return res.status(400).json({ msg: "ID de usuario inválido." });
    }
    // Buscar la primera agenda activa del usuario que no está cerrada
    const agendaActiva = await AgendaModel.findOne(
      {
        idUsuario: idUsu,
        isClosed: false,
      },
      { _id: 1, actividades: 1 }
    );

    if (!agendaActiva) {
      return res.json({ msg: "No hay agendas activas para este usuario.", agendaActiva });
    };
  
    res.send(JSON.stringify(agendaActiva, null, 2));
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Error al obtener la agenda del usuario." });
  }
};

export const crearAgenda = async (req, res) => {
  try {
    const actividades = req.body.actividades;
    const idUser = req.body.idUser;
  
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({ msg: "Token de acceso no proporcionado." });
    }
    if (typeof idUser !== "string" || !validator.isMongoId(idUser)) {
      return res.status(400).json({ msg: "ID de usuario inválido." });
    }

    
    const userExists = await UserModel.findById(idUser); // Asegúrate de que User es tu modelo de usuario
    if (!userExists)
      return res.status(404).send({ msg: "Usuario no encontrado" });

    // Crear la nueva agenda con los datos de la solicitud
    const newAgenda = new AgendaModel({
      idUsuario: idUser,
      actividades: actividades, // Asumiendo que las actividades vienen en el cuerpo de la solicitud
    });

    // Guardar la nueva agenda en la base de datos
    await newAgenda.save();

    res.status(200).json({msg: "Agenda creada exitosamente." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Error inesperado." });
  }
};

export const actualizarAgenda = async (req, res) => {
  try {
    const idUser = req.body.idUser; // ID del usuario enviado en el cuerpo de la solicitud
    const nuevasActividades = req.body.nuevasActividades; // Nuevas actividades a agregar
    const idAgenda = req.params.idAgenda; // ID de la agenda envi


    // Verificar si el ID del usuario está presente
    if (typeof idUser !== "string" || !validator.isMongoId(idUser)) {
      return res.status(400).json({ message: "ID de usuario inválido." });
    }
    // Buscar la última agenda activa del usuario
    const ultimaAgendaActiva = await AgendaModel.findOne({
      idUsuario: idUser,
      isClosed: false,
    }).sort({ create_at: -1 }); // Ordenar por fecha de creación en orden descendente para obtener la más reciente

    if (!ultimaAgendaActiva) {
      return res.status(404).json({
        msg: "No se encontró ninguna agenda activa para el usuario especificado.",
      });
    }

    // Agregar las nuevas actividades
    ultimaAgendaActiva.actividades.push(...nuevasActividades);

    // Guardar la agenda actualizada en la base de datos
    await ultimaAgendaActiva.save();

    // Enviar la agenda actualizada como respuesta
    res.status(200).json({msg: "Agenda actualizada correctamente." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Error al actualizar la agenda." });
  }
};

export const marcarComoRealizada = async (req, res) => {
  try {
    const { idAgenda, idActividad } = req.body;

    // Validar que se hayan proporcionado ambos valores
    if (!idAgenda || !idActividad) {
      return res.status(400).json({
        msg: "Se requiere el ID de la agenda y el nombre de la actividad.",
      });
    }
    if (typeof idAgenda !== "string" || !validator.isMongoId(idAgenda)) {
      return res.status(400).json({ msg: "ID de agenda inválido." });
    }
    // Buscar la agenda por su ID
    const agenda = await AgendaModel.findById(idAgenda);

    if (!agenda) {
      return res
        .status(404)
        .json({ msg: "La agenda especificada no fue encontrada." });
    }

    // Iterar sobre las actividades de la agenda
    const actividadEncontrada = agenda.actividades.find(actividad =>
      actividad._id.equals(idActividad)
    );

    if (!actividadEncontrada) {
      return res.status(404).json({
        msg: "La actividad especificada no fue encontrada en la agenda.",
      });
    }

    // Marcar la actividad como realizada
    actividadEncontrada.completada = true;

    // Guardar la agenda actualizada en la base de datos
    await agenda.save();

    // Enviar la agenda actualizada como respuesta
    res.status(200).json({ msg: "Actividad marcada como realizada." });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ msg: "Error al marcar la actividad como realizada." });
  }
};

export const eliminarActividad = async (req, res) => {
  try {
    const { idAgenda, idActividad } = req.params;

    if (typeof idAgenda !== "string" || !validator.isMongoId(idAgenda)) {
      return res.status(400).json({ msg: "ID de agenda inválido." });
    }
    // Verificar si se han proporcionado ambos IDs
    if (!idAgenda || !idActividad) {
      return res
        .status(400)
        .json({ msg: "Se requieren los IDs de la agenda y la actividad." });
    }

    // Buscar la agenda por su ID
    const agenda = await AgendaModel.findById(idAgenda);

    if (!agenda) {
      return res
        .status(404)
        .json({ msg: "La agenda especificada no fue encontrada." });
    }

    // Filtrar y eliminar la actividad específica de la agenda
    const index = agenda.actividades.findIndex(actividad =>
      actividad._id.equals(idActividad)
    );
    if (index === -1) {
      return res.status(404).json({
        msg: "La actividad especificada no fue encontrada en la agenda.",
      });
    }
    agenda.actividades.splice(index, 1);



    // Guardar la agenda actualizada en la base de datos
    await agenda.save();

    // Enviar la agenda actualizada como respuesta
    res.status(200).json({ msg: "Actividad eliminada correctamente." });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ msg: "Error al eliminar la actividad de la agenda." });
  }
};
