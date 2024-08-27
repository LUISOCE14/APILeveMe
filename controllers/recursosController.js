import mongoose from "mongoose";
import { RecursoModel } from "../models/recursos.js";
import jwt from "jsonwebtoken";
import validator from "validator";

export const agregarRecursos = async (req, res) => {
  try {
    // Extraer los datos del cuerpo de la solicitud
    const { titulo, descripcion, tag, url } = req.body;

    // Crear un nuevo recurso con los datos recibidos
    const nuevoRecurso = new RecursoModel({
      titulo,
      descripcion,
      tag,
      url,
    });

    // Guardar el nuevo recurso en la base de datos
    await nuevoRecurso.save();

    // Enviar respuesta indicando éxito
    res.status(201).json({ msg: "Recurso agregado exitosamente" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Error interno del servidor" });
  }
};

export const obtenerRecursos = async (req, res) => {
  try {
    // Buscar todos los recursos en la base de datos
    const recursos = await RecursoModel.find();

    // Enviar respuesta con los recursos encontrados
    res.status(200).json(recursos);
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Error interno del servidor" });
  }
};
