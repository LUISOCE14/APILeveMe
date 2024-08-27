import { Router } from "express";
import {
  obtenerAgendaUser,
  crearAgenda,
  actualizarAgenda,
  marcarComoRealizada,
  eliminarActividad,
} from "../controllers/agendaController.js";

const router = Router();

// Ruta de Agenda

router.get("/ObtenerAgendaUser/:idUser", obtenerAgendaUser);
router.put("/ActualizarAgenda/:idAgenda", actualizarAgenda);
router.post("/CrearAgenda", crearAgenda);
router.post("/MarcarComoRealizada", marcarComoRealizada);
router.delete("/EliminarActividad/:idAgenda/:idActividad", eliminarActividad);

export default router;
