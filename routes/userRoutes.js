import { Router } from "express";
import {
  ObtenerDatosUsuario,
  actualizarFoto,
  obtenerIntereses,
  actualizarIntereses,
  obtenerTodosLosIntereses,
  agregarIntereses,
  eliminarIntereses,
  ObtenerProgresoUsuario
} from "../controllers/userContoller.js";

const router = Router();

router.get("/obtenerPerfilUsuario/:idUser", ObtenerDatosUsuario);
router.post("/actualizarFoto", actualizarFoto);
router.get("/obtenerIntereses/:idUser", obtenerIntereses);
router.post("/actualizarIntereses", actualizarIntereses);
router.get("/obtenerTodosLosIntereses", obtenerTodosLosIntereses);
router.post("/agregarIntereses", agregarIntereses);
router.put("/eliminarIntereses", eliminarIntereses);
router.post("/ObtenerProgresoUsuario", ObtenerProgresoUsuario);

export default router;
