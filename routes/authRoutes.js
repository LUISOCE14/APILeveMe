import { Router } from "express";

import {
  iniciarSesion,
  cerrarSesion,
  registrarUsuario,
  solicitarRecuperacionContrasena,
  cambiarContrasena,
} from "../controllers/authController.js";

const router = Router();

router.post("/login", iniciarSesion);
router.get("/logout", cerrarSesion);
router.post("/register", registrarUsuario);
router.post("/recuperar-contrasena", solicitarRecuperacionContrasena);
router.post("/cambiar-contrasena", cambiarContrasena);

export default router;
