import { Router } from "express";

import { iniciarSesion, cerrarSesion, registrarUsuario } from "../controllers/authController.js";

const router = Router();

router.post("/login", iniciarSesion);
router.get("/logout", cerrarSesion);
router.post("/register", registrarUsuario);

export default router;
