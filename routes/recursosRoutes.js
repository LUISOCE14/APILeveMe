import { Router } from "express";
import { agregarRecursos, obtenerRecursos } from "../controllers/recursosController.js";

const router = Router();

router.put("/AgregarRecursos/:idRecursos", agregarRecursos);
router.get("/ObtenerRecursos", obtenerRecursos);

export default router;
