import { Router } from "express";
import { agregarPost, mostrarPost, mostrarTodosLosPosts, agregarComentario, agregarLike} from "../controllers/postController.js";


const router = Router();

router.post("/AgregarPost", agregarPost);
router.get("/MostrarPost/:idPost", mostrarPost);
router.get("/MostrarTodosLosPosts", mostrarTodosLosPosts);
router.post("/AgregarComentario", agregarComentario);
router.post("/AgregarLike", agregarLike);

export default router;