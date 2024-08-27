import express from 'express';
import { getRecomendacion } from '../controllers/recomendacionController.js';

const router = express.Router();

router.post('/', getRecomendacion);

export default router;