import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import helmet from 'helmet';
import compression from 'compression';
import welcomeRoutes from './routes/authRoutes.js';
import userRoutes from './routes/userRoutes.js';
import agendaRoutes from "./routes/agendaRoutes.js";
import recursosRoutes from './routes/recursosRoutes.js';
import postRoutes from './routes/postRoutes.js';
import apiRecommendations from "./routes/recomendacionRoutes.js"
import { connectDB } from './config/db.js';
import { closeAgendasDaily } from './services/cronJobs.js';

dotenv.config();

const app = express();
const port = process.env.PORT || 4000;
const mongo_uri = process.env.MONGO_URI;

// Middlewares
app.use(helmet());
app.use(compression());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  optionsSuccessStatus: 200
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rutas
app.use('/api/auth', welcomeRoutes);
app.use('/api/user', userRoutes);
app.use('/api/agendas', agendaRoutes);
app.use('/api/recursos', recursosRoutes);
app.use('/api/posts', postRoutes);
app.use("/api/recomendaciones",apiRecommendations)

closeAgendasDaily(); // Cada día a las 20:58

app.get('/', (req, res) => {
   res.send("Bienvenido a la API de Autenticación y Usuarios! Consulte la documentación para obtener más información.");
});

// Manejo de rutas no encontradas
app.use((req, res, next) => {
  res.status(404).json({ message: "Ruta no encontrada" });
});

// Manejo de errores
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Error interno del servidor' });
});

// Función de inicio
const start = async () => {
  try {
    await connectDB(mongo_uri);
    console.log('Conexión a la base de datos establecida');
    
    // Eliminar la condición y siempre iniciar el servidor HTTP
    app.listen(port, '0.0.0.0', () => {
      console.log(`Servidor corriendo en http://0.0.0.0:${port}`);
    });

  } catch (error) {
    console.error('Error al iniciar el servidor:', error);
    process.exit(1);
  }
};

start();

// Exportar la app para entornos serverless
export default app;