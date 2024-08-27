import validator from "validator";
import axios from "axios";
import dotenv from "dotenv";

dotenv.config();

const API_RECOMENDACIONES = process.env.URL_REC;

export const getRecomendacion = async (req, res) => {
  try {
    const { interests, price_preference } = req.body;

    // Validación de los datos de entrada
    if (!interests || !Array.isArray(interests) || interests.length === 0) {
      return res.status(400).json({ msg: "Se requiere un array de intereses" });
    }
    // Hacer la petición a la API
    const recommendations = await fetchRecommendations(
      interests,
      price_preference
    );
    if (recommendations.length === 0) {
      return res.json({ recommendations: [] });
    }

    // Modificar las recomendaciones para que solo devuelvan "activity"
    const modifiedRecommendations = recommendations.map(rec => ({
      activity: rec.activity,
    }));
    res.json({ recommendations: modifiedRecommendations });
  } catch (error) {
    console.error("Error al obtener recomendaciones:", error.message);
    res.status(500).json({ msg: "Error al procesar la solicitud" });
  }
};

const fetchRecommendations = async (interests, price_preference) => {
  try {
    const response = await axios.post(`${API_RECOMENDACIONES}/recommend`, {
      interests,
      price_preference,
    });

    const data = response.data;
    return data;
  } catch (error) {
    console.error("Error en fetchRecommendations:", error.message);
    if (error.response) {
      console.log("Respuesta de error:", error.response.status);
      console.log("Datos de error:", error.response.data);
    }
    throw error;
  }
};
