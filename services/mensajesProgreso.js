import { mensajes } from "./messages.js";

export const mensajeCompletados = (total, completadas, todasCompletadas) => {
    let porcentaje;

  if (!todasCompletadas) {
    porcentaje = (completadas / total) * 100;
  } else {
    porcentaje = 100;
  }
  // Encuentra el objeto correspondiente al rango de porcentaje
  const mensajeObj = mensajes.find(
    msg => porcentaje >= msg.min && porcentaje <= msg.max
  );

  // Si no se encuentra un objeto para el porcentaje, devolver un mensaje predeterminado
  if (!mensajeObj)
    return "No se pudo encontrar un mensaje para este porcentaje.";

  // Selecciona un mensaje aleatorio de la lista de textos
  const mensajesPosibles = mensajeObj.texts;
  const mensajeAleatorio =
    mensajesPosibles[Math.floor(Math.random() * mensajesPosibles.length)];

  return  mensajeAleatorio
};
