import cron from 'node-cron';
import { AgendaModel } from '../models/agenda.js';
import { ProgresoModel }  from '../models/progreso.js';

 export const closeAgendasDaily = () => {
    cron.schedule('55 23 * * *', async () => {
      try {
        const today = new Date().toLocaleDateString('en-CA', { timeZone: 'America/Mexico_City' });
        const agendas = await AgendaModel.find({ isClosed: false });
  
        for (const agenda of agendas) {
          const totalActivities = agenda.actividades.length;
          const completedActivities = agenda.actividades.filter(act => act.completada).length;
  
          // Crear el registro de progreso
          await ProgresoModel.create({
            idUsuario: agenda.idUsuario,
            idAgenda: agenda._id,
            date: today,
            actividadesTotal: totalActivities,
            actividadesCompletadas: completedActivities,
            todasCompletadas: totalActivities === completedActivities,
          });
  
          // Cerrar la agenda
          agenda.isClosed = true;
          await agenda.save();
        }
  
        console.log('Agendas cerradas y progreso registrado con éxito para el día:', today);
      } catch (error) {
        console.error('Error en el cron job de cierre de agendas:', error);
      }
    });
  };
