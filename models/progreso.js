import mongoose from "mongoose";

const ProgresoSchema = new mongoose.Schema({
    idUsuario: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
    },
    idAgenda: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Agenda",
        required: true,
    },
    date: {
        type: String,
        required: true,
    },
    actividadesTotal: {
        type: Number,
        required: true,
    },
    actividadesCompletadas: {
        type: Number,
        required: true,
    },
    todasCompletadas: {
        type: Boolean,
        required: true,
    },
});

// Middleware para asegurar que la fecha esté en formato 'YYYY-MM-DD'
ProgresoSchema.pre('save', function(next) {
    if (this.isModified('date')) {
        const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateRegex.test(this.date)) {
            const dateObj = new Date(this.date);
            if (!isNaN(dateObj.getTime())) {
                this.date = dateObj.toISOString().split('T')[0];
            } else {
                return next(new Error('Formato de fecha inválido'));
            }
        }
    }
    next();
});

export const ProgresoModel = mongoose.model('Progreso', ProgresoSchema);

