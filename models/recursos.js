import mongoose from "mongoose";

const recursosSchema = new mongoose.Schema({
    titulo: {
        type: String,
        required: true,
    },
    descripcion: {
        type: String,
        required: true,
    },
    tag: {
        type: String,
        required: true,
    },
    url: {
        type: String,
        required: true,
        unique:true,
        validate: {
            validator: function(v) {
                // Expresión regular para validar URLs
                return /^(https?:\/\/[^\s]+)/g.test(v);
            },
            message: props => `${props.value} no es una URL válida!`,
        },
    }
});

export const RecursoModel = mongoose.model("Recurso", recursosSchema);
