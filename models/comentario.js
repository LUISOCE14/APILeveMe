import mongoose from "mongoose";

const comentarioSchema = new mongoose.Schema({
    idPost: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Post",
        required: true,
    },
    idUsuario:{
        type: mongoose.Schema.Types.ObjectId,
        ref: "Users"
      },
    contenido: {
        type: String,
        required: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
        required: true,
    },
});

export const ComentarioModel = mongoose.model("Comentario", comentarioSchema);