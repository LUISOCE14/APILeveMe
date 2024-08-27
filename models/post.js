import mongoose from "mongoose";

const postSchema = new mongoose.Schema({
    idUsuario:{
        type: mongoose.Schema.Types.ObjectId,
        ref: "Users"
      },
    descripcion: {
        type: String,
        required: true,
    },
    time: {
        type: Date,
        default: Date.now,
        required: true,
    },
    megusta: {
        type: Number,
        default: 0,
        required: true,
    },
    likesUsuarios: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "Users",
        default: [],
      }],
    comentarios: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "Comentario",
        required: true,
    }],
});

export const PostModel = mongoose.model("Post", postSchema);