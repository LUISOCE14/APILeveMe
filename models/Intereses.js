import mongoose from "mongoose";

const InteresSchema = new mongoose.Schema({
    nombre: {
        type: String,
        required: true,
    },
});

export const InteresModel = mongoose.model("Interese", InteresSchema);