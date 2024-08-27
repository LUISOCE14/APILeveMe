import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config({
  path: "../.env"
});


mongoose.set("strictQuery", false);

 export const connectDB = (uri) =>{
  return mongoose.connect(uri);
}

