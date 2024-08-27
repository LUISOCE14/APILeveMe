import { PostModel } from "../models/post.js";
import validator from "validator";
import { ComentarioModel } from "../models/comentario.js";
import {
  loadCensorWords,
  containsCensoredWords,
} from "../services/censorUtils.js";
import { UserModel } from "../models/User.js";

export const agregarPost = async (req, res) => {
  try {
    // Cargar palabras censurables
    const words = loadCensorWords();

    const { idUser, descripcion } = req.body;
    if (!validator.isMongoId(idUser)) {
      return res.json({ msg: "ID de usuario inválido.",estado: 0 });
    }

    const userExists = await UserModel.findById(idUser);
    if (!userExists) {
      return res.json({ msg: "El usuario no existe.",estado: 0 });
    }

    if (!descripcion.trim()) {
      return res
        .status(400)
        .json({ msg: "La descripción no puede estar vacía.",estado: 0 });
    }

    // Verificar si la descripción contiene palabras censurables
    if (containsCensoredWords(descripcion, words)) {
      return res
        .json({ msg: "La descripción contiene palabras no permitidas.",estado: 0 });
    }

    // Si llegamos aquí, la descripción es válida
    const newPost = new PostModel({
      idUsuario: idUser,
      descripcion: descripcion,
    });

    await newPost.save();
    res.status(201).json({msg: "Post agregado correctamente.", estado: 1 });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Error interno del servidor." });
  }
};

export const mostrarPost = async (req, res) => {
  try {
    // Obtener el ID del post de la solicitud
    const postId = req.params.idPost;

    // Buscar el post en la base de datos, incluyendo la información del usuario y los comentarios
    const comentarios = await ComentarioModel.find({ idPost: postId }).populate(
      {
        path: "idUsuario",
        model: "User",
        select: "nombreCompleto avatar",
      }
    ).sort({ createdAt: -1 });
    // Verificar si el post existe
    if (!comentarios) {
      return res.status(404).json({ msg: "El post no existe." });
    }

    const comentariosData = comentarios.map(comentario => ({
      id: comentario._id,
      contenido: comentario.contenido,
      time: formatearFecha(comentario.createdAt),
      usuario: {
        id: comentario.idUsuario._id,
        nombre: comentario.idUsuario.nombreCompleto,
        avatar: comentario.idUsuario.avatar,
      },
    }));

    // Devolver los detalles del post
    res.status(200).json(comentariosData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Hubo un error al procesar la solicitud." });
  }
};

export const mostrarTodosLosPosts = async (req, res) => {
  try {
    // Buscar todos los posts en la base de datos, incluyendo la información del usuario y el número de comentarios
    const posts = await PostModel.find()
      .populate({
        path: "idUsuario",
        model: "User",
        select: "nombreCompleto avatar",
      })
      .select("_id descripcion time megusta comentarios likesUsuarios")
      .exec();

    // Verificar si hay posts
    if (posts.length === 0) {
      return res.status(200).json({ msg: "No hay posts.", data: [] });
    }

    // Transformar la respuesta para incluir el número de comentarios
    const postData = posts.map(post => ({
      post: {
        id: post._id,
        descripcion: post.descripcion,
        time: formatearFecha(post.time),
        megusta: post.megusta,
        numComentarios: post.comentarios.length,
        likes: JSON.stringify(post.likesUsuarios, null, 2),
      },
      usuario: {
        id: post.idUsuario._id,
        nombreCompleto: post.idUsuario.nombreCompleto,
        avatar: post.idUsuario.avatar,
      },
    }));

    // Devolver los posts transformados
    res.status(200).json(postData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Hubo un error al procesar la solicitud." });
  }
};

export const agregarComentario = async (req, res) => {
  const { idPost, idUser, comentario } = req.body;

  try {
    // Cargar palabras censurables
    const words = loadCensorWords();

    if (!validator.isMongoId(idUser)) {
      return res.status(400).json({ msg: "ID de usuario inválido." });
    }
    if (!validator.isMongoId(idPost)) {
      return res.status(400).json({ msg: "ID de post inválido." });
    }
    if (!validator.isLength(comentario, { min: 1, max: 1000 })) {
      return res
        .status(400)
        .json({ msg: "El comentario debe tener entre 1 y 1000 caracteres." });
    }

    // Verificar si el comentario contiene palabras censurables
    if (containsCensoredWords(comentario, words)) {
      return res
        .status(400)
        .json({ msg: "El comentario contiene palabras no permitidas." });
    }

    // Verificar si el post y el usuario existen
    const postExists = await PostModel.findById(idPost);
    if (!postExists) {
      return res.status(404).json({ msg: "El post no existe." });
    }
    const userExists = await UserModel.findById(idUser);
    if (!userExists) {
      return res.status(404).json({ msg: "El usuario no existe." });
    }

    const newComentario = new ComentarioModel({
      idPost,
      idUsuario: idUser,
      contenido: comentario,
    });

    const savedComentario = await newComentario.save();
    postExists.comentarios.push(savedComentario._id);

    await postExists.save();
    const newCommentario =  await ExtraerInfoComentario(savedComentario);

    res.status(201).json(newCommentario);
  } catch (error) {
    console.error(error);
    return res
      .status(500)
      .json({ msg: "Hubo un error al agregar el comentario." });
  }
};

const formatearFecha = time => {
  // Convertir la cadena de fecha recibida en un objeto Date
  const postTime = new Date(time);

  // Formatear la fecha al formato yyyy-mm-dd
  const fechaFormateada = postTime.toISOString().split("T")[0];

  return fechaFormateada;
};

const ExtraerInfoComentario = async comentarioId => {
  try {
    // Buscar el comentario por ID y llenar la referencia al usuario
    const comentarioResult = await ComentarioModel.findOne({ _id: comentarioId }).populate({
      path: "idUsuario",
      model: "User",
      select: "nombreCompleto avatar",
    });

    // Verificar si el comentario fue encontrado
    if (!comentarioResult) {
      throw new Error("Comentario no encontrado");
    }

    const comentariosData = {
      id: comentarioResult._id,
      contenido: comentarioResult.contenido,
      time: formatearFecha(comentarioResult.createdAt),
      usuario: {
        id: comentarioResult.idUsuario._id,
        nombre: comentarioResult.idUsuario.nombreCompleto,
        avatar: comentarioResult.idUsuario.avatar,
      },
    };

    return comentariosData;
  } catch (error) {
    console.error(error);
    throw error; // O manejar el error según sea necesario
  }
};


export const agregarLike = async (req, res) => {
  try {
    const { idUser, idPost } = req.body;
    console.log(req.body);

    if (typeof idUser !== "string" || !validator.isMongoId(idUser)) {
      return res.status(400).json({ msg: "ID de usuario inválido." });
    }
    if (typeof idPost!== "string" ||!validator.isMongoId(idPost)){
      return res.status(400).json({ msg: "ID de post inválido." });
    }

    // Buscar el post en la base de datos
    const post = await PostModel.findById(idPost);
    if (!post) {
      return res.status(404).json({ msg: "El post no existe" });
    }

    // Verificar si el usuario ya ha dado like al post
    if (post.likesUsuarios.includes(idUser)) {
      // El usuario ya ha dado like, entonces se elimina el like
      post.megusta--;
      post.likesUsuarios.pull(idUser);
      await post.save();
      return res.status(200).json({ msg: "Like eliminado correctamente" });
    } else {
      // El usuario no ha dado like, entonces se agrega el like
      post.megusta++;
      post.likesUsuarios.push(idUser);
      await post.save();
      return res.status(200).json({ msg: "Like agregado correctamente" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Hubo un error al procesar la solicitud" });
  }
};
