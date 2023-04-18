# Que se hizo en la clase?

1) Instalar librerias de npm i express mongoose cors joi dotenv(ok)
2)Levantamos un servidor(ok)
3) agregamos el script start al package.json(ok)
4) agregamos cors y dotenv(ok)
5) conectamos mongo atlas (coonect drivers o connect app)(ok)
6) creamos la carpeta config e importamos mongoose(ok)
7) Creamos el archivo .env en el directorio principal de nuestro proyecto y colocamos la url que copiamos en atlas(ok)
8) Acordarse de colocar el nombre de la base de datos en la url de atlas(ok)
9) luego importamos nuestra database.js en el servidos(index.js)(ok)
10) creamos una ruta y su controlador, y las instanciamos en el servidor(ok)
12) creamos el models Users.js(ok)
13) Importamos el modelo en nuestro controllador(ok)
14) usamos thunderclient o postman y agregamos en el body (Post)lo del modelo(ok)
15) modificamos el create , para que pueda guardar la informacion (ok)del usuario en nuestra base de datos, ojo mongo agrega un id al objeto creado con la propiedad _id: 
16) Usamos postman o thunder y creamos el usuario, verificamos en atlas su creacion(ok)
17) Creamos ahora la obtencion para todos los usuarios creados(ok)
18) modifciamos el modelo agregando el type y el requires, explicaion de esto mas a fondo(ok)
19) explicar documentacion de mongoose, sus propiedades(ok)
20) explicar el error que sucede en el body que puedo enviar cualquier cosa en el, con respecto a un model establecido(ok)
21) Crear un delete para usuarios(ok)
22)Crear un update para usuarios(ok)
23) Añadir Models de productos con favoriteProduct en el modelo de usuarios : {type: mongoose.objectID}
24) al momento de obtener la informacion en usuarios agregar Populate, explicar populate
25) Ejercicio: Empezar a desarrollar su modelo pàra el Ecommerce

