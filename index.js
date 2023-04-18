const express = require('express')
//* Cors nos permite hacer solicitudes entre dominios, ejemplo una peticion fetch a nuestro backend
const cors = require('cors');
const userRouter = require('./Routes/userRoutes');
const productRouter = require('./Routes/productRoutes');

//Variables de entorno

require('dotenv').config();
require('./Config/database');


const app = express();

// const whiteList = ["https//localhost:3000"]
// esto va en cors{origin: whiteList}
//* middleware 

app.use(cors())
//* mi sevidor entienda json
app.use(express.json())

app.use(userRouter)
app.use(productRouter)


const puerto = process.env.PORT; 

app.listen(puerto, () => console.log(`Conectado en puerto ${puerto}!`) )