const Product = require('../models/Product');
const User = require('../models/User');



//Publico

const getProducts = async(req, res) => {
    try {
        const products =  await Product.find()

        res.json({success: true, msg: "Lista de productos", info: products})
    } catch (error) {
       res.status(500).json({success: false, msg: "hubo un error en obteniendo los datos"}) 
    }
}

const getProductById = async(req,res) => {

    const { productId } = req.params

    try {
        const product = await Product.findById(productId);

        res.json({success: true, msg: "Producto obtenido", info: product})
    } catch (error) {
        res.status(500).json({success: false, msg: "hubo un error en obteniendo los datos"}) 
    }
}

//Admin

const createProduct = async(req, res) => {
    try {
        const user = await User.findById(req.auth.id)
        console.log(user.isAdmin)
        if(!user.isAdmin){
            throw new Error('No tienes acceso para crear productos!')
        }

        const newProduct = new Product(req.body);
        await newProduct.save();
        
        res.json({success: true, message: "Se ha creado un nuevo producto", productId: newProduct._id })
    } catch (error) {
        res.json({success: false, message: error.message})
    }
}

const editProduct = async(req, res) => {

        const {name, price, brand, image, stock, color} = req.body;
        const {productId} = req.params;

    try {
        
        const edit = await Product.findByIdAndUpdate(productId, {name, price, brand, image, stock, color}, {new: true})
        
        res.json({success: true, msg: "Producto Actualizado!!!", update: edit})

    } catch (error) {
        res.status(500).json({success: false, msg: "hubo un error actualizando el producto"})
    }
}

const deleteProduct = async(req, res) => {

    const {productId} = req.params;

try {
    
    const destroyed = await Product.findByIdAndDelete(productId)
    
    res.json({success: true, msg: "Producto Elimiando!!!", delete: destroyed})

} catch (error) {
    res.status(500).json({success: false, msg: "hubo un error eliminando el producto"})
}
}


const reduceStock = async(req, res) => {
    const purchasedProducts = req.body.cartItems;
    try {
        purchasedProducts.map(async(purchasedProduct) => {
            await Product.findByIdAndUpdate(purchasedProduct._id, {stock: purchasedProduct.stock - purchasedProduct.quantity})
        })

        res.json({success: true, msg: 'stock reduced' })
    } catch (error) {
        res.status(500).json({success: false, msg: "hubo un error"})
    }
}

module.exports = {createProduct, editProduct, deleteProduct, getProductById, getProducts, reduceStock};