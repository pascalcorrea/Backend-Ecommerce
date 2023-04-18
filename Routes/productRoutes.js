const express = require('express');
const {createProduct, deleteProduct, editProduct, getProductById, getProducts, reduceStock} = require('../controllers/product.controller')
const auth = require('../Middlewares/auth')

const productRouter = express.Router();

productRouter.route('/products')
    .post(auth, createProduct)
    .get(getProducts)

productRouter.route('/products/:productId')
    .get(getProductById)
    
productRouter.route('/products/reduce')
    .put(reduceStock)
productRouter.route('/admin/products/:productId')
    .put(editProduct)
    .delete(auth, deleteProduct)

module.exports = productRouter
