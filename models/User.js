const mongoose = require('mongoose');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { stringify } = require('querystring');

const userSchema = new mongoose.Schema({
    firstname: {
        type: String,
        default: "Nombre no señalado",
        trim: true,
        lowercase: true
    },
    lastname: {
        type: String,
        default: "Apellido no señalado",
        trim: true,
        lowercase: true
    },
    email: {
        type: String,
        match: [/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/],
        required: true
    },
    age: {
        type: Number,
        min: 16,
        max: 90
    },
    favoriteProducts: [
        {
            type: mongoose.Types.ObjectId,
            ref: 'product' 
        }
    ],
    password: {
        type: String,
        match: [/^(?=.*\d)(?=.*[a-z])(?=.*[a-zA-Z]).{8,}$/gm],
        required: true
    },
    salt: {
        type: String,
        required: true
    },
    isAdmin: {
        type: Boolean,
        required: true,
        default: false
    },
    image: {
        type: String,
        default: "https://images.unsplash.com/photo-1472099645785-5658abf4ff4e?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxzZWFyY2h8M3x8ZGVmYXVsdCUyMHVzZXJ8ZW58MHx8MHx8&auto=format&fit=crop&w=500&q=60"
    }
})

userSchema.methods.hashPassword = function(password){
    this.salt = crypto.randomBytes(10).toString('hex')
    this.password = crypto.pbkdf2Sync(password, this.salt, 5000, 20, 'sha512').toString('hex')
}

userSchema.methods.hashValidation = function(password, salt, passwordDB) {
    const hash = crypto.pbkdf2Sync(password, salt, 5000, 20, 'sha512').toString('hex');
    return hash === passwordDB;
}

userSchema.methods.generateToken = function() {

    const payload = {
        id: this._id,
        email: this.email
    }

    const token = jwt.sign(payload, process.env.SECRET, {expiresIn: 360000});
    return token;
}


const User = mongoose.model('user', userSchema);

module.exports = User;
