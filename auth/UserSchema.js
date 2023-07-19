var mongoose = require('mongoose');

var UserSchema = new mongoose.Schema({
    name:String,
    email:String,
    password:String,
    phone:String,
    role:String
})

mongoose.model('login',UserSchema)
module.exports = mongoose.model('login')