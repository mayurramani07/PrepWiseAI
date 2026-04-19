const mongoose = require("mongoose")

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        unique: [true, "username already take"],
        required: true,
    },

    email : {
        type: String,
        unique: [true, "Account already exist"],
        required: true,
    },

    password: {
        type: String,
        required: true
    }

})

const userModel = mongoose.model("users", userSchema)

module.exports = userModel