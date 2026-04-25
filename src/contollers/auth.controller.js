const userModel = require("../models/user.model")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")

/**
 * @name registerUserController
 * @description Handles the registration of a new user by validating input,
 * checking for existing accounts, securely hashing the password,
 * and issuing a JWT token upon successful creation.
 * @access Public
 */

async function registerUserController(req, res) {
    try {
        const { username, email, password } = req.body

        if (!username || !email || !password) {
            return res.status(400).json({
                message: "All required fields (username, email, and password) must be provided."
            })
        }

        if (password.length < 6) {
            return res.status(400).json({
                message: "Password must contain at least 6 characters."
            })
        }

        const emailRegex = /^\S+@\S+\.\S+$/
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                message: "The provided email address is not in a valid format."
            })
        }

        const isUserAlreadyExists = await userModel.findOne({
            $or: [{ username }, { email }]
        })

        if (isUserAlreadyExists) {
            return res.status(400).json({
                message: "An account with the given username or email already exists."
            })
        }

        const hash = await bcrypt.hash(password, 10)

        const user = await userModel.create({
            username,
            email,
            password: hash
        })

        const token = jwt.sign(
            { id: user._id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: "1d" }
        )

        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "Strict" : "Lax"
        })
        return res.status(201).json({
            message: "User registration completed successfully.",
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            }
        })

    } catch (error) {
        console.error("Registration Error:", error)
        return res.status(500).json({
            message: "An unexpected error occurred while processing the request."
        })
    }
}

module.exports = {
    registerUserController
}