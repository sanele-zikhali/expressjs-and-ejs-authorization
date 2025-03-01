const jwt = require("jsonwebtoken")
require("dotenv").config()
const express = require('express');
const bcrypt = require('bcrypt');
const app = express();
const db = require("better-sqlite3")("authApp.db")
db.pragma("jornal_mode=WAL")

// Database Setup
const createTables = db.transaction(()=>{
    db.prepare(
        `CREATE TABLE IF NOT EXISTS users (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Username STRING NOT NULL Unique,
            Password STRING NOT NULL
        )`
    ).run()
})

createTables()

app.set("view engine", "ejs")
app.use(express.urlencoded({extended:false}))
app.use(express.static("public"))

app.use(function(req, res, next){
    res.locals.errors = []

    // Decode Web Token
    try{
        const decoded = jwt.decode(req.cookies.authApp, process.env.JWTSECRET)
        req.user = decoded
    }catch(err){
        req.user = false
    }

    res.locals.user = req.user

    next()
})

app.get("", (req, res)=>{
    res.render("index")
})

app.get("/login", (req, res)=>{
    res.render("login")
})

app.post("/register", (req, res)=>{
    if(typeof req.body.username !== "string") req.body.username = ""
    if(typeof req.body.password !== "string") req.body.password = ""

    const errors = []

    req.body.username = req.body.username.trim() 
    if(!req.body.username) errors.push("You must provide a username.")
    if(req.body.username && req.body.username.length < 3) errors.push("Username must be at least 3 characters.")
    if(req.body.username && req.body.username.length > 10) errors.push("Username cannot exceed 10 characters.")
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain numbers.")

    if(!req.body.password) errors.push("You must provide a password.")
    if(req.body.password && req.body.password.length < 8) errors.push("Password must be at least 8 characters.")
    if(req.body.password && req.body.password.length > 20) errors.push("Password cannot exceed 20 characters.")


    if(errors.length){
        res.render("index", {errors})
    }

    // Save User Data
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)

    const saveStatement = db.prepare("INSERT INTO users (Username, Password) VALUES (?,?)")
    const results = saveStatement.run(req.body.username, req.body.password)

    const lookupSatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const currentUser =  lookupSatement.get(results.lastInsertRowid)


    // Login User
    const secretToken = jwt.sign({
        userId: currentUser.Id,
        exp: Math.floor(Date.now() / 1000 ) + 60 * 60 * 24
    } 
    ,process.env.JWTSECRET)

    res.cookie("authApp", secretToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24 
    })

    res.redirect("/success")
})

app.get("/success", (req, res)=>{
    res.render("success")
})

app.get("/users", (req, res)=>{

})

app.listen(3000)