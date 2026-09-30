require("dotenv").config();
const mongoose = require("mongoose");
const express = require("express");
const User = require("./models/User");
const bcrypt = require("bcryptjs");
const session = require("express-session");


const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET || "secure-login-secret",
    resave: false,
    saveUninitialized: false
}));

app.use(express.static("public"));

app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/index.html");
});



// =========================
// REGISTER
// =========================

app.post("/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).send("Email already registered");
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            name,
            email,
            password: hashedPassword
        });

        await user.save();

        res.send("Registration successful");

    } catch (error) {
        console.error(error);
        res.status(500).send("Registration failed");
    }
});


// =========================
// LOGIN
// =========================

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.send("Logged out");
    });
});

app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).send("Invalid email or password");
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).send("Invalid email or password");
        }

        req.session.userId = user._id;
        req.session.userName = user.name;

        res.send("Login successful");

    } catch (error) {
        console.error(error);
        res.status(500).send("Login failed");
    }
});


// =========================
// DASHBOARD
// =========================

app.get("/dashboard", (req, res) => {
    if (!req.session.userId) {
        return res.status(401).send("Unauthorized");
    }

    res.sendFile(__dirname + "/public/dashboard.html");
});


// =========================
// TEST ROUTE
// =========================

app.get("/test", (req, res) => {
    res.send("Secure Login System Backend is Working!");
});


// =========================
// MONGODB CONNECTION
// =========================

mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log("MongoDB connected successfully");
    })
    .catch((err) => {
        console.error("MongoDB connection error:", err);
    });


// =========================
// START SERVER
// =========================

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
 
