require('dotenv').config();
require("./utils.js");
const path = require('path');  // Add this line to work with paths


const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); // Set the path for views
const Joi = require("joi");


const expireTime = 60 * 60 * 1000; //expires after 1 hour

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));


app.use(session({
    secret: node_session_secret,
    store: MongoStore.create({
        mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/users`,
        crypto: {
            secret: mongodb_session_secret
        }
    }), // Create mongoStore here
    saveUninitialized: false,
    resave: true
}));

app.use((req, res, next) => {
    try {
        res.locals.user = req.session.user || {};
    } catch (err) {
        console.error("Error setting res.locals.user:", err);
        res.locals.user = {}; // Set to an empty object on error
    }
    next();
});


app.get('/', (req, res) => {
    res.render('index', {
        // Pass the entire user object
        authenticated: req.session.authenticated,
        user: res.locals.user,  // This includes username, userType, etc.
    });
});

app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error) {
        console.log(validationResult.error);
        return res.render('error', { message: "NoSQL Injection Detected" });
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

// Signup Route (GET)
app.get('/signup', (req, res) => {
    res.render('signup', { error: null }); // Pass error = null initially
});

// Login Route (GET)
app.get('/login', (req, res) => {
    res.render('login', { error: req.query.error }); // Include error handling
});

app.post('/submitUser', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ username, password, email });

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render("signup", { error: validationResult.error.details[0].message }); // Render signup.ejs WITH the error message from Joi
        return;
    }
    const existingUser = await userCollection.findOne({ email });
    if (existingUser) {
        // Render signup.ejs with an error message
        return res.render('signup', { error: 'Error: Email already in use.' });
    }


    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        username: username,
        password: hashedPassword,
        email: email,
        userType: 'user' // Add userType: user
    });
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.user = {
        username: username,
        userType: "user",
        _id: new ObjectId()
    };
    req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
});

app.post('/loggingin', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate input using Joi
        const schema = Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().required(),
        });
        const validationResult = schema.validate({ email, password });
        if (validationResult.error) {
            return res.render('login', { error: "Invalid email or password." });
        }

        const user = await userCollection.findOne({ email: email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.render('login', { error: "Incorrect email or password." });
        }

        // Successful login
        req.session.authenticated = true;
        req.session.user = {  // Set complete user object in session
            username: user.username,
            userType: user.userType || "user", // Default to 'user'
            _id: user._id
        };
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');

    } catch (err) {
        console.error("Error in login:", err);
        res.status(500).render('error', { message: "Internal Server Error" });
    }
});


app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
    return;
});


app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    const images = [
        { id: 1, src: '/gandalf.jpg', name: 'Gandalf' },
        { id: 2, src: '/hermoine.jpg', name: 'Hermoine' },
        { id: 3, src: '/merlin.jpg', name: 'Merlin' }
    ];
    res.render('members', { user: req.session.user, images: images });
});

const isAdmin = (req, res, next) => {
    if (req.session.authenticated && req.session.user.userType === "admin") {
        next(); // User is an admin, proceed to the route
    } else {
        // Not authorized
        if (!req.session.authenticated) { // User is not logged in
            res.redirect('/login'); // Redirect to login with error message
        } else { // User is logged in but not an admin
            res.status(403).render('admin', {
                users: [],
                error: "Forbidden (403): You are not authorized to access this page."
            });
        }
    }
};
app.get('/admin', isAdmin, async (req, res) => {
    try {
        const users = await userCollection.find({}).toArray();
        res.render('admin', { users, error: null }); // Pass error = null
    } catch (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
    }
});

// Promote Route
app.get('/promote/:userId', isAdmin, async (req, res) => { //isAdmin middleware
    try {
        const userId = req.params.userId;

        await userCollection.updateOne(
            { _id: new ObjectId(userId) },
            { $set: { userType: 'admin' } }
        );

        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
    }
});

// Demote Route
app.get('/demote/:userId', isAdmin, async (req, res) => {
    try {
        const userId = req.params.userId;

        await userCollection.updateOne(
            { _id: new ObjectId(userId) },
            { $set: { userType: 'user' } }
        );

        res.redirect('/admin');
    } catch (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
    }
});


app.use(express.static(__dirname + "/public"));


app.get('*', (req, res) => {
    res.status(404);
    res.render('404');  // Render the 404.ejs template
});
app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 