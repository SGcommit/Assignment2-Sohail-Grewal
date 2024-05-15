require('dotenv').config();
require("./utils.js");
const path = require('path');  // Add this line to work with paths
app.set('view engine', 'ejs'); 
app.set('views', path.join(__dirname, 'views')); // Set the path for views

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

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

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/users`,
    // mongoUrl: `mongodb+srv://<span class="math-inline">\{mongodb\_user\}\:</span>{mongodb_password}@<span class="math-inline">\{mongodb\_host\}/</span>{mongodb_database}?retryWrites=true&w=majority`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

// app.get('/', (req, res) => {
//     if (req.session.authenticated) {
//         res.send(`
//         <h1>Hello, ${req.session.username}</h1> 
//         <a href="/members">Members Area</a>
//         <a href="/logout">Logout</a>
//       `);
//     } else {
//         res.send(`
//         <h1>Welcome!</h1>
//         <a href="/createUser">Sign Up</a>
//         <a href="/login">Login</a>
//       `);
//     }
// });

app.get('/', (req, res) => {
    res.render('index', { 
      authenticated: req.session.authenticated, 
      username: req.session.username
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
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req, res) => {
    var color = req.query.color;

    res.send("<h1 style='color:" + color + ";'>Sohail Grewal</h1>");
});

app.get('/contact', (req, res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req, res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: " + email);
    }
});


app.get('/createUser', (req, res) => {
    var html = `
    <h1>create user</h1>
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'></br>
    <input name='email' type='text' placeholder='email'></br>
    <input name='password' type='password' placeholder='password'></br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.get('/login', (req, res) => {
    var html = `
    <h1>log in</h1>
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'></br>
    <input name='password' type='password' placeholder='password'></br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
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
    // if (validationResult.error != null) {
    //     console.log(validationResult.error);
    //     res.redirect("/createUser");
    //     return;
    // }
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render("signup"); // Render the signup.ejs template
        return;
    }
    const existingUser = await userCollection.findOne({ email }); 

    if (existingUser) {
      res.send(`<h1>Error: Email already in use</h1> <a href="/createUser">Go Back</a>`); 
      return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, password: hashedPassword, email: email });
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/loggedIn');
});

app.post('/loggingin', async (req, res) => {
    var password = req.body.password;
    var username = req.body.username;
    var email = req.body.email;

    const schema = Joi.string().email().required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ email: 1, username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        res.redirect("/login");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = result[0].username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/loggedIn');
        return;
    }
    else {
        let loginFormHtml = `
        <h1>Log In</h1>
        <form action='/loggingin' method='post'>
          <input name='email' type='email' placeholder='email'> </br>
          <input name='password' type='password' placeholder='password'>
          <p style="color: red;">Incorrect email or password</p> 
          <button>Submit</button>
        </form>
      `;
      res.send(loginFormHtml);

        return;
    }
});

app.get('/loggedin', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }

    res.redirect('/members');
    return;
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
    return;
});


// app.get('/members', (req, res) => {
//     if (!req.session.authenticated) {
//         res.redirect('/');
//         return;
//     }

//     const images = [
//         { id: 1, src: '/gandalf.jpg', name: 'Gandalf' },
//         { id: 2, src: '/hermoine.jpg', name: 'Hermoine' },
//         { id: 3, src: '/merlin.jpg', name: 'Merlin'}
//     ];

//     const randomIndex = Math.floor(Math.random() * images.length);
//     const selected = images[randomIndex];

//     res.send(`
//     <h1>Hello, ${req.session.username}</h1> 
//     <h2>Members Only Area</h2>
//     <h3>Your Random Wizard: ${selected.name}</h3>
//     <img src="${selected.src}" width="250px">
//     <h3><a href="/logout">Logout</a></h3>
//   `);
// });
app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    const images = [
        { id: 1, src: '/gandalf.jpg', name: 'Gandalf' },
        { id: 2, src: '/hermoine.jpg', name: 'Hermoine' },
        { id: 3, src: '/merlin.jpg', name: 'Merlin'}
    ];
    res.render('members', { images, username: req.session.username }); 
});

const isAdmin = (req, res, next) => {
    function isAdmin(req, res, next) {
        if (req.session.authenticated && req.session.userType === "admin") {
          next(); // User is admin, proceed to the /admin route
        } else {
          if (req.session.authenticated) {
            // Authenticated but not admin
            res.status(403).send("Forbidden: You are not authorized to access this page.");
          } else {
            // Not authenticated
            res.redirect("/login"); 
          }
        }
      }
};

app.get('/admin', isAdmin, async (req, res) => { // use middleware 
    try {
      const users = await userCollection.find({}).toArray();
      res.render('admin', { users }); // Render admin.ejs template
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

// app.get("*", (req, res) => {
//     res.status(404);
//     res.send("<h3>Page not found - 404</h3>");
// })
app.get('*', (req, res) => {
    res.status(404);
    res.render('404');  // Render the 404.ejs template
});
app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 