require('./utils.js');
require('dotenv').config(); 
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const saltRounds = 12;

const app = express();

const Joi = require("joi");
const mongoSanitizer = require('mongo-sanitizer').default;


const PORT = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000; //expires after 1 hour  (minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

const {database} = include('databaseConnection');
const userCollection = database.db(mongodb_user_database).collection('users');

app.use(express.urlencoded({extended: false}));
app.use(express.json());

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
	crypto: {
		secret: mongodb_session_secret
	}
});

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req, res) => {
    if(!req.session.authenticated) {
        let html = `
        <form action="/signup">
        <button type="submit">Sign up</button>
        </form>
        <form action="/login">
        <button type="submit">Log in</button>
        </form>
        `;
        res.send(html);
    }
    else {
        let html = `
        <p>Hello, ${req.session.user}</p>
        <form action="/members">
        <button type="submit">Go to Members Area</button>
        </form>
        <form action="/logout">
        <button type="submit">Logout</button>
        </form>
        `;
        res.send(html)
    }
})

app.get('/signup', (req, res) => {
    let html = `
    <form action="/signupSubmit" method='POST'>
    <input name='name' type='text' placeholder='name'></input><br>
    <input name='email' type='email' placeholder='email'></input><br>
    <input name='password' type='password' placeholder='password'></input><br>
    <button type="submit">Submit</button>
    </form>
    `;
    res.send(html);
})

app.post('/signupSubmit', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    if (!name) {
        res.send(`<p>Please provide a name.</p><a href='/signup'>Try again</a>`);
        return;
    }
    if (!email) {
        res.send(`<p>Please provide an email address.</p><a href='/signup'>Try again</a>`);
        return;
    }
    if (!password) {
        res.send(`<p>Please provide a password.</p><a href='/signup'>Try again</a>`);
        return;
    }

	const schema = Joi.object(
		{
			name: Joi.string().alphanum().max(20).required(),
			email: Joi.string().email().max(40).required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({name, email, password});
	if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({name: name, email: email, password: hashedPassword});
	console.log("Inserted user");

    req.session.authenticated = true;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
})

app.get('/login', (req, res) => {
    let html = `
    <form action="/loginSubmit" method='POST'>
    <input name='email' type='email' placeholder='email'></input><br>
    <input name='password' type='password' placeholder='password'></input><br>
    <button type="submit">Submit</button>
    </form>
    `;
    res.send(html);
    
})

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().email().max(40).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
        console.log(validationResult.error);
		res.send("<p>Invalid email.</p><a href='/login'>Try again</a>");
        return;
	}

	const result = await userCollection.find({email: email}).project({name: 1, email: 1, password: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.send("<p>Invalid email.</p><a href='/login'>Try again</a>");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.name = result[0].name;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	}
	else {
		console.log("incorrect password");
		res.send("<p>Invalid email/password combination.</p><a href='/login'>Try again</a>");
		return;
	}
})

app.get('/members', (req, res) => {
    if (req.session.authenticated) {
        let max = 3;
        let randomInt = Math.floor(Math.random() * max); 
        let imgUrl;
        if (randomInt == 0) {
            imgUrl = '/bulbasaur.png';
        }
        else if (randomInt == 1) {
            imgUrl = '/charmander.png';
        }
        else if (randomInt == 2) {
            imgUrl = '/squirtle.png';
        }
        let html = `
        <h1>Hello, ${req.session.name}</h1>
        <img src='${imgUrl}' alt='img' />
        <form action="/logout">
        <button type="submit">Sign out</button>
        </form>
        `;
        res.send(html);
        return;
    }
    res.redirect('/');
})

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});


app.use(express.static(__dirname + "/public"));

app.use((req,res) => {
	res.status(404);
	res.send("Page not found - 404");
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});