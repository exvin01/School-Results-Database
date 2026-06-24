const express = require('express');
const path = require('path');
const {MongoClient} = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Parse form data + JSON + serve static files
app.use(express.static(__dirname));
app.use(express.json());
app.use(express.urlencoded({extended: true})); // fixed: extended not extends

// MongoDB connection
const uri = process.env.MONGODB_URI;
let client;
let db;

async function connectDB() {
    if(!db){
        client = new MongoClient(uri);
        await client.connect();
        db = client.db('SchoolData'); // fixed:.db() not.connect()
        console.log('Connected to MongoDB');
    }
    return db;
}

// SIGNUP
app.post('/signup', async(req, res) =>{
    try {
        const {stdnumber, stdname, stdpass} = req.body;

        if(!stdnumber ||!stdname ||!stdpass){
            return res.status(400).send('All fields required');
        }

        const database = await connectDB();
        const collection = database.collection('stdinfo');

        const userExist = await collection.findOne({stdnumber});
        if(userExist){
            return res.sendFile(path.join(__dirname, 'reject.html'));
        }

        const hashedPassword = await bcrypt.hash(stdpass, 10);

        await collection.insertOne({
            stdnumber,
            stdname,
            stdpass: hashedPassword,
            createdAt: new Date().toLocaleString('en-CA', {timeZone: 'Africa/Blantyre'}),
            ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress
        });

        // Redirect to succes page after sign up success 
        res.sendFile(path.join(__dirname, 'success.html'));
    } catch (err) {
        console.error(err);
        res.status(500).send('Error: signup failed');
    }
});

// TEACHER: Insert results
app.post('/results', async(req, res) =>{
    try {
        const {stdnumber, fullname, Class, maths, english, total, position, outof} = req.body;

        const database = await connectDB();
        const collection = database.collection('stdresults');

        // Optional: prevent duplicate entry for same student + term
        const userExist = await collection.findOne({stdnumber});
        if(userExist){
            return res.sendFile(path.join(__dirname, 'reject.html'));
        }

        await collection.insertOne({
            stdnumber,
            fullname,
            Class,
            maths: Number(maths),
            english: Number(english),
            total: Number(total),
            position: Number(position),
            outof: Number(outof),
            createdAt: new Date().toLocaleString('en-CA', {timeZone: 'Africa/Blantyre'}),
            ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress
        });

        res.send('<h2>Results saved successfully!</h2><a href="/teachers.html">Add more</a>');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error: saving results failed');
    }
});

// LOGIN
app.post('/login', async(req, res) =>{
    try {
        const {stdnumber, stdpass} = req.body;

        const database = await connectDB();
        const collection = database.collection('stdinfo');

        const userExist = await collection.findOne({stdnumber});
        if(!userExist){
            return res.sendFile(path.join(__dirname, 'reject.html'));
        }

        const validpassword = await bcrypt.compare(stdpass, userExist.stdpass);
        if(!validpassword){
            return res.sendFile(path.join(__dirname, 'reject.html'));
        }

        // Create JWT token
        const token = jwt.sign(
            {id: userExist._id, stdnumber: userExist.stdnumber, name: userExist.stdname},
            process.env.JWT_SECRET, 
            {expiresIn: '7d'}
        );

        // Send token + redirect to dashboard
        res.json({success: true, token, name: userExist.stdname});
    } catch (err) {
        console.error(err);
        res.status(500).json({success: false, message: err.message});
    }
});

// PROTECTED: Get results
app.get('/output', async(req, res) =>{
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if(!token)
            return res.status(401).json({success: false, message: 'No token'});

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const database = await connectDB();

        const collection = database.collection('stdresults');
        const stdresults = await collection.find({stdnumber: decoded.stdnumber}).toArray(); // fixed: await + variable name

        if(stdresults.length === 0){
            return res.json({success: false, message: 'No results found for this student'});
        }

        res.json({success: true, stdresults, name: decoded.name});
    } catch (err) {
        console.error(err);
        res.status(401).json({success: false, message: 'Invalid token'})
    }
});

// Routes for pages
app.get('/', (req, res) =>{
    res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/signup',(req, res) =>{
    res.sendFile(path.join(__dirname, 'signup.html'));
});
app.get('/dashboard',(req, res) =>{
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

module.exports = app;