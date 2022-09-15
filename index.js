// IMPORTS
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken")
require("dotenv").config()


// INIT EXPRESS & ENABLE BODY PARSER
const app = express();

app.use(express.urlencoded({extended: true}));
app.use(express.json());


// MONGOOSE SETTINGS
mongoose.connect(process.env.MONGO_URI);

// USER SCHEMA
const userSchema = new mongoose.Schema({
    f_name: String,
    l_name: String,
    email: String,
    password: String,
    sessions: [String],
    profile: {
       address: String,
       salary: String
    }
});

// HASHING MIDDLEWARE
SALT_WORK_FACTOR = 10;
userSchema.pre('save', function(next) {
    var user = this;

    if (!user.isModified('password')) return next();

    bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt) {
        if (err) return next(err);

        bcrypt.hash(user.password, salt, function(err, hash) {
            if (err) return next(err);
            user.password = hash;
            next();
        });
    });
});
 
// METHOD TO COMAPRE HASH
userSchema.methods.comparePassword = function(candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch);
    });
};

// CREATE USER MODEL FROM SCHEMA
const User = mongoose.model("User", userSchema);


// HELPER FUNCTIONS FOR JWTs
function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: "15m"});
}
function generateRefreshToken(user, usedToken=undefined) {
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, {expiresIn: "120m"});

    User.findOne({email: user['user']}, function(err, user) {
        if(err)
            throw err;
        else {
            user['sessions'].push(refreshToken);
            if (usedToken)
                user['sessions'] = user['sessions'].filter( (c) => c != usedToken);
            user.save();
        }
    });

    return refreshToken;
}

// JWT AUTH MIDDLEWARE
function validateToken(req, res, next) {
    const authHeader = req.headers["authorization"]
    if (!authHeader)
        res.status(401).send({'status':'fail','error':'token not present'});
    else
        {
            const token = authHeader.split(" ")[1]
            if (!token)
                res.status(401).send({'status':'fail','error':'token not present'});
            else {
                jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
                    if (err) { 
                        res.status(401).send({'status':'fail','error':'token invalid'});
                    }
                    else {
                        req.user = user;
                        next();
                    }
                });
            }
        }
}


// API ENDPOINTS
app.post("/register/l1", (req, res) => {
    if (req.body['f_name'] === undefined || req.body['l_name'] === undefined || req.body['email'] === undefined || req.body['password'] === undefined) {
        res.status(400).send({'status':'fail','error':'missing inputs'});
    }
    else {
        User.findOne({email: req.body['email']}, function(err, user) {
            if(err) {
                res.status(400).send({'status':'fail','error':'issue with input'});
            }
            else if (!user) {
                const user = new User({f_name: req.body['f_name'], l_name: req.body['l_name'], email: req.body['email'], password: req.body['password'], profile: {address: undefined, salary: undefined}})
                user.save();
                res.status(200).send({'status':'success','desc':'level 1 user registration complete'});
            }
            else {
                if (user['profile']['address'])
                    res.status(403).send({'status':'fail','error':'user has already completed registration'});
                else
                    res.status(403).send({'status':'fail','error':'proceed to l2 registration'});
            }
        });
    }
});

app.post("/register/l2", (req, res) => {
    if (req.body['email'] === undefined || req.body['password'] === undefined || req.body['address'] === undefined || req.body['salary'] === undefined) {
        res.status(400).send({'status':'fail','error':'missing inputs'});
    }
    else {
        User.findOne({email: req.body['email']}, function(err, user) {
            if(err) {
                res.status(400).send({'status':'fail','error':'issue with input'});
            }
            else if (!user) {
                res.status(403).send({'status':'fail','error':'level 1 user registration not yet done'});
            }
            else {
                user.comparePassword(req.body['password'], function(err, isMatch) {
                        if (err) throw err;
                        if (isMatch) {
                            if (user['profile']['address'])
                                res.status(403).send({'status':'fail','error':'user has already completed registration'});
                            else {
                                user['profile']['address'] = req.body['address'];
                                user['profile']['salary'] = req.body['salary'];
                                user.save();
                                res.status(200).send({'status':'success','desc':'level 2 user registration complete'});
                            }
                        }
                        else {
                            res.status(401).send({'status':'fail','error':'password incorrect'});
                        }
                });
            }
        });
    }
});

app.post("/login", (req, res) => {
    if (req.body['email'] === undefined || req.body['password'] === undefined)
        res.status(400).send({'status':'fail','error':'missing inputs'});
    else {
        User.findOne({email: req.body['email']}, function(err, user) {
            if(err) {
                res.status(400).send({'status':'fail','error':'issue with input'});
            }
            else if (!user) {
                res.status(403).send({'status':'fail','error':'level 1 user registration not yet done'});
            }
            else {
                if (user['profile']['address']) {
                    user.comparePassword(req.body['password'], function(err, isMatch) {
                            if (err) throw err;
                            if (isMatch) {
                                if (user['sessions'].length == 2)
                                    res.status(403).send({'status':'fail','error':'only 2 logins are allowed. please logout from one of the devices.'});
                                else {
                                    const accessToken = generateAccessToken({user: req.body['email']});
                                    const refreshToken = generateRefreshToken({user: req.body['email']});
                                    res.send({'accessToken':accessToken, 'refreshToken':refreshToken});
                                }
                            }
                            else {
                                res.status(401).send({'status':'fail','error':'password incorrect'});
                            }
                    });
                }
                else
                    res.status(403).send({'status':'fail','error':'level 2 user registration not done yet'});
            }
        });
    }
});

//REFRESH TOKEN API
app.post("/refreshToken", (req,res) => {
    if (req.body['token'] === undefined)
        res.status(400).send({'status':'fail','error':'missing inputs'});
    else {
        jwt.verify(req.body['token'], process.env.REFRESH_TOKEN_SECRET, (err, user) => {
            if (err) { 
                res.status(401).send({'status':'fail','error':'token invalid'});
             }
             else {
                User.findOne({email: user['user']}, function(err, u) {
                    if(err)
                        throw err;
                    if (!u['sessions'].includes(req.body.token)) {
                        res.status(401).send({'status':'fail','error':'token invalid'});
                    }
                    else {
                        const accessToken = generateAccessToken ({'user': u['email']});
                        const refreshToken = generateRefreshToken ({'user': u['email']}, req.body['token']);

                        res.send({accessToken: accessToken, refreshToken: refreshToken});
                    }
                });
             }
        });
    }
});

app.post('/logout', (req,res) => {
    if (req.body['token'] === undefined)
        res.status(400).send({'status':'fail','error':'missing inputs'});
    else {
        jwt.verify(req.body['token'], process.env.REFRESH_TOKEN_SECRET, (err, user) => {
            if (err) { 
                res.status(401).send({'status':'fail','error':'token invalid'});
             }
             else {
                User.findOne({email: user['user']}, function(err, u) {
                    if(err)
                        throw err;
                    if (!u['sessions'].includes(req.body.token)) {
                        res.status(401).send({'status':'fail','error':'token invalid'});
                    }
                    else {
                        u['sessions'] = u['sessions'].filter( (c) => c != req.body.token);
                        u.save();

                        res.status(200).send({'status':'success', 'desc':'user logged out'});
                    }
                });
             }
        });
    }
});

app.get("/getDetails", validateToken, (req, res) => {
    User.findOne({email: req.user.user}, function(err, user) {
        if(err) {
            res.status(400).send({'status':'fail','error':'issue with input'});
        }
        else if (!user) {
            res.status(403).send({'status':'fail','error':'level 1 user registration not yet done'});
        }
        else {
            if (user['profile']['address'])
                res.status(200).send({'status':'success', 'user':{'f_name':user['f_name'], 'l_name':user['l_name'], 'email':user['email'], 'profile':{'address':user['profile']['address'], 'salary':user['profile']['salary']}}});
            else
                res.status(403).send({'status':'fail','error':'level 2 user registration not done yet'});
        }
    });
});


// START SERVER
const port = process.env.PORT;
app.listen(port, () => {console.log("listening on port "+port)});
