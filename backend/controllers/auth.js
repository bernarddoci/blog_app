const { validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const User = require('../models/user');
const errHandler = require('../utils/errorHandler');

exports.signup = async (req, res, next) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        const error = new Error('Validation failes.');
        error.statusCode = 422;
        error.data = errors.array();
        throw error;
    };

    const { email, name, password } = req.body;
    try{
        const hashedPw = await bcrypt.hash(password, 12)
        const user = new User({
            email,
            password: hashedPw,
            name
        })
        const result = await user.save();
        res.status(201).json({ message: 'User created!', userId: result._id })
    } catch(err) {
        errHandler(err, next);
    }
    
};

exports.login = async (req, res, next) => {
    const { email, password } = req.body;
    try{
        const user = await User.findOne({ email })
        if(!user) {
            const error = new Error('A user with this email could not be found.');
            error.statusCode = 401;
            throw error;
        }
        const isEqual = await bcrypt.compare(password, user.password)
        if(!isEqual) {
            const error = new Error('Wrong password!');
            error.statusCode = 401;
            throw error;
        }
        const token = jwt.sign(
            {
                email: user.email,
                userId: user._id.toString()
            }, 
            'somesupersecretkey', 
            { expiresIn: '1h' }
        );
        res.status(200).json({token: token, userId: user._id.toString()});
    } catch(err) {
        errHandler(err, next)
    }
}

exports.getUserStatus = async (req, res, next) => {
    try{
        const user = await User.findById(req.userId)
        if(!user) {
            const error = new Error('User not found.');
            error.stausCode = 404;
            throw error;
        }
        res.status(200).json({status: user.status});
    } catch(err) {
        errHandler(err, next)
    }
}

exports.updateUserStatus = async (req, res, next) => {
    const newStatus = req.body.status;
    try {
        const user = await User.findByIdAndUpdate(req.userId, {status: newStatus}, {useFindAndModify: false})
        if(!user) {
            const error = new Error('User not found.');
            error.stausCode = 404;
            throw error;
        }
        res.status(200).json({message: 'User updated.'});
    } catch (err) {
        errHandler(err, next)
    }
}