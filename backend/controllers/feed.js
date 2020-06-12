const { validationResult } = require('express-validator');
const fs = require('fs');
const path = require('path');

const io = require('../socket');
const Post = require('../models/post');
const User = require('../models/user');

const errHandler = (err, next) => {
    if(!err.statusCode) {
        err.statusCode = 500;
    }
    next(err);
}

exports.getPosts = async (req, res, next) => {
    const currentPage = req.query.page || 1;
    const perPage = 2;
    let totalItems;
    try{
        const totalItems = await Post.find().countDocuments();
        const posts = await Post.find()
            .populate('creator')
            .skip((currentPage - 1) * perPage)
            .sort({ createdAt: -1 })
            .limit(perPage);
        res.status(200)
        .json({
            message: 'Fetched posts successfully.', 
            posts, 
            totalItems
        })
    } catch(err) {
        errHandler(err, next);
    }
    
};

exports.createPost = async (req, res, next) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        const error = new Error('Validation Failed, entered data is incorrect.')
        error.statusCode = 422;
        throw error;
    }
    if(!req.file) {
        const error = new Error('No image provided.');
        error.statusCode = 422;
        throw error;
    }
    const { title, content } = req.body;
    const imageUrl = req.file.path.replace("\\" ,"/");
    const post = new Post({
        title, 
        content,
        imageUrl,
        creator: req.userId,
    });
    try{
        await post.save();
        const user = await User.findById(req.userId);
        user.posts.push(post);
        await user.save();
        io.getIO().emit('posts', { 
            action: 'create', 
            post: {...post._doc, creator: { _id: req.userId, name: user.name }} 
        });
        res.status(201).json({
            message: 'Post created successfully!',
            post,
            creator: {_id: user._id, name: user.name}
        })
    } catch(err) {
        errHandler(err, next);
    }
};

exports.getPost = async (req, res, next) => {
    const postId = req.params.postId;
    try{
        const post = await Post.findById(postId)
        if(!post) {
            const error = new Error('Could not find post.');
            error.statusCode = 404;
            throw error;
        }
        res.status(200).json({message: 'Post fetched.', post})
    } catch (err) {
        errHandler(err, next);
    }
}

exports.updatePost = async (req, res, next) => {
    const postId = req.params.postId;
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        const error = new Error('Validation Failed, entered data is incorrect.')
        error.statusCode = 422;
        throw error;
    }

    const { title, content } = req.body;
    let imageUrl = req.body.image;
    if(req.file) {
        imageUrl = req.file.path.replace("\\" ,"/");
    }
    if(!imageUrl) {
        const error = new Error('No file picked.');
        error.statusCode = 422;
        throw error;
    }

    try{
        const post = await Post.findById(postId).populate('creator');
        if(!post) {
            const error = new Error('Could not find post.');
            error.statusCode = 404;
            throw error;
        }
        // Check logedin user
        if(post.creator._id.toString() !== req.userId) {
            const error = new Error('Not authorized!');
            error.statusCode = 403;
            throw error;
        }
        // If image has changed, delete previous one and add new one...
        if(imageUrl !== post.imageUrl) {
            clearImage(post.imageUrl);
        }
        post.title = title;
        post.imageUrl = imageUrl;
        post.content = content; 
        const result = await post.save();
        io.getIO().emit('posts', { action: 'update', post: result });
        res.status(200).json({message: 'Post updated!', post: result});
    } catch(err) {
        errHandler(err, next)
    }
    
}

exports.deletePost = async (req, res, next) => {
    const postId = req.params.postId;
    try{
        const post = await Post.findById(postId)
        if(!post) {
            const error = new Error('Could not find post.');
            error.statusCode = 404;
            throw error;
        }
        if(post.creator.toString() !== req.userId) {
            const error = new Error('Not authorized!');
            error.statusCode = 403;
            throw error;
        }

        clearImage(post.imageUrl);
        await Post.findByIdAndRemove(postId);

        const user = await User.findById(req.userId);
        user.posts.pull(postId);
        await user.save();
        io.getIO().emit('posts', { action: 'delete', post: postId});
        res.status(200).json({message: 'Deleted post.'});
    } catch(err) {
        errHandler(err, next)
    }
    
}

const clearImage = filePath => {
    filePath = path.join(__dirname, '..', filePath);
    fs.unlink(filePath, err => console.log(err));
}