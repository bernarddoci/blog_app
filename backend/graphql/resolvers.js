const bcrypt = require('bcryptjs');
const validator = require('validator');
const jwt = require('jsonwebtoken');

const User = require('../models/user');
const Post = require('../models/post');
const { clearImage } = require('../utils/file');

const isAuthUser = req => {
    if(!req.isAuth) {
        const error = new Error('Not authenticated!');
        error.code = 401;
        throw error;
    }
}

module.exports = {
    createUser: async function ({ userInput }, req) {
        const { email, name, password } = userInput;
        const errors = [];
        if (!validator.isEmail(email)) {
            errors.push({ message: 'E-Mail is invalid.' });
        }
        if (
            validator.isEmpty(password) ||
            !validator.isLength(password, { min: 5 })
        ) {
            errors.push({ message: 'Password too short!' });
        }
        if (errors.length > 0) {
            const error = new Error('Invalid input.');
            error.data = errors;
            error.code = 422;
            throw error;
        }
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            const error = new Error('User exists already!');
            throw error;
        }
        const hashedPw = await bcrypt.hash(password, 12);
        const user = new User({
            email,
            name,
            password: hashedPw
        });
        const createdUser = await user.save();
        // Return user wihtout mongoose meta data and convert user id to string so it won't fail with gql.
        return { ...createdUser._doc, _id: createdUser._id.toString() };
    },
    login: async function({email, password}) {
        const user = await User.findOne({email});
        if(!user) {
            const error = new Error('User not found.');
            error.code = 401;
            throw error;
        }
        const isEqual = await bcrypt.compare(password, user.password);
        if(!isEqual) {
            const error = new Error('Password is incorrect.');
            error.code = 401;
            throw error;
        }
        const token = jwt.sign({
            userId: user._id.toString(),
            email: user.email
        }, 
        'somesupersecretsecret', 
        {expiresIn: '1h'}
        );
        return { token, userId: user._id.toString() }
    },
    createPost: async function({postInput}, req) {
        isAuthUser(req);
        const { title, content, imageUrl } = postInput;
        const errors = [];
        if(validator.isEmpty(title) || !validator.isLength(title, {min: 5})) {
            errors.push({message: 'Title is invalid.'})
        }
        if(validator.isEmpty(content) || !validator.isLength(content, {min: 10})){
            errors.push({message: 'Content is invalid.'})
        }
        if(errors.length > 0) {
            const error = new Error('Invalid input.')
            error.code = 422;
            error.data = errors;
            throw error;
        }
        const user = await User.findById(req.userId);
        if(!user) {
            const error = new Error('Invalid user.');
            error.code = 401;
            throw error;
        }
        const post = new Post({
            title,
            content,
            imageUrl,
            creator: user
        })
        const createdPost = await post.save();
        user.posts.push(createdPost);
        await user.save();
        return { 
            ...createdPost._doc, 
            _id: createdPost._id.toString(), 
            createdAt: createdPost.createdAt.toISOString(),
            updatedAt: createdPost.updatedAt.toISOString()
        };
    },
    posts: async function({page}, req) {
        isAuthUser(req);
        if(!page) {
            page = 1;
        }
        const perPage = 2;
        const totalPosts = await Post.find().countDocuments();
        const posts = await Post.find()
            .sort({createdAt: -1})
            .skip((page -1) * perPage)
            .limit(perPage)
            .populate('creator');
        return {
            posts: posts.map(p => {
                return {...p._doc, _id: p._id.toString(), createdAt: p.createdAt.toISOString(), updatedAt: p.updatedAt.toISOString()}
            }), 
            totalPosts: totalPosts
        };
    },
    post: async function({ id }, req) {
        isAuthUser(req);
        const post = await Post.findById(id).populate('creator');
        if(!post) {
            const err = new Error('No post found!');
            error.code = 404;
            throw error;
        }
        return {
            ...post._doc, 
            _id: post._id.toString(), 
            createdAt: post.createdAt.toISOString(), 
            updatedAt: post.updatedAt.toISOString()
        }
    },
    updatePost: async function({id, postInput}, req) {
        isAuthUser(req);
        const { title, content, imageUrl } = postInput;
        const post = await Post.findById(id).populate('creator');
        if(!post) {
            const err = new Error('No post found!');
            error.code = 404;
            throw error;
        }
        if(post.creator._id.toString() !== req.userId.toString()) {
            const error = new Error('Not authorized');
            error.code = 403;
            throw error;
        }
        const errors = [];
        if(validator.isEmpty(title) || !validator.isLength(title, {min: 5})) {
            errors.push({message: 'Title is invalid.'})
        }
        if(validator.isEmpty(content) || !validator.isLength(content, {min: 10})){
            errors.push({message: 'Content is invalid.'})
        }
        if(errors.length > 0) {
            const error = new Error('Invalid input.')
            error.code = 422;
            error.data = errors;
            throw error;
        }
        post.title = title;
        post.content = content;
        if(imageUrl !== 'undefined') {
            post.imageUrl = imageUrl;
        }
        const updatedPost = await post.save();
        return {
            ...updatedPost._doc,
            _id: updatedPost._id.toString(),
            createdAt: updatedPost.createdAt.toISOString(), 
            updatedAt: updatedPost.updatedAt.toISOString()
        }
    },
    deletePost: async function({ id }, req) {
        isAuthUser(req);
        const post = await Post.findById(id);
        if(!post) {
            const err = new Error('No post found!');
            error.code = 404;
            throw error;
        }
        if(post.creator.toString() !== req.userId.toString()) {
            const error = new Error('Not authorized');
            error.code = 403;
            throw error;
        }
        clearImage(post.imageUrl);
        await Post.findByIdAndRemove(id);
        const user = await User.findById(req.userId);
        user.posts.pull(id);
        await user.save();
        return true;
    },
    user: async function(args, req) {
        isAuthUser(req);
        const user = await User.findById(req.userId);
        if(!user) {
            const err = new Error('User not found.');
            error.code = 404;
            throw error;
        }
        return {
            ...user._doc,
            _id: user._id.toString()
        };
    },
    updateStatus: async function({status}, req) {
        isAuthUser(req);
        const user = await User.findById(req.userId);
        if(!user) {
            const err = new Error('User not found.');
            error.code = 404;
            throw error;
        }
        user.status = status;
        await user.save();
        return {
            ...user._doc,
            _id: user._id.toString()
        };
    }
}