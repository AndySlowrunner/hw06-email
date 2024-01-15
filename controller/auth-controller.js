import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import gravatar from 'gravatar';
import fs from 'fs/promises';
import path from 'path';
import jimp from 'jimp';
import User from "../models/User.js";
import ctrlWrapper from '../decorators/ctrlWrapper.js';
import HttpError from '../helper/HttpError.js';
import 'dotenv/config';

const { JWT_SECRET } = process.env;

const avatarsPath = path.resolve('public', 'avatars');

const changeAvatar = async (req, res) => {
    const { _id } = req.user;
    if (!req.file) {
        throw HttpError(400, 'Please add an image')
    };
    const { path: oldPath, filename } = req.file;
    const newPath = path.join(avatarsPath, filename);
    await fs.rename(oldPath, newPath);

    jimp.read(newPath)
        .then((filename) => {
            return filename
                .resize(250, 250)
                .write(newPath);
        })
        .catch((err) => {
            console.error(err);
        });

    const avatarURL = path.join('avatars', filename);
    await User.findByIdAndUpdate(_id, {avatarURL});
    res.json({avatarURL});
};

const register = async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({email});
    if (user) {
        throw HttpError(409, 'Email in use');
    }
    const hashPassword = await bcrypt.hash(password, 10);
    const avatarURL = gravatar.url(email);
    const newUser = await User.create({...req.body, avatarURL, password: hashPassword});
    res.json({
        'user': {
            'email': newUser.email,
            'subscription': newUser.subscription,
        }
    })
};

const login = async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
        throw HttpError(401, 'Email or password is wrong');
    }
    const passwordCompare = await bcrypt.compare(password, user.password);
    if (!passwordCompare) {
        throw HttpError(401, 'Email or password is wrong');
    }
    const { _id: id } = user;
    const payload = {
        id
    };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '23h' });
    await User.findByIdAndUpdate(id, { token });
    const subscription = user.subscription;
    res.json({
        'token': token,
        'user': {
            'email': email,
            'subscription': subscription,
        }
    });
};

const getCurrent = async (req, res) => {
    const { email, subscription } = req.user;
    res.json({
        'email': email,
        'subscription': subscription,
    });
};

const logout = async (req, res) => {
    const { _id } = req.user;
    await User.findByIdAndUpdate(_id, { token: '' });
    res.status(204).json('No Content');
};

export default {
    changeAvatar: ctrlWrapper(changeAvatar),
    register: ctrlWrapper(register),
    login: ctrlWrapper(login),
    getCurrent: ctrlWrapper(getCurrent),
    logout: ctrlWrapper(logout),
};