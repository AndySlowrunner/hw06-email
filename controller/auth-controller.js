import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import gravatar from 'gravatar';
import fs from 'fs/promises';
import path from 'path';
import jimp from 'jimp';
import { nanoid } from 'nanoid';

import User from "../models/User.js";
import ctrlWrapper from '../decorators/ctrlWrapper.js';
import HttpError from '../helper/HttpError.js';
import sendEmail from '../helper/sendEmail.js';
import dotenv from 'dotenv';

dotenv.config();

const { JWT_SECRET, BASE_URL } = process.env;

const avatarsPath = path.resolve('public', 'avatars');

const verify = async (req, res) => {
    const { verificationToken } = req.params;
    const user = await User.findOne({ verificationToken });
    if (!user) {
        throw HttpError(404, 'User not found')
    }
    await User.findByIdAndUpdate(user._id, { verify: true, verificationToken: null });
    res.json({
        message: 'Verification successful'
    })
};

const resendVerifyEmail = async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
        throw HttpError(400, 'missing required field email')
    }
    if (user.verify) {
        throw HttpError(400, 'Verification has already been passed')
    }
    const verifyEmail = {
        to: email,
        subject: 'Email verify',
        html: `<a target="_blank" href="${BASE_URL}/api/users/verify/${user.verificationToken}">Click to verify your email</a>`
    };
    await sendEmail(verifyEmail);

    res.json({
        message: 'Verification email sent'
    })
}

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
    const verificationToken = nanoid();
    const avatarURL = gravatar.url(email);
    const newUser = await User.create({ ...req.body, avatarURL, password: hashPassword, verificationToken });
    
    const verifyEmail = {
        to: email,
        subject: 'Email verify',
        html: `<a target="_blank" href="${BASE_URL}/api/users/verify/${verificationToken}">Click to verify your email</a>`
    };
    await sendEmail(verifyEmail);

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
    if (!user.verify) {
        throw HttpError(401, 'Email is not verify');
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
    resendVerifyEmail: ctrlWrapper(resendVerifyEmail),
    verify: ctrlWrapper(verify),
    changeAvatar: ctrlWrapper(changeAvatar),
    register: ctrlWrapper(register),
    login: ctrlWrapper(login),
    getCurrent: ctrlWrapper(getCurrent),
    logout: ctrlWrapper(logout),
};