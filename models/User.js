import { Schema, model } from "mongoose";
import Joi from "joi";

import { addUpdateSetting, handleSaveError } from "./hooks.js";

const mailformat = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;

const userSchema = new Schema({
    password: {
        type: String,
        required: [true, 'Set password for user'],
        minlength: 4,
    },
    email: {
        type: String,
        match: mailformat,
        required: [true, 'Email is required'],
        unique: true,
    },
    subscription: {
        type: String,
        enum: ["starter", "pro", "business"],
        default: "starter"
    },
    avatarURL: {
        type: String,
        required: true,
    },
    token: String
}, { versionKey: false, timestamps: true });

userSchema.post("save", handleSaveError);
userSchema.pre("findOneAndUpdate", addUpdateSetting);
userSchema.post("findOneAndUpdate", handleSaveError);

export const userSignupSchema = Joi.object({
    password: Joi.string().min(4).required(),
    email: Joi.string().pattern(mailformat).required(),
});

export const userLoginSchema = Joi.object({
    password: Joi.string().min(4).required(),
    email: Joi.string().pattern(mailformat).required(),
});

const User = model("user", userSchema);

export default User;