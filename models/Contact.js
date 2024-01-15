import { Schema, model } from "mongoose";
import Joi from "joi";
import { addUpdateSetting, handleSaveError } from "./hooks.js";

const contactSchema = new Schema({
    name: {
        type: String,
        required: [true, 'Set name for contact'],
    },
    email: {
        type: String,
    },
    phone: {
        type: String,
    },
    favorite: {
        type: Boolean,
        default: false,
    },
    owner: {
      type: Schema.Types.ObjectId,
      ref: 'user',
    },
}, { versionKey: false, timestamps: true });

contactSchema.post("save", handleSaveError);
contactSchema.pre("findOneAndUpdate", addUpdateSetting);
contactSchema.post("findOneAndUpdate", handleSaveError);

const Contact = model("contact", contactSchema);

export const contactAddSchema = Joi.object({
    name: Joi.string().required().messages({
        "any.required": `"name" must be exist`
    }),
    email: Joi.string().email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } }).required(),
    phone: Joi.string().required(),
    favorite: Joi.boolean(),
});

export const contactUpdateSchema = Joi.object({
    name: Joi.string(),
    email: Joi.string(),
    phone: Joi.string(),
    favorite: Joi.boolean(),
});

export const favoriteUpdateSchema = Joi.object({
    favorite: Joi.boolean().required(),
});

export default Contact;