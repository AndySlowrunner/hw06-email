import ctrlWrapper from '../decorators/ctrlWrapper.js';
import HttpError from '../helper/HttpError.js';
import Contact from '../models/Contact.js';

const getAll = async (req, res) => {
    const { _id: owner } = req.user;
    const result = await Contact.find({owner});
    res.json(result);
};

const getById = async (req, res) => {
    const { contactId: _id } = req.params;
    const { _id: owner } = req.user;
    const result = await Contact.findOne({_id, owner});
    if (!result) {
        throw HttpError(404)
    };
    res.json(result);
};

const addNew = async (req, res) => {
    const { _id: owner } = req.user;
    const result = await Contact.create({...req.body, owner});
    res.status(201).json(result);
};

const deleteById = async (req, res) => {
    const { contactId: _id } = req.params;
    const { _id: owner } = req.user;
    const result = await Contact.findOneAndDelete({_id, owner});
    if (!result) {
        throw HttpError(404)
    };
    res.json({ message: "contact deleted" });
};

const updateById = async (req, res) => {
    const { contactId: _id } = req.params;
    const { _id: owner } = req.user;
    const result = await Contact.findOneAndUpdate({_id, owner}, req.body);
    if (!result) {
        throw HttpError(404)
    };
    res.json(result);
};

const updateStatusContact = async (req, res) => {
    const { contactId: _id } = req.params;
    const { _id: owner } = req.user;
    const result = await Contact.findOneAndUpdate({_id, owner}, req.body);
    if (!result) {
        throw HttpError(404)
    };
    res.json(result);
};

export default {
    getAll: ctrlWrapper(getAll),
    getById: ctrlWrapper(getById),
    addNew: ctrlWrapper(addNew),
    updateById: ctrlWrapper(updateById),
    deleteById: ctrlWrapper(deleteById),
    updateStatusContact: ctrlWrapper(updateStatusContact),
};