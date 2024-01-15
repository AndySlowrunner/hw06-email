import { HttpError } from "../helper/index.js";

const isEmptyBody = (req, res, next) => {
    const { length } = Object.keys(req.body);
    if (!length) {
        return next(HttpError(400, "Missing fields"));
    }
    next();
};

export default isEmptyBody;