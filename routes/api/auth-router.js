import express from "express";

import authController from "../../controller/auth-controller.js";
import isEmptyBody from "../../middleware/isEmptyBody.js";
import validateBody from '../../decorators/validateBody.js';
import upload from '../../middleware/upload.js';
import { userLoginSchema, userSignupSchema, userResendEmailSchema } from "../../models/User.js";
import authenticate from "../../middleware/authenticate.js";

const authRouter = express.Router();

authRouter.post('/register', isEmptyBody, validateBody(userSignupSchema), authController.register);
authRouter.post('/login', isEmptyBody, validateBody(userLoginSchema), authController.login);
authRouter.get('/current', authenticate, authController.getCurrent);
authRouter.post('/logout', authenticate, authController.logout);
authRouter.patch('/avatars', authenticate, upload.single('avatar'), authController.changeAvatar);
authRouter.get('/verify/:verificationToken', authController.verify);
authRouter.post('/verify', isEmptyBody, validateBody(userResendEmailSchema), authController.resendVerifyEmail);

export default authRouter;