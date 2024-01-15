import express from 'express';

import contactsController from '../../controller/contacts-controller.js';
import isEmptyBody from '../../middleware/isEmptyBody.js';
import isValidId from '../../middleware/isValidId.js';
import validateBody from '../../decorators/validateBody.js';
import { contactAddSchema, contactUpdateSchema, favoriteUpdateSchema } from '../../models/Contact.js';
import isEmptyFavorite from '../../middleware/isEmptyFavorite.js';
import authenticate from '../../middleware/authenticate.js';


const router = express.Router()

router.use(authenticate);

router.get('/', contactsController.getAll);

router.get('/:contactId', isValidId, contactsController.getById);

router.post('/', isEmptyBody, validateBody(contactAddSchema), contactsController.addNew);

router.delete('/:contactId', isValidId, contactsController.deleteById);

router.put('/:contactId', isValidId, isEmptyBody, validateBody(contactUpdateSchema), contactsController.updateById);

router.patch('/:contactId/favorite', isValidId, isEmptyFavorite, validateBody(favoriteUpdateSchema), contactsController.updateStatusContact);

export default router;
