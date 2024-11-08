const express = require('express');
const { signup, login, protected} = require('../controllers/userController');
const authenticateToken = require('../middlewares/authMiddleware');

const router = express.Router();

router.post('/signup', signup);
router.post('/login', login);
router.get('/protected', authenticateToken, protected);

module.exports = router;
