const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const users = require('../userStore');  // Certifique-se de que o caminho está correto

const generateToken = (user) => {
    return jwt.sign({ username: user.username, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

const signup = async (req, res) => {
    const { username, email, password } = req.body;
    
    const existingUser = users.find(user => user.username === username || user.email === email);
    if (existingUser) {
        return res.status(400).json({ message: 'Usuário ou e-mail já existe.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { username, email, password: hashedPassword };
    users.push(user);  // Adiciona o novo usuário ao array
    res.status(201).json({ message: 'Usuário criado com sucesso!' });
};

const login = async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(user => user.username === username);
    if (!user) {
        return res.status(400).json({ message: 'Usuário ou senha inválidos.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ message: 'Usuário ou senha inválidos.' });
    }

    const token = generateToken(user);
    res.status(200).json({ token });
};

const protected = (req, res) => {
    res.json({ message: `Olá, ${req.user.username}! Você acessou uma rota protegida.` });
};

module.exports = { signup, login, protected };


