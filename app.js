const express = require('express');
const dotenv = require('dotenv');
const userRoutes = require('./routes/userRoutes');
const authenticateToken = require('./middlewares/authMiddleware');

dotenv.config();

const app = express();
app.use(express.json());

app.use('/api', userRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
