const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors'); // Importando o CORS


const app = express();
app.use(express.json());
app.use(cors()); // Ativando o CORS

const users = []; // Armazenamento em memória (simulação de banco de dados)

// Chave secreta para gerar tokens
const SECRET_KEY = 'supersecretkey123';

// Middleware para autenticação via token JWT
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Token não fornecido' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
}

// Rota de cadastro
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    if (!username || !password || !email) {
        return res.status(400).json({ error: 'Nome de usuário e senha são obrigatórios' });
    }

    // Verificar se o usuário já existe
    const userExists = users.find(user => user.email === email);
    if (userExists) {
        return res.status(400).json({ error: 'Usuário já existe' });
    }

    // Criptografar a senha
    const hashedPassword = await bcrypt.hash(password, 10);

    // Salvar o usuário
    const user = { username, email, password: hashedPassword };
    users.push(user);
    res.status(201).json({ message: 'Usuário registrado com sucesso' });
});

// Rota de login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Nome de usuário e senha são obrigatórios' });
    }

    console.log(username)
    // Verificar se o usuário existe
    const user = users.find(user => user.email === username);
    if (!user) {
        return res.status(400).json({ error: 'Usuário não encontrado' });
    }

    // Comparar a senha
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(400).json({ error: 'Senha incorreta' });
    }

    // Gerar token JWT
    const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ message: 'Login realizado com sucesso', token });
});

// Rota para listar usuários (autenticada)
app.get('/users', authenticateToken, (req, res) => {
    res.json(users);
});

// Rota para deletar um usuário (autenticada)
app.delete('/users/:username', authenticateToken, (req, res) => {
    const { username } = req.params;

    const userIndex = users.findIndex(user => user.username === username);
    if (userIndex === -1) {
        return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    users.splice(userIndex, 1);
    res.json({ message: 'Usuário deletado com sucesso' });
});

// Iniciar o servidor
app.listen(3000, () => {
    console.log('Servidor rodando na porta 3000');
});
