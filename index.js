import express from 'express';
import sql from './connectToDB.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';


const app = express();
const PORT = process.env.PORT || 3022;

app.use(express.json()); 

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'your_refresh_token_secret';

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Missing Details' });
    }
    try {
        const [user] = await sql`SELECT * FROM users WHERE email = ${email}`;
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const accessToken = jwt.sign({ email: user.email, password: user.password }, JWT_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ email: user.email, password: user.password }, REFRESH_TOKEN_SECRET, { expiresIn: '1h' });
        res.status(200).json({ "token": accessToken, "refreshToken": refreshToken });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/refresh',async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(400).json({ error: 'Missing Details' });
    }
    try {
        const payload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
        const accessToken = jwt.sign({ email: payload.email, password: payload.password }, JWT_SECRET, { expiresIn: '15m' });
        res.json({ "token": accessToken });
    } catch (err) {
        return res.status(401).json({ error: 'Invalid refresh token' });
    }
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !password || !email) {
        return res.status(400).json({ error: 'Missing Details' });
    }

    const result = await sql`SELECT * FROM users WHERE email = ${email} `;
    if (result.length > 0) {
        return res.status(409).json({ error: 'User already exists' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await sql`INSERT INTO users (username, email, password) VALUES (${username}, ${email}, ${hashedPassword}) RETURNING email, password`;
        res.status(201).json("User registered successfully");
    }
    catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/addexpense', async (req, res) => {
     const { authorization } = req.headers;
     const { amount, category, description, expense_date } = req.body;

    if(authorization && authorization.startsWith('Bearer ')){
        const token = authorization.split(' ')[1];
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (!decoded) {
                return res.status(401).json({ error: 'Unauthorized' });
            }
            const email = decoded.email;
            if (!email) {
                return res.status(401).json({ error: 'Unauthorized' });
            }
            
            const user = await sql`SELECT * FROM users WHERE email = ${email}`;
            const userid = user[0].id
            console.log('userid:', userid);
                    if (!amount || !category || !description || !expense_date) {
                        return res.status(400).json({ error: 'Missing Details' });
                    }

                        await sql`INSERT INTO expenses (user_id, amount, category, description, expense_date) VALUES (${userid}, ${amount}, ${category}, ${description}, ${expense_date})`;
                        res.status(201).json("Expense added successfully");
                  
            } catch (err) {
            return res.status(401).json(err);
        }
    } else {
        return res.status(401).json({ error: 'Unauthorized' });
    }
});

app.get('/expenses', async (req, res) => {
    const { authorization } = req.headers;
    const { startDate, endDate, filterBy } = req.query;
    if(authorization && authorization.startsWith('Bearer ')){
        const token = authorization.split(' ')[1];
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (!decoded) {
                return res.status(401).json({ error: 'Unauthorized' });
            }
            const email = decoded.email;
            if (!email) {
                return res.status(401).json({ error: 'Unauthorized' });
            }
            
            const user = await sql`SELECT * FROM users WHERE email = ${email}`;
            const userid = user[0].id
            let params = [userid];
            let filterString = '';
            if (filterBy === 'past_week') {
                    filterString = ' AND expense_date >= CURRENT_DATE - INTERVAL \'1 week\'';
                } else if (filterBy === 'past_month') {
                    filterString = ' AND expense_date >= CURRENT_DATE - INTERVAL \'1 month\'';
                } else if (filterBy === 'last_3_months') {
                    filterString = ' AND expense_date >= CURRENT_DATE - INTERVAL \'3 months\'';
                } else if (startDate && endDate) {
                    filterString = ` AND expense_date BETWEEN $2 AND $3`;
                    params.push(startDate, endDate);
                }
                let query = `SELECT * FROM expenses WHERE user_id = $1 ${filterString} ORDER BY id DESC`;

                const expenses = await sql.unsafe(query,params);
                res.status(200).json(expenses);
            
        } catch (err) {
            return res.status(404).json(err);
        }
    } else {
        return res.status(401).json({ error: 'Unauthorized' });
    }
});


app.put('/expense/:id', async (req, res) => {
    const { authorization } = req.headers;
    const { id } = req.params;
    const { amount, category, description } = req.body;

   if(authorization && authorization.startsWith('Bearer ')){
       const token = authorization.split(' ')[1];
       try {
           const decoded = jwt.verify(token, JWT_SECRET);
           if (!decoded) {
               return res.status(401).json({ error: 'Unauthorized' });
           }
           const email = decoded.email;
           if (!email) {
               return res.status(401).json({ error: 'Unauthorized' });
           }
           
           const user = await sql`SELECT * FROM users WHERE email = ${email}`;
           const userid = user[0].id;
            if (!amount || !category || !description) {   
                return res.status(400).json({ error: 'Missing Details' });
            }
            const expense = await sql`SELECT * FROM expenses WHERE id = ${id} AND user_id = ${userid}`;
            if (expense.length === 0) {
                return res.status(404).json({ error: 'Expense not found' });
            }
                await sql`UPDATE expenses SET amount = ${amount}, category = ${category}, description = ${description} WHERE id = ${id} AND user_id = ${userid}`;
                res.status(200).json("Expense updated successfully");
             
           } catch (err) {
           return res.status(401).json(err);
       }
   } else {
       return res.status(401).json({ error: 'Unauthorized' });
   }
    
});

app.delete('/expense/:id', async (req, res) => {
    const { authorization } = req.headers;
    const { id } = req.params;

   if(authorization && authorization.startsWith('Bearer ')){
       const token = authorization.split(' ')[1];
       try {
           const decoded = jwt.verify(token, JWT_SECRET);
           if (!decoded) {
               return res.status(401).json({ error: 'Unauthorized' });
           }
           const email = decoded.email;
           if (!email) {
               return res.status(401).json({ error: 'Unauthorized' });
           }
           
           const user = await sql`SELECT * FROM users WHERE email = ${email}`;
           const userid = user[0].id;
            const expense = await sql`SELECT * FROM expenses WHERE id = ${id} AND user_id = ${userid}`;
            if (expense.length === 0) {
                return res.status(404).json({ error: 'Expense not found' });
            }
                await sql`DELETE FROM expenses WHERE id = ${id} AND user_id = ${userid}`;
                res.status(200).json("Expense deleted successfully");
             
           } catch (err) {
           return res.status(401).json(err);
       }
   } else {
       return res.status(401).json({ error: 'Unauthorized' });
   }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});     