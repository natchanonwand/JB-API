require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const promisePool = require('./database'); // Import the promise-based pool

const app = express();
// Middleware to parse JSON bodies
app.use(express.json());
const PORT = process.env.PORT || 3002;
// Secret key for JWT
const secret = 'Fullstack-login-project';

app.listen(PORT, () => {
    console.log(`Server running on PORT : ${PORT}`);
});

app.use(cors());
app.use(bodyParser.json());

app.get('/test', (req, res) => {
    res.send('Hello brother !');
});

// Registration endpoint
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body; // Add username to the destructuring

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the user data with hashed password into the database
        const insertQuery = 'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)'; // Include username in the query
        await promisePool.execute(insertQuery, [username, email, hashedPassword]); // Pass username to the query

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Error registering user' });
    }
});


// Login route
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Query the database to find the user with the provided email
        const query = 'SELECT * FROM users WHERE email = ?';
        const [users] = await promisePool.execute(query, [email]);

        if (users.length === 0) {
            // If no user found with the provided email, return an error
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const user = users[0];
        const passwordIsValid = await bcrypt.compare(password, user.password_hash);

        if (!passwordIsValid) {
            // If the password is invalid, return an error
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Sign JWT token using the hardcoded secret key
        const token = jwt.sign({ id: user.id, email: user.email }, secret, {
            expiresIn: '8h'
        });

        // Login successful, send the JWT token
        return res.status(200).json({ status: 'ok', message: 'Login successful', token });
    } catch (error) {
        // Handle errors
        console.error('Error logging in:', error);
        return res.status(500).json({ error: 'Error logging in' });
    }
});


// Authentication endpoint
app.post('/api/authen', async (req, res) => {
    try {
        const token = req.headers.authorization.split(' ')[1];
        var decoded = jwt.verify(token, secret); // Verify token with the hardcoded secret key
        res.json({ status: 'ok', decoded });
    } catch (err) {
        res.json({ status: 'error', message: err.message });
    }
});

// Get all user emails route
app.get('/users/emails', async (req, res) => { // Use async function for route handler
    try {
        const query = 'SELECT email FROM users';
        const [users] = await promisePool.execute(query); // Use promisePool.execute instead of db.query

        const emails = users.map(user => user.email);
        res.status(200).json({ emails });
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ message: "An error occurred", error: error.message });
    }
});

// Get all records from Air_Blower
app.get('/api/air-blower', async (req, res) => {
    const { machine_name, record_date, record_time } = req.query;
    let query = 'SELECT * FROM Air_Blower WHERE 1=1';
    const queryParams = [];

    if (machine_name) {
        query += ' AND machine_name = ?';
        queryParams.push(machine_name);
    }

    if (record_date) {
        query += ' AND DATE(record_date) = ?';
        queryParams.push(record_date);
    }

    if (record_time) {
        query += ' AND record_time = ?';
        queryParams.push(record_time);
    }

    if (machine_name && record_date && record_time) {
        // Order by record_id in descending order to get the latest record first
        query += ' ORDER BY record_id DESC';
        // Limit the result to 1 record
        query += ' LIMIT 1';
    }

    try {
        const [records] = await promisePool.execute(query, queryParams);

        // Round specific fields to two decimal places if they exist in the records
        const roundedRecords = records.map(record => ({
            ...record,
            // Add any other fields that you want to round here
            // Example:
            // T1: record.T1 ? parseFloat(record.T1).toFixed(2) : null,
            // T2: record.T2 ? parseFloat(record.T2).toFixed(2) : null
        }));

        res.status(200).json(roundedRecords);
    } catch (error) {
        console.error('Error fetching records from Air_Blower:', error);
        res.status(500).json({ error: 'Error fetching records from Air_Blower' });
    }
});


// Add a new record to Air_Blower
app.post('/api/air-blower', async (req, res) => {
    const { machine_name, record_date, record_time, status, A1, A2, A3, T, note } = req.body;

    try {
        const query = `INSERT INTO Air_Blower (machine_name, record_date, record_time, status, A1, A2, A3, T, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        await promisePool.execute(query, [machine_name, record_date, record_time, status, A1, A2, A3, T, note]);
        res.status(201).json({ message: 'Record added successfully' });
    } catch (error) {
        console.error('Error adding record:', error);
        res.status(500).json({ error: 'Error adding record' });
    }
});

// Update an existing record in Air_Blower
app.put('/api/air-blower/:id', async (req, res) => {
    const { id } = req.params;
    const { machine_name, record_date, record_time, status, A1, A2, A3, T, note } = req.body;

    try {
        const query = `UPDATE Air_Blower SET machine_name = ?, record_date = ?, record_time = ?, status = ?, A1 = ?, A2 = ?, A3 = ?, T = ?, note = ? WHERE record_id = ?`;
        await promisePool.execute(query, [machine_name, record_date, record_time, status, A1, A2, A3, T, note, id]);
        res.status(200).json({ message: 'Record updated successfully' });
    } catch (error) {
        console.error('Error updating record:', error);
        res.status(500).json({ error: 'Error updating record' });
    }
});

// Utility function to create routes
const createRoutesForTable = (tableName) => {
    // Dynamic endpoint to fetch the latest record from any table based on max record_id
app.get('/api/:tableName', async (req, res) => {
    const tableName = req.params.tableName;
    const { machine_name, record_date, record_time } = req.query;
    let query = `SELECT * FROM ${tableName} WHERE 1=1`;
    const queryParams = [];

    if (machine_name) {
        query += ' AND machine_name = ?';
        queryParams.push(machine_name);
    }

    if (record_date) {
        query += ' AND DATE(record_date) = ?';
        queryParams.push(record_date);
    }

    if (record_time) {
        query += ' AND record_time = ?';
        queryParams.push(record_time);
    }

    if (machine_name && record_date && record_time) {
        // Order by record_id in descending order to get the latest record first
        query += ' ORDER BY record_id DESC';
        // Limit the result to 1 record
        query += ' LIMIT 1';
    }

    try {
        const [records] = await promisePool.execute(query, queryParams);
        res.status(200).json(records);
    } catch (error) {
        console.error(`Error fetching records from ${tableName}:`, error);
        res.status(500).json({ error: `Error fetching records from ${tableName}` });
    }
});

    
    

    app.post(`/api/${tableName}`, async (req, res) => {
        const { machine_name, record_date, record_time, status, A1, A2, A3, T, note } = req.body;

        try {
            const query = `INSERT INTO ${tableName} (machine_name, record_date, record_time, status, A1, A2, A3, T, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
            await promisePool.execute(query, [machine_name, record_date, record_time, status, A1, A2, A3, T, note]);
            res.status(201).json({ message: 'Record added successfully' });
        } catch (error) {
            console.error(`Error adding record to ${tableName}:`, error);
            res.status(500).json({ error: `Error adding record to ${tableName}` });
        }
    });

    app.put(`/api/${tableName}/:id`, async (req, res) => {
        const { id } = req.params;
        const { machine_name, record_date, record_time, status, A1, A2, A3, T, note } = req.body;

        try {
            const query = `UPDATE ${tableName} SET machine_name = ?, record_date = ?, record_time = ?, status = ?, A1 = ?, A2 = ?, A3 = ?, T = ?, note=? WHERE record_id = ?`;
            await promisePool.execute(query, [machine_name, record_date, record_time, status, A1, A2, A3, T, note, id]);
            res.status(200).json({ message: 'Record updated successfully' });
        } catch (error) {
            console.error(`Error updating record in ${tableName}:`, error);
            res.status(500).json({ error: `Error updating record in ${tableName}` });
        }
    });
};

// Get all records from Fine_Screen
app.get('/api/fine-screen', async (req, res) => {
    const { machine_name, record_date, record_time } = req.query;
    let query = 'SELECT * FROM Fine_Screen WHERE 1=1';
    const queryParams = [];

    if (machine_name) {
        query += ' AND machine_name = ?';
        queryParams.push(machine_name);
    }

    if (record_date) {
        query += ' AND DATE(record_date) = ?';
        queryParams.push(record_date);
    }

    if (record_time) {
        query += ' AND record_time = ?';
        queryParams.push(record_time);
    }

    if (machine_name && record_date && record_time) {
        // Order by record_id in descending order to get the latest record first
        query += ' ORDER BY record_id DESC';
        // Limit the result to 1 record
        query += ' LIMIT 1';
    }

    try {
        const [records] = await promisePool.execute(query, queryParams);

        // Round specific fields to two decimal places if they exist in the records
        const roundedRecords = records.map(record => ({
            ...record,
            // Add any other fields that you want to round here
            // Example:
            // T1: record.T1 ? parseFloat(record.T1).toFixed(2) : null,
            // T2: record.T2 ? parseFloat(record.T2).toFixed(2) : null
        }));

        res.status(200).json(roundedRecords);
    } catch (error) {
        console.error('Error fetching records from Fine_Screen:', error);
        res.status(500).json({ error: 'Error fetching records from Fine_Screen' });
    }
});



// Add a new record to Fine_Screen
app.post('/api/fine_screen', async (req, res) => {
    const { machine_name, record_date, record_time, status, A1, note } = req.body;

    try {
        const query = 'INSERT INTO Fine_Screen (machine_name, record_date, record_time, status, A1, note) VALUES (?, ?, ?, ?, ?, ?)';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, A1, note]);
        res.status(201).json({ message: 'Record added successfully to Fine_Screen' });
    } catch (error) {
        console.error('Error adding record to Fine_Screen:', error);
        res.status(500).json({ error: 'Error adding record to Fine_Screen' });
    }
});

// Update an existing record in Fine_Screen
app.put('/api/fine_screen/:id', async (req, res) => {
    const { id } = req.params;
    const { machine_name, record_date, record_time, status, A1, note } = req.body;

    try {
        const query = 'UPDATE Fine_Screen SET machine_name = ?, record_date = ?, record_time = ?, status = ?, A1 = ?, note=? WHERE record_id = ?';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, A1, note, id]);
        res.status(200).json({ message: 'Record updated successfully in Fine_Screen' });
    } catch (error) {
        console.error('Error updating record in Fine_Screen:', error);
        res.status(500).json({ error: 'Error updating record in Fine_Screen' });
    }
});

// Get the latest record from inlet_gate based on max record_id
app.get('/api/inlet_gate', async (req, res) => {
    const { machine_name, record_date, record_time } = req.query;
    let query = 'SELECT * FROM inlet_gate WHERE 1=1';
    const queryParams = [];

    if (machine_name) {
        query += ' AND machine_name = ?';
        queryParams.push(machine_name);
    }

    if (record_date) {
        query += ' AND DATE(record_date) = ?';
        queryParams.push(record_date);
    }

    if (record_time) {
        query += ' AND record_time = ?';
        queryParams.push(record_time);
    }

    // Order by record_id in descending order to get the latest record first
    query += ' ORDER BY record_id DESC';
    // Limit the result to 1 record
    query += ' LIMIT 1';

    try {
        const [records] = await promisePool.execute(query, queryParams);
        res.status(200).json(records);
    } catch (error) {
        console.error('Error fetching records from inlet_gate:', error);
        res.status(500).json({ error: 'Error fetching records from inlet_gate' });
    }
});




// Add a new record to inlet_gate
app.post('/api/inlet_gate', async (req, res) => {
    const { machine_name, record_date, record_time, status, gate_percentage, note } = req.body;

    try {
        const query = 'INSERT INTO inlet_gate (machine_name, record_date, record_time, status, gate_percentage, note) VALUES (?, ?, ?, ?, ?, ?)';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, gate_percentage, note]);
        res.status(201).json({ message: 'Record added successfully to inlet_gate' });
    } catch (error) {
        console.error('Error adding record to inlet_gate:', error);
        res.status(500).json({ error: 'Error adding record to inlet_gate' });
    }
});

// Update an existing record in inlet_gate
app.put('/api/inlet_gate/:id', async (req, res) => {
    const { id } = req.params;
    const { machine_name, record_date, record_time, status, gate_percentage, note } = req.body;

    try {
        const query = 'UPDATE inlet_gate SET machine_name = ?, record_date = ?, record_time = ?, status = ?, gate_percentage = ?, note=? WHERE record_id = ?';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, gate_percentage, note, id]);
        res.status(200).json({ message: 'Record updated successfully in inlet_gate' });
    } catch (error) {
        console.error('Error updating record in inlet_gate:', error);
        res.status(500).json({ error: 'Error updating record in inlet_gate' });
    }
});

// Get the latest record from Coarse_Screen based on max record_id
app.get('/api/coarse_screen', async (req, res) => {
    const { machine_name, record_date, record_time } = req.query;
    let query = 'SELECT * FROM Coarse_Screen WHERE 1=1';
    const queryParams = [];

    if (machine_name) {
        query += ' AND machine_name = ?';
        queryParams.push(machine_name);
    }

    if (record_date) {
        query += ' AND DATE(record_date) = ?';
        queryParams.push(record_date);
    }

    if (record_time) {
        query += ' AND record_time = ?';
        queryParams.push(record_time);
    }

    // Order by record_id in descending order to get the latest record first
    query += ' ORDER BY record_id DESC';
    // Limit the result to 1 record
    query += ' LIMIT 1';

    try {
        const [records] = await promisePool.execute(query, queryParams);

        // Round T1 and T2 to two decimal places
        const roundedRecords = records.map(record => ({
            ...record,
            T1: record.T1 ? parseFloat(record.T1).toFixed(2) : null,
            T2: record.T2 ? parseFloat(record.T2).toFixed(2) : null
        }));

        res.status(200).json(roundedRecords);
    } catch (error) {
        console.error('Error fetching records from Coarse_Screen:', error);
        res.status(500).json({ error: 'Error fetching records from Coarse_Screen' });
    }
});




// Add a new record to Coarse_Screen
app.post('/api/coarse_screen', async (req, res) => {
    let { machine_name, record_date, record_time, status, T1, T2, note } = req.body;

    // Round T1 and T2 to 2 decimal places
    T1 = parseFloat(T1).toFixed(2);
    T2 = parseFloat(T2).toFixed(2);

    try {
        const query = 'INSERT INTO Coarse_Screen (machine_name, record_date, record_time, status, T1, T2, note) VALUES (?, ?, ?, ?, ?, ?, ?)';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, T1, T2, note]);
        res.status(201).json({ message: 'Record added successfully to Coarse_Screen' });
    } catch (error) {
        console.error('Error adding record to Coarse_Screen:', error);
        res.status(500).json({ error: 'Error adding record to Coarse_Screen' });
    }
});

// Update an existing record in Coarse_Screen
app.put('/api/coarse_screen/:id', async (req, res) => {
    const { id } = req.params;
    const { machine_name, record_date, record_time, status, T1, T2, note } = req.body;

    try {
        const query = 'UPDATE Coarse_Screen SET machine_name = ?, record_date = ?, record_time = ?, status = ?, T1 = ?, T2 = ?, note=? WHERE record_id = ?';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, T1, T2, note, id]);
        res.status(200).json({ message: 'Record updated successfully in Coarse_Screen' });
    } catch (error) {
        console.error('Error updating record in Coarse_Screen:', error);
        res.status(500).json({ error: 'Error updating record in Coarse_Screen' });
    }
});

// Get all records from Water_Pump
app.get('/api/water_pump', async (req, res) => {
    const { machine_name, record_date, record_time } = req.query;
    let query = 'SELECT * FROM Water_Pump WHERE 1=1';
    const queryParams = [];

    if (machine_name) {
        query += ' AND machine_name = ?';
        queryParams.push(machine_name);
    }

    if (record_date) {
        query += ' AND DATE(record_date) = ?';
        queryParams.push(record_date);
    }

    if (record_time) {
        query += ' AND record_time = ?';
        queryParams.push(record_time);
    }

    if (record_date && record_time) {
        query += ' ORDER BY record_id DESC';
        query += ' LIMIT 1';
    }

    try {
        const [records] = await promisePool.execute(query, queryParams);

        // Round T1 and T2 to two decimal places
        const roundedRecords = records.map(record => ({
            ...record,
            T1: record.T1 ? parseFloat(record.T1).toFixed(2) : null,
            T2: record.T2 ? parseFloat(record.T2).toFixed(2) : null
        }));

        res.status(200).json(roundedRecords);
    } catch (error) {
        console.error('Error fetching records from Water_Pump:', error);
        res.status(500).json({ error: 'Error fetching records from Water_Pump' });
    }
});



// Add a new record to Water_Pump
app.post('/api/water_pump', async (req, res) => {
    const { machine_name, record_date, record_time, status, note } = req.body;

    try {
        const query = 'INSERT INTO Water_Pump (machine_name, record_date, record_time, status, note) VALUES (?, ?, ?, ?, ?)';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, note]);
        res.status(201).json({ message: 'Record added successfully to Water_Pump' });
    } catch (error) {
        console.error('Error adding record to Water_Pump:', error);
        res.status(500).json({ error: 'Error adding record to Water_Pump' });
    }
});

// Update an existing record in Water_Pump
app.put('/api/water_pump/:id', async (req, res) => {
    const { id } = req.params;
    const { machine_name, record_date, record_time, status, note } = req.body;

    try {
        const query = 'UPDATE Water_Pump SET machine_name = ?, record_date = ?, record_time = ?, status = ?, note=? WHERE record_id = ?';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, note, id]);
        res.status(200).json({ message: 'Record updated successfully in Water_Pump' });
    } catch (error) {
        console.error('Error updating record in Water_Pump:', error);
        res.status(500).json({ error: 'Error updating record in Water_Pump' });
    }
});

// Get all records from Auto_Sampler
app.get('/api/auto_sampler', async (req, res) => {
    const { machine_name, record_date, record_time } = req.query;
    let query = 'SELECT * FROM Auto_Sampler WHERE 1=1';
    const queryParams = [];

    if (machine_name) {
        query += ' AND machine_name = ?';
        queryParams.push(machine_name);
    }

    if (record_date) {
        query += ' AND DATE(record_date) = ?';
        queryParams.push(record_date);
    }

    if (record_time) {
        query += ' AND record_time = ?';
        queryParams.push(record_time);
    }

    if (record_date && record_time) {
        query += ' ORDER BY record_id DESC';
        query += ' LIMIT 1';
    }

    try {
        const [records] = await promisePool.execute(query, queryParams);

        // Round T to two decimal places if it exists in the records
        const roundedRecords = records.map(record => ({
            ...record,
            T: record.T ? parseFloat(record.T).toFixed(2) : null
        }));

        res.status(200).json(roundedRecords);
    } catch (error) {
        console.error('Error fetching records from Auto_Sampler:', error);
        res.status(500).json({ error: 'Error fetching records from Auto_Sampler' });
    }
});



// Add a new record to Auto_Sampler
app.post('/api/auto_sampler', async (req, res) => {
    const { machine_name, record_date, record_time, status, T, note } = req.body;

    try {
        const query = 'INSERT INTO Auto_Sampler (machine_name, record_date, record_time, status, T, note) VALUES (?, ?, ?, ?, ?, ?)';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, T, note]);
        res.status(201).json({ message: 'Record added successfully to Auto_Sampler' });
    } catch (error) {
        console.error('Error adding record to Auto_Sampler:', error);
        res.status(500).json({ error: 'Error adding record to Auto_Sampler' });
    }
});

// Update an existing record in Auto_Sampler
app.put('/api/auto_sampler/:id', async (req, res) => {
    const { id } = req.params;
    const { machine_name, record_date, record_time, status, T, note } = req.body;

    try {
        const query = 'UPDATE Auto_Sampler SET machine_name = ?, record_date = ?, record_time = ?, status = ?, T = ?, note=? WHERE record_id = ?';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, T, note, id]);
        res.status(200).json({ message: 'Record updated successfully in Auto_Sampler' });
    } catch (error) {
        console.error('Error updating record in Auto_Sampler:', error);
        res.status(500).json({ error: 'Error updating record in Auto_Sampler' });
    }
});

// Get all records from Air_Flow
app.get('/api/air_flow', async (req, res) => {
    const { machine_name, record_date, record_time } = req.query;
    let query = 'SELECT * FROM Air_Flow WHERE 1=1';
    const queryParams = [];

    if (machine_name) {
        query += ' AND machine_name = ?';
        queryParams.push(machine_name);
    }

    if (record_date) {
        query += ' AND DATE(record_date) = ?';
        queryParams.push(record_date);
    }

    if (record_time) {
        query += ' AND record_time = ?';
        queryParams.push(record_time);
    }

    // Only order by record_id and limit to 1 if both record_date and record_time are provided
    if (record_date && record_time) {
        query += ' ORDER BY record_id DESC';
        query += ' LIMIT 1';
    }

    try {
        const [records] = await promisePool.execute(query, queryParams);

        // Round relevant fields to two decimal places if they exist
        const roundedRecords = records.map(record => ({
            ...record,
            // Add any other fields that you want to round here
            // Example:
            // T1: record.T1 ? parseFloat(record.T1).toFixed(2) : null,
            // T2: record.T2 ? parseFloat(record.T2).toFixed(2) : null
        }));

        res.status(200).json(roundedRecords);
    } catch (error) {
        console.error('Error fetching records from Air_Flow:', error);
        res.status(500).json({ error: 'Error fetching records from Air_Flow' });
    }
});



// Add a new record to Air_Flow
app.post('/api/air_flow', async (req, res) => {
    const { machine_name, record_date, record_time, Flow, valve_percentage, note } = req.body;

    try {
        const query = 'INSERT INTO Air_Flow (machine_name, record_date, record_time, Flow, valve_percentage, note) VALUES (?, ?, ?, ?, ?, ?)';
        await promisePool.execute(query, [machine_name, record_date, record_time, Flow, valve_percentage, note]);
        res.status(201).json({ message: 'Record added successfully to Air_Flow' });
    } catch (error) {
        console.error('Error adding record to Air_Flow:', error);
        res.status(500).json({ error: 'Error adding record to Air_Flow' });
    }
});

// Update an existing record in Air_Flow
app.put('/api/air_flow/:id', async (req, res) => {
    const { id } = req.params;
    const { machine_name, record_date, record_time, Flow, valve_percentage, note } = req.body;

    try {
        const query = 'UPDATE Air_Flow SET machine_name = ?, record_date = ?, record_time = ?, Flow = ?, valve_percentage = ?, note=? WHERE record_id = ?';
        await promisePool.execute(query, [machine_name, record_date, record_time, Flow, valve_percentage, note, id]);
        res.status(200).json({ message: 'Record updated successfully in Air_Flow' });
    } catch (error) {
        console.error('Error updating record in Air_Flow:', error);
        res.status(500).json({ error: 'Error updating record in Air_Flow' });
    }
});

// Get all records from Biofilter
app.get('/api/biofilter', async (req, res) => {
    const { machine_name, record_date, record_time } = req.query;
    let query = 'SELECT * FROM Biofilter WHERE 1=1';
    const queryParams = [];

    if (machine_name) {
        query += ' AND machine_name = ?';
        queryParams.push(machine_name);
    }

    if (record_date) {
        query += ' AND DATE(record_date) = ?';
        queryParams.push(record_date);
    }

    if (record_time) {
        query += ' AND record_time = ?';
        queryParams.push(record_time);
    }

    if (record_date && record_time) {
        query += ' ORDER BY record_id DESC';
        query += ' LIMIT 1';
    }

    try {
        const [records] = await promisePool.execute(query, queryParams);

        // Round relevant fields to two decimal places if they exist
        const roundedRecords = records.map(record => ({
            ...record,
            T: record.T ? parseFloat(record.T).toFixed(2) : null
        }));

        res.status(200).json(roundedRecords);
    } catch (error) {
        console.error('Error fetching records from Biofilter:', error);
        res.status(500).json({ error: 'Error fetching records from Biofilter' });
    }
});



// Add a new record to Biofilter
app.post('/api/biofilter', async (req, res) => {
    const { machine_name, record_date, record_time, status, note } = req.body;

    try {
        const query = 'INSERT INTO Biofilter (machine_name, record_date, record_time, status, note) VALUES (?, ?, ?, ?, ?)';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, note]);
        res.status(201).json({ message: 'Record added successfully to Biofilter' });
    } catch (error) {
        console.error('Error adding record to Biofilter:', error);
        res.status(500).json({ error: 'Error adding record to Biofilter' });
    }
});

// Update an existing record in Biofilter
app.put('/api/biofilter/:id', async (req, res) => {
    const { id } = req.params;
    const { machine_name, record_date, record_time, status, note } = req.body;

    try {
        const query = 'UPDATE Biofilter SET machine_name = ?, record_date = ?, record_time = ?, status = ?, note=? WHERE record_id = ?';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, note, id]);
        res.status(200).json({ message: 'Record updated successfully in Biofilter' });
    } catch (error) {
        console.error('Error updating record in Biofilter:', error);
        res.status(500).json({ error: 'Error updating record in Biofilter' });
    }
});

/// Get all records from Garden_Pump
app.get('/api/garden_pump', async (req, res) => {
    const { machine_name, record_date, record_time } = req.query;
    let query = 'SELECT * FROM Garden_Pump WHERE 1=1';
    const queryParams = [];

    if (machine_name) {
        query += ' AND machine_name = ?';
        queryParams.push(machine_name);
    }

    if (record_date) {
        query += ' AND DATE(record_date) = ?';
        queryParams.push(record_date);
    }

    if (record_time) {
        query += ' AND record_time = ?';
        queryParams.push(record_time);
    }

    if (record_date && record_time) {
        query += ' ORDER BY record_id DESC';
        query += ' LIMIT 1';
    }

    try {
        const [records] = await promisePool.execute(query, queryParams);

        // Round relevant fields to two decimal places if they exist
        const roundedRecords = records.map(record => ({
            ...record,
            // Add any other fields that you want to round here
            // Example:
            // T1: record.T1 ? parseFloat(record.T1).toFixed(2) : null,
            // T2: record.T2 ? parseFloat(record.T2).toFixed(2) : null
        }));

        res.status(200).json(roundedRecords);
    } catch (error) {
        console.error('Error fetching records from Garden_Pump:', error);
        res.status(500).json({ error: 'Error fetching records from Garden_Pump' });
    }
});



// Add a new record to Garden_Pump
app.post('/api/garden_pump', async (req, res) => {
    const { machine_name, record_date, record_time, status, note } = req.body;

    try {
        const query = 'INSERT INTO Garden_Pump (machine_name, record_date, record_time, status, note) VALUES (?, ?, ?, ?, ?)';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, note]);
        res.status(201).json({ message: 'Record added successfully to Garden_Pump' });
    } catch (error) {
        console.error('Error adding record to Garden_Pump:', error);
        res.status(500).json({ error: 'Error adding record to Garden_Pump' });
    }
});

// Update an existing record in Garden_Pump
app.put('/api/garden_pump/:id', async (req, res) => {
    const { id } = req.params;
    const { machine_name, record_date, record_time, status, note } = req.body;

    try {
        const query = 'UPDATE Garden_Pump SET machine_name = ?, record_date = ?, record_time = ?, status = ?, note=? WHERE record_id = ?';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, note, id]);
        res.status(200).json({ message: 'Record updated successfully in Garden_Pump' });
    } catch (error) {
        console.error('Error updating record in Garden_Pump:', error);
        res.status(500).json({ error: 'Error updating record in Garden_Pump' });
    }
});


// Get all records from Chiller
app.get('/api/chiller', async (req, res) => {
    const { machine_name, record_date, record_time } = req.query;
    let query = 'SELECT * FROM Chiller WHERE 1=1';
    const queryParams = [];

    if (machine_name) {
        query += ' AND machine_name = ?';
        queryParams.push(machine_name);
    }

    if (record_date) {
        query += ' AND DATE(record_date) = ?';
        queryParams.push(record_date);
    }

    if (record_time) {
        query += ' AND record_time = ?';
        queryParams.push(record_time);
    }

    // Only order by record_id and limit to 1 if both record_date and record_time are provided
    if (record_date && record_time) {
        query += ' ORDER BY record_id DESC';
        query += ' LIMIT 1';
    }

    try {
        const [records] = await promisePool.execute(query, queryParams);

        // Round relevant fields to two decimal places if they exist
        const roundedRecords = records.map(record => ({
            ...record,
            // Add any other fields that you want to round here
            // Example:
            // T1: record.T1 ? parseFloat(record.T1).toFixed(2) : null,
            // T2: record.T2 ? parseFloat(record.T2).toFixed(2) : null
        }));

        res.status(200).json(roundedRecords);
    } catch (error) {
        console.error('Error fetching records from Chiller:', error);
        res.status(500).json({ error: 'Error fetching records from Chiller' });
    }
});


// Add a new record to Chiller
app.post('/api/chiller', async (req, res) => {
    const { machine_name, record_date, record_time, status, note } = req.body;

    try {
        const query = 'INSERT INTO Chiller (machine_name, record_date, record_time, status, note) VALUES (?, ?, ?, ?, ?)';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, note]);
        res.status(201).json({ message: 'Record added successfully to Chiller' });
    } catch (error) {
        console.error('Error adding record to Chiller:', error);
        res.status(500).json({ error: 'Error adding record to Chiller' });
    }
});

// Update an existing record in Chiller
app.put('/api/chiller/:id', async (req, res) => {
    const { id } = req.params;
    const { machine_name, record_date, record_time, status, note } = req.body;

    try {
        const query = 'UPDATE Chiller SET machine_name = ?, record_date = ?, record_time = ?, status = ?, note = ? WHERE record_id = ?';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, note, id]);
        res.status(200).json({ message: 'Record updated successfully in Chiller' });
    } catch (error) {
        console.error('Error updating record in Chiller:', error);
        res.status(500).json({ error: 'Error updating record in Chiller' });
    }
});

// Get all records from Vortex_Grit
app.get('/api/vortex_grit', async (req, res) => {
    const { machine_name, record_date, record_time } = req.query;
    let query = 'SELECT * FROM Vortex_Grit WHERE 1=1';
    const queryParams = [];

    if (machine_name) {
        query += ' AND machine_name = ?';
        queryParams.push(machine_name);
    }

    if (record_date) {
        query += ' AND DATE(record_date) = ?';
        queryParams.push(record_date);
    }

    if (record_time) {
        query += ' AND record_time = ?';
        queryParams.push(record_time);
    }

    if (record_date && record_time) {
        query += ' ORDER BY record_id DESC';
        query += ' LIMIT 1';
    }

    try {
        const [records] = await promisePool.execute(query, queryParams);

        // Round relevant fields to two decimal places if they exist
        const roundedRecords = records.map(record => ({
            ...record,
            // Add any other fields that you want to round here
            // Example:
            // T1: record.T1 ? parseFloat(record.T1).toFixed(2) : null,
            // T2: record.T2 ? parseFloat(record.T2).toFixed(2) : null
        }));

        res.status(200).json(roundedRecords);
    } catch (error) {
        console.error('Error fetching records from Vortex_Grit:', error);
        res.status(500).json({ error: 'Error fetching records from Vortex_Grit' });
    }
});



// Add a new record to Vortex_Grit
app.post('/api/vortex_grit', async (req, res) => {
    const { machine_name, record_date, record_time, status, T, note } = req.body;

    try {
        const query = 'INSERT INTO Vortex_Grit (machine_name, record_date, record_time, status, T, note) VALUES (?, ?, ?, ?, ?,?)';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, T, note]);
        res.status(201).json({ message: 'Record added successfully to Vortex_Grit' });
    } catch (error) {
        console.error('Error adding record to Vortex_Grit:', error);
        res.status(500).json({ error: 'Error adding record to Vortex_Grit' });
    }
});

// Update an existing record in Vortex_Grit
app.put('/api/vortex_grit/:id', async (req, res) => {
    const { id } = req.params;
    const { machine_name, record_date, record_time, status, T, note } = req.body;

    try {
        const query = 'UPDATE AVortex_Grit SET machine_name = ?, record_date = ?, record_time = ?, status = ?, T = ?, note=? WHERE record_id = ?';
        await promisePool.execute(query, [machine_name, record_date, record_time, status, T, note, id]);
        res.status(200).json({ message: 'Record updated successfully in Vortex_Grit' });
    } catch (error) {
        console.error('Error updating record in Vortex_Grit:', error);
        res.status(500).json({ error: 'Error updating record in Vortex_Grit' });
    }
});

// Get all records from Clarifier table
app.get('/api/clarifier', async (req, res) => {
    const { machine_name, record_date, record_time } = req.query;
    let query = 'SELECT * FROM Clarifier WHERE 1=1';
    const queryParams = [];

    if (machine_name) {
        query += ' AND machine_name = ?';
        queryParams.push(machine_name);
    }

    if (record_date) {
        query += ' AND DATE(record_date) = ?';
        queryParams.push(record_date);
    }

    if (record_time) {
        query += ' AND record_time = ?';
        queryParams.push(record_time);
    }

    if (record_date && record_time) {
        query += ' ORDER BY record_id DESC';
        query += ' LIMIT 1';
    }

    try {
        const [records] = await promisePool.execute(query, queryParams);

        // Round T1 and T2 to two decimal places
        const roundedRecords = records.map(record => ({
            ...record,
            T1: record.T1 ? parseFloat(record.T1).toFixed(2) : null,
            T2: record.T2 ? parseFloat(record.T2).toFixed(2) : null
        }));

        res.status(200).json(roundedRecords);
    } catch (error) {
        console.error('Error fetching clarifier records:', error);
        res.status(500).json({ error: 'Error fetching clarifier records' });
    }
});



// Add a new record to Clarifier table
app.post('/api/clarifier', async (req, res) => {
    const { machine_name, record_date, record_time, status, A_motor1, A_motor2, A_scum, A_pump, T_motor, T_scum, T_pump, note } = req.body;

    try {
        const insertQuery = `
            INSERT INTO Clarifier (machine_name, record_date, record_time, status, A_motor1, A_motor2, A_scum, A_pump, T_motor, T_scum, T_pump, note)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        await promisePool.execute(insertQuery, [machine_name, record_date, record_time, status, A_motor1, A_motor2, A_scum, A_pump, T_motor, T_scum, T_pump, note]);
        res.status(201).json({ message: 'Record added successfully' });
    } catch (error) {
        console.error('Error adding clarifier record:', error);
        res.status(500).json({ error: 'Error adding clarifier record' });
    }
});

// Update a record in Clarifier table
app.put('/api/clarifier/:id', async (req, res) => {
    const { id } = req.params;
    const { machine_name, record_date, record_time, status, A_motor1, A_motor2, A_scum, A_pump, T_motor, T_scum, T_pump, note } = req.body;

    try {
        const updateQuery = `
            UPDATE Clarifier
            SET machine_name = ?, record_date = ?, record_time = ?, status = ?, A_motor1 = ?, A_motor2 = ?, A_scum = ?, A_pump = ?, T_motor = ?, T_scum = ?, T_pump = ?, note=?
            WHERE record_id = ?
        `;
        await promisePool.execute(updateQuery, [machine_name, record_date, record_time, status, A_motor1, A_motor2, A_scum, A_pump, T_motor, T_scum, T_pump, note, id]);
        res.status(200).json({ message: 'Record updated successfully' });
    } catch (error) {
        console.error('Error updating clarifier record:', error);
        res.status(500).json({ error: 'Error updating clarifier record' });
    }
});


// Add a new record to Recorder table
// Get all records from Recorder table or the latest record based on record_date and record_time
app.get('/api/recorder', async (req, res) => {
    const { record_date, record_time } = req.query;
    let query = 'SELECT * FROM Recorder WHERE 1=1';
    const queryParams = [];

    if (record_date) {
        // Extract the date part only (YYYY-MM-DD)
        const formattedDate = record_date.split('T')[0];
        query += ' AND DATE(record_date) = ?';
        queryParams.push(formattedDate);
    }

    if (record_time) {
        query += ' AND record_time = ?';
        queryParams.push(record_time);
    }

    if (record_date && record_time) {
        query += ' ORDER BY record_id DESC LIMIT 1';
    }

    // Log the query and parameters
    console.log('Executing query:', query);
    console.log('With parameters:', queryParams);

    try {
        const [records] = await promisePool.execute(query, queryParams);
        res.status(200).json(records);
    } catch (error) {
        console.error('Error fetching recorder records:', error);
        res.status(500).json({ error: 'Error fetching recorder records' });
    }
});


app.post('/api/recorder', async (req, res) => {
    const { recorder_name, record_date, record_time } = req.body;

    try {
        const insertQuery = `
            INSERT INTO Recorder (recorder_name, record_date, record_time)
            VALUES (?, ?, ?)
        `;
        await promisePool.execute(insertQuery, [recorder_name, record_date, record_time]);
        res.status(201).json({ message: 'Record added successfully' });
    } catch (error) {
        console.error('Error adding recorder record:', error);
        res.status(500).json({ error: 'Error adding recorder record' });
    }
});



// Update a record in Recorder table
app.put('/api/recorder/:id', async (req, res) => {
    const { id } = req.params;
    const { recorder_name, record_date, record_time } = req.body;

    try {
        const updateQuery = `
            UPDATE Recorder
            SET recorder_name = ?, record_date = ?, record_time = ?
            WHERE record_id = ?
        `;
        await promisePool.execute(updateQuery, [recorder_name, record_date, record_time, id]);
        res.status(200).json({ message: 'Record updated successfully' });
    } catch (error) {
        console.error('Error updating recorder record:', error);
        res.status(500).json({ error: 'Error updating recorder record' });
    }
});

// List of tables
const tables = [
    'Inlet_Pumping',
    'Anoxic_Mixer',
    'Effluent_Pump',
    'Ventilation_Fan_Room1',
    'Ventilation_Fan_Room2',
    'Ventilation_Fan_Room3',
    'Ventilation_Fan_Room4',
    'Ventilation_Fan_Room5',
    'Ventilation_Fan_Room6',
    'Ventilation_Inlet_Pumping_Station',
    'Scum_Pump_Fan_Room6',
    'Drainage_Pump',
    'Chiller_Water_Pump'
];

// Create routes for each table
tables.forEach(createRoutesForTable);

module.exports = app
