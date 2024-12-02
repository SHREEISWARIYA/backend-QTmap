const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const moment = require('moment-timezone');  // You'll need to install this package


const app = express();
const SECRET_KEY = 'your-secret-key'; // Use a secure key in production

// Middleware
app.use(bodyParser.json());

// Enable CORS if needed
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    next();
});

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/QT_map', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const UserModel = mongoose.model('users', UserSchema);

// Login endpoint
app.post('/validateUser', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Username and password are required' 
            });
        } 
        
        // First check if user exists
        const userExists = await UserModel.findOne({ username });
        if (!userExists) {
            return res.status(401).json({ 
                success: false, 
                message: 'Username does not exist',
                errorType: 'username' 
            });
        }

        const user = await UserModel.findOne({ username, password });
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Incorrect password',
                errorType: 'password'   
            });
        }

        if (user) {
            // Generate JWT token
            const token = jwt.sign(
                { userId: user._id, username: user.username },
                SECRET_KEY,
                { expiresIn: '24h' }
            );
            
            res.json({ 
                success: true, 
                message: 'User validated successfully',
                token: token,
                username: user.username,
                userId: user._id.toString()  // Add this line to include the MongoDB ID
            });
        } else {
            res.status(401).json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

// Signup endpoint
app.post('/signup', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Username and password are required' 
            });
        }

        // Check if username exists
        const existingUser = await UserModel.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ 
                success: false, 
                message: 'Username already exists' 
            });
        }

        // Create new user
        const newUser = new UserModel({ username, password });
        await newUser.save(); 

        // Create default settings for the new user
        const defaultSettings = new SettingsModel({
            userId: newUser._id,
            general: {
                pastDataHours: 24,
                dataRefresh: 5,
                theme: 'Dark'
            },
            pastTrail: {
                hours: 24,
                plotSize: 'Small'
            }
        });

        await defaultSettings.save();

        console.log('Created default settings for new user:', {
            userId: newUser._id,
            settings: defaultSettings
        });

        res.json({ 
            success: true, 
            message: 'User registered successfully' 
        });
    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

// Verify token middleware
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'No token provided' 
        });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ 
            success: false, 
            message: 'Invalid token' 
        });
    }
};

// Protected route example
app.get('/protected', verifyToken, (req, res) => {
    res.json({ 
        success: true, 
        message: 'Protected data', 
        user: req.user 
    });
});   

///////////////////////////////////////////////////
////////////////////settings collection///////////

// Settings Schema - Update to include viewport
const SettingsSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'users' },
    general: {
        pastDataHours: { type: Number, default: 24 },
        dataRefresh: { type: Number, default: 5 },
        timezone: { type: Number, default: 0.0 },
        theme: { type: String, default: 'Dark', enum: ['Dark', 'Light'] }
    },
    pastTrail: {
        hours: { type: Number, default: 24 },
        plotSize: { type: String, default: 'Small' }
    },
    // Added viewport settings
    viewport: {
        latitude: { type: Number, default: 0 },
        longitude: { type: Number, default: 0 },
        zoomLevel: { type: Number, default: 3 }
    },
    updatedAt: { type: Date, default: Date.now }
});

const SettingsModel = mongoose.model('settings', SettingsSchema);

// Save settings endpoint
app.post('/saveSettings', verifyToken, async (req, res) => {
    try {
        const { userId, settings } = req.body;
        
        // Debug log
        console.log('Received request body:', JSON.stringify(req.body, null, 2));

        if (!userId || !settings) {
            return res.status(400).json({
                success: false,
                message: 'UserId and settings are required'
            });
        }

        // Validate settings structure
        if (!settings.general) {
            return res.status(400).json({
                success: false,
                message: 'Invalid settings structure. General section is required.'
            });
        }

        // Validate required fields
        if (!settings.general.pastDataHours || 
            !settings.general.dataRefresh || 
            !settings.general.theme ||
            settings.general.timezone === undefined ||  // Changed validation for timezone
            !settings.pastTrail.hours || 
            !settings.pastTrail.plotSize) {
            return res.status(400).json({
                success: false,
                message: 'Missing required settings fields'
            });
        }

        // Format the settings data with safe parsing
        const formattedSettings = {
            general: {
                pastDataHours: parseInt(settings.general.pastDataHours) || 24,
                dataRefresh: parseInt(settings.general.dataRefresh) || 5,
                theme: settings.general.theme || 'Dark' ,
                timezone: parseFloat(settings.general.timezone) || 0.0 
            },
            pastTrail: {
                hours: parseInt(settings.pastTrail.hours) || 24,
                plotSize: settings.pastTrail.plotSize || "Small"
            }
        };

        // Validate timezone offset range
        if (formattedSettings.general.timezone < -12.0 || formattedSettings.general.timezone > 14.0) {
            return res.status(400).json({
                success: false,
                message: 'Invalid timezone offset. Must be between -12.0 and +14.0'
            });
        }

        // Debug log
        console.log('Formatted settings:', JSON.stringify(formattedSettings, null, 2));

        // Update or create settings
        const updatedSettings = await SettingsModel.findOneAndUpdate(
            { userId: new mongoose.Types.ObjectId(userId) },
            { 
                $set: {
                    ...formattedSettings,
                    updatedAt: new Date()
                }
            },
            { upsert: true, new: true }
        );

        res.json({
            success: true,
            message: 'Settings saved successfully',
            settings: updatedSettings
        });

    } catch (err) {
        console.error('Save settings error:', err);
        console.error('Request body:', req.body);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: err.message
        });
    }
}); 

// Add the new endpoints
app.post('/saveViewportAndTheme', verifyToken, async (req, res) => {
    try {
        const { userId, viewport, isDarkTheme } = req.body;

        console.log('Received viewport and theme update:', {
            userId,
            viewport,
            isDarkTheme
        });

        if (!userId || !viewport) {
            return res.status(400).json({
                success: false,
                message: 'UserId and viewport data are required'
            });
        }

        // Validate viewport data
        if (viewport.latitude === undefined || 
            viewport.longitude === undefined || 
            viewport.zoomLevel === undefined) {
            return res.status(400).json({
                success: false,
                message: 'Invalid viewport data'
            });
        }

        // Format the viewport data with safe parsing
        const formattedViewport = {
            latitude: parseFloat(viewport.latitude) || 0,
            longitude: parseFloat(viewport.longitude) || 0,
            zoomLevel: parseInt(viewport.zoomLevel) || 3
        };

        // Validate coordinate ranges
        if (formattedViewport.latitude < -90 || formattedViewport.latitude > 90 ||
            formattedViewport.longitude < -180 || formattedViewport.longitude > 180) {
            return res.status(400).json({
                success: false,
                message: 'Invalid coordinates'
            });
        }

        // Update settings
        const updatedSettings = await SettingsModel.findOneAndUpdate(
            { userId: new mongoose.Types.ObjectId(userId) },
            { 
                $set: {
                    viewport: formattedViewport,
                    'general.theme': isDarkTheme ? 'Dark' : 'Light',
                    updatedAt: new Date()
                }
            },
            { upsert: true, new: true }
        );

        res.json({
            success: true,
            message: 'Viewport and theme settings saved successfully',
            settings: updatedSettings
        });

    } catch (err) {
        console.error('Save viewport and theme error:', err);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: err.message
        });
    }
});

// Endpoint to get viewport and theme
app.get('/getViewportAndTheme/:userId', verifyToken, async (req, res) => {
    try {
        const userId = req.params.userId;

        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'UserId is required'
            });
        }

        const settings = await SettingsModel.findOne({ 
            userId: new mongoose.Types.ObjectId(userId) 
        });

        if (!settings) {
            // Return default values if no settings found
            return res.json({
                success: true,
                viewport: {
                    latitude: 0,
                    longitude: 0,
                    zoomLevel: 3
                },
                isDarkTheme: true
            });
        }

        res.json({
            success: true,
            viewport: settings.viewport,
            isDarkTheme: settings.general.theme === 'Dark'
        });

    } catch (err) {
        console.error('Get viewport and theme error:', err);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: err.message
        });
    }
});




////////////////////////////
//////////////////////////// 

app.get('/getSettings/:userId', verifyToken, async (req, res) => {
    try {
        console.log('Received request for settings');
        console.log('UserId:', req.params.userId);
        console.log('Auth header:', req.headers.authorization);

        const userId = req.params.userId;

        if (!userId) {
            console.log('No userId provided');
            return res.status(400).json({
                success: false,
                message: 'UserId is required'
            });
        }

        console.log('Looking for settings with userId:', userId);
        const settings = await SettingsModel.findOne({ 
            userId: new mongoose.Types.ObjectId(userId) 
        });

        console.log('Found settings:', settings);

        if (!settings) {
            console.log('No settings found');
            return res.status(404).json({
                success: false,
                message: 'Settings not found for this user'
            });
        }

        console.log('Sending settings response');
        res.json({
            success: true,
            message: 'Settings retrieved successfully',
            settings: settings
        });

    } catch (err) {
        console.error('Get settings error:', err);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            
            error: err.message
        });
    }
});
///////////////////////////////

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});