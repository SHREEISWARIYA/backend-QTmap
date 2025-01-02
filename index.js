const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const moment = require('moment-timezone');  // You'll need to install this package
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 10; // Number of salt rounds for bcrypt


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
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false }
});

const UserModel = mongoose.model('users', UserSchema);

// Login endpoint
app.post('/validateUser', async (req, res) => {
    try {
        const { username, password } = req.body; 

        console.log("\n=== Login Attempt ===");
        console.log("Username:", username);

        // Validate input
        if (!username || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Username and password are required' 
            });
        } 
        
        // Find user by username
        const user = await UserModel.findOne({ username });
        
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Username does not exist',
                errorType: 'username' 
            });
        }

        // Compare password with hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        console.log("Attempting password verification");
        console.log("Input password:", password);
        console.log("Stored hashed password:", user.password);
        console.log("Password valid:", isPasswordValid);
        
        if (!isPasswordValid) {
            return res.status(401).json({ 
                success: false, 
                message: 'Incorrect password',
                errorType: 'password'   
            });
        }

        // If we get here, username and password are correct
        const userObject = user.toObject();

        console.log("\n=== User Found ===");
        console.log("User ID:", userObject._id.toString());
        console.log("Username:", userObject.username);
        console.log("Is Admin:", Boolean(userObject.isAdmin));
        console.log("Raw isAdmin value:", userObject.isAdmin);
        console.log("Full user object:", JSON.stringify(userObject, null, 2));

        // If user is admin, log additional information
        if (userObject.isAdmin === true) {
            console.log("\n=== Admin User Detected ===");
            console.log("Admin privileges are enabled for this user");
        }

        // Generate JWT token with admin status
        const token = jwt.sign(
            { 
                userId: user._id, 
                username: user.username,
                isAdmin: user.isAdmin
            },
            SECRET_KEY,
            { expiresIn: '24h' }
        ); 

        console.log("\n=== Login Success ===");
        console.log("Token generated successfully");
        
        // Send response with all necessary user information
        res.json({ 
            success: true, 
            message: 'User validated successfully',
            token: token,
            username: user.username,
            userId: user._id.toString(),
            isAdmin: user.isAdmin,
            // You can add additional user data here if needed
        });

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

        // Hash password
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        // Create new user with hashed password
        const newUser = new UserModel({ 
            username, 
            password: hashedPassword // Store hashed password
        });
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
            },
            tracking: {
                mmsiList: [],  // Add empty MMSI list by default
                trackColor: "#FFFF00"  
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


////////// user management admin login //////////

// Get all users endpoint (protected, admin only)
app.get('/users', verifyToken, async (req, res) => {
    try {
        // Check if the requesting user is an admin
        if (!req.user.isAdmin) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.',
            });
        }

        // Fetch all users, excluding passwords
        const users = await UserModel.find({}, { password: 0 });

        // Filter out users with isAdmin: true
        const nonAdminUsers = users.filter(user => !user.isAdmin);

        console.log('Fetched non-admin users:', nonAdminUsers);

        res.json({
            success: true,
            message: 'Users retrieved successfully',
            users: nonAdminUsers.map(user => ({
                id: user._id,
                username: user.username,
                isAdmin: user.isAdmin,
                // Add any other fields you want to include
            })),
        });
    } catch (err) {
        console.error('Get users error:', err);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: err.message,
        });
    }
}); 

// Add this to your backend code
app.delete('/users/:userId', verifyToken, async (req, res) => {
    try {
        // Check if the requesting user is an admin
        if (!req.user.isAdmin) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }

        const userToDelete = await UserModel.findById(req.params.userId);
        
        // Prevent deletion of admin users
        if (userToDelete.isAdmin) {
            return res.status(400).json({
                success: false,
                message: 'Cannot delete admin users'
            });
        } 

        // Delete user's settings first
        await SettingsModel.findOneAndDelete({ userId: req.params.userId });

        await UserModel.findByIdAndDelete(req.params.userId);
        
        res.json({
            success: true,
            message: 'User and associated settings deleted successfully'
        });

    } catch (err) {
        console.error('Delete user error:', err);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: err.message
        });
    }
});  

//to edit users 
app.post('/updateUsername', verifyToken, async (req, res) => {
    try {
        // Check if the requesting user is an admin
        if (!req.user.isAdmin) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }

        const { userId, newUsername } = req.body;

        // Check if new username already exists
        const existingUser = await UserModel.findOne({ 
            username: newUsername,
            _id: { $ne: userId } // Exclude the current user
        });

        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'Username already exists'
            });
        }

        // Update username
        const updatedUser = await UserModel.findByIdAndUpdate(
            userId,
            { username: newUsername },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            message: 'Username updated successfully',
            user: {
                id: updatedUser._id,
                username: updatedUser.username,
                isAdmin: updatedUser.isAdmin
            }
        });

    } catch (err) {
        console.error('Update username error:', err);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: err.message
        });
    }
}); 

//update password
app.post('/updatePassword', verifyToken, async (req, res) => {
    try {
        if (!req.user.isAdmin) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }

        const { userId, newPassword } = req.body;

        // Password validation regex
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

        if (!passwordRegex.test(newPassword)) {
            return res.status(400).json({
                success: false,
                message: 'Password must contain at least 8 characters, including uppercase, lowercase, number and special character'
            });
        } 

         // Hash new password
         const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

        const updatedUser = await UserModel.findByIdAndUpdate(
            userId,
            { password: hashedPassword },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            message: 'Password updated successfully'
        });

    } catch (err) {
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
}); 

// //to create new user by admin
app.post('/admin/createUser', verifyToken, async (req, res) => {
    try {
        // Verify admin privileges
        if (!req.user.isAdmin) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin privileges required.'
            });
        }

        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Username and password are required' 
            });
        }

        // Password validation regex
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({
                success: false,
                message: 'Password must contain at least 8 characters, including uppercase, lowercase, number and special character'
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

        // Hash password
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        // Create new user
        const newUser = new UserModel({ username, password: hashedPassword  });
        await newUser.save();

        // Create default settings
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
            },
            tracking: {
                watchlists: [
                    {
                        name: "Watchlist 1",
                        description: "First watchlist",
                        mmsiList: [],
                        isActive: false
                    },
                    {
                        name: "Watchlist 2",
                        description: "Second watchlist",
                        mmsiList: [],
                        isActive: false
                    },
                    {
                        name: "Watchlist 3",
                        description: "Third watchlist",
                        mmsiList: [],
                        isActive: false
                    },
                    {
                        name: "Watchlist 4",
                        description: "Fourth watchlist",
                        mmsiList: [],
                        isActive: false
                    },
                    {
                        name: "Watchlist 5",
                        description: "Fifth watchlist",
                        mmsiList: [],
                        isActive: false
                    }
                ],
                trackColor: "#FFFF00"
            },
            ui: {
                searchBar: {
                    x: 10,
                    y: 10
                }
            }        
        });

        await defaultSettings.save();

        res.json({ 
            success: true, 
            message: 'User created successfully' 
        });

    } catch (err) {
        console.error('Create user error:', err);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});


///////////////////////////////////////////////////
//////////////////// settings collection ///////////

// Settings Schema - Update to include preferredLocation section
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
    viewport: {
        latitude: { type: Number, default: 0 },
        longitude: { type: Number, default: 0 },
        zoomLevel: { type: Number, default: 3 }
    },
    preferredLocation: {
        name: { type: String, default: '' },
        WKT: { type: String, default: '' },
        isPreferred : { type: Boolean, default: true }
    },
    tracking: {
        watchlists: {
            type: [{
                name: { type: String, required: true },
                description: { type: String },
                mmsiList: { type: [String], default: [] },
                isActive: { type: Boolean, default: false }
            }],
            default: () => ([
                {
                    name: "Watchlist 1",
                    description: "First watchlist",
                    mmsiList: [],
                    isActive: false
                },
                {
                    name: "Watchlist 2",
                    description: "Second watchlist",
                    mmsiList: [],
                    isActive: false
                },
                {
                    name: "Watchlist 3",
                    description: "Third watchlist",
                    mmsiList: [],
                    isActive: false
                },
                {
                    name: "Watchlist 4",
                    description: "Fourth watchlist",
                    mmsiList: [],
                    isActive: false
                },
                {
                    name: "Watchlist 5",
                    description: "Fifth watchlist",
                    mmsiList: [],
                    isActive: false
                }
            ])
        },
        trackColor: { type: String, default: "#FFFF00" }
    },
    ui: {
        searchBar: {
            x: { type: Number, default: 10 },
            y: { type: Number, default: 10 }
        }
    },
    updatedAt: { type: Date, default: Date.now }
});

const SettingsModel = mongoose.model('settings', SettingsSchema); 

// Add this near the top of your file, after your imports
const DEFAULT_WATCHLISTS = [
    {
        name: "Watchlist 1",
        description: "First watchlist",
        mmsiList: [],
        isActive: false
    },
    {
        name: "Watchlist 2",
        description: "Second watchlist",
        mmsiList: [],
        isActive: false
    },
    {
        name: "Watchlist 3",
        description: "Third watchlist",
        mmsiList: [],
        isActive: false
    },
    {
        name: "Watchlist 4",
        description: "Fourth watchlist",
        mmsiList: [],
        isActive: false
    },
    {
        name: "Watchlist 5",
        description: "Fifth watchlist",
        mmsiList: [],
        isActive: false
    }
];

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
                timezone: parseFloat(settings.general.timezone) || 0.0 ,
            },
            pastTrail: {
                hours: parseInt(settings.pastTrail.hours) || 24,
                plotSize: settings.pastTrail.plotSize || "Small"
            },
            tracking: {
                mmsiList: Array.isArray(settings.tracking?.mmsiList) 
                    ? settings.tracking.mmsiList 
                    : [],
                trackColor: settings.tracking?.trackColor || "#FFFF00",
                // Handle watchlists
                watchlists: Array.isArray(settings.tracking?.watchlists)
                    ? settings.tracking.watchlists.map(watchlist => ({
                        name: watchlist.name || "",
                        description: watchlist.description || "",
                        mmsiList: Array.isArray(watchlist.mmsiList) 
                            ? watchlist.mmsiList 
                            : [],
                        isActive: Boolean(watchlist.isActive)
                    }))
                    : []
            }
        };  

        // Get existing settings to preserve watchlists if not provided in update
        const existingSettings = await SettingsModel.findOne({ 
            userId: new mongoose.Types.ObjectId(userId) 
        });

        // If watchlists aren't provided in the update but exist in current settings, preserve them
        if (!settings.tracking?.watchlists && existingSettings?.tracking?.watchlists) {
            formattedSettings.tracking.watchlists = existingSettings.tracking.watchlists;
        }

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
                    'ui.searchBar': settings.ui?.searchBar || { x: 10, y: 10 },
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

// Save preferred location endpoint
app.post('/savePreferredLocation', verifyToken, async (req, res) => {
    try {
        const { userId, preferredLocation } = req.body;
        console.log('Received viewport and theme update:', {
            userId,
            preferredLocation
        });
        if (!userId || !preferredLocation) {
            return res.status(400).json({
                success: false,
                message: 'UserId and preferredLocation are required'
            });
        }

        // Update settings
        const updatedSettings = await SettingsModel.findOneAndUpdate(
            { userId: new mongoose.Types.ObjectId(userId) },
            { 
                $set: {
                    preferredLocation: {
                        name: preferredLocation.name,
                        WKT: preferredLocation.WKT,
                        isPreferred : preferredLocation.isPreferred
                    },
                    updatedAt: new Date()
                }
            },
            { upsert: true, new: true }
        );

        res.json({
            success: true,
            message: 'Preferred location saved successfully',
            settings: updatedSettings
        });

    } catch (err) {
        console.error('Save preferred location error:', err);
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
                preferredLocation:
                {
                    name : "Not Set",
                    WKT : "",
                    isPreferred : false 
                },
                isDarkTheme: true
            });
        }

        res.json({
            success: true,
            viewport: settings.viewport,
            preferredLocation: settings.preferredLocation,
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

    


// Add UUID endpoint
app.post('/addUUIDToWatchlist', verifyToken, async (req, res) => {
    try {
        const { userId, uuid, watchlistName } = req.body;

        if (!userId || !uuid || !watchlistName) {
            return res.status(400).json({
                success: false,
                message: 'UserId, UUID, and Watchlist name are required'
            });
        }

        // Find user settings and the specific watchlist
        const settings = await SettingsModel.findOne({ 
            userId: new mongoose.Types.ObjectId(userId) 
        });

        if (!settings) {
            return res.status(404).json({
                success: false,
                message: 'Settings not found for this user'
            });
        }

        const watchlist = settings.tracking.watchlists.find(wl => wl.name === watchlistName);

        if (!watchlist) {
            return res.status(404).json({
                success: false,
                message: 'Watchlist not found'
            });
        }

        // Check if UUID already exists in the watchlist
        if (watchlist.mmsiList.includes(uuid)) {
            return res.status(400).json({
                success: false,
                message: 'UUID already exists in the watchlist'
            });
        }

        // Add new UUID to the watchlist
        watchlist.mmsiList.push(uuid);
        settings.updatedAt = new Date();
        await settings.save();

        res.json({
            success: true,
            message: 'UUID added successfully',
            watchlist: watchlist
        });

    } catch (err) {
        console.error('Add UUID error:', err);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: err.message
        });
    }
});


//delete mmsi from tracking
// Delete MMSI endpoint
app.delete('/deleteMMSI/:userId/:mmsiId', verifyToken, async (req, res) => {
    try {
        const { userId, mmsiId } = req.params;

        if (!userId || !mmsiId) {
            return res.status(400).json({
                success: false,
                message: 'UserId and mmsiId are required'
            });
        }

        // Find user settings
        const settings = await SettingsModel.findOne({ 
            userId: new mongoose.Types.ObjectId(userId) 
        });

        if (!settings) {
            return res.status(404).json({
                success: false,
                message: 'Settings not found for this user'
            });
        }

        // Remove MMSI from the list
        const mmsiIndex = settings.tracking.mmsiList.indexOf(mmsiId);
        if (mmsiIndex === -1) {
            return res.status(404).json({
                success: false,
                message: 'MMSI not found in the list'
            });
        }

        settings.tracking.mmsiList.splice(mmsiIndex, 1);
        settings.updatedAt = new Date();
        await settings.save();

        console.log(`MMSI ${mmsiId} deleted for user ${userId}`);

        res.json({
            success: true,
            message: 'MMSI deleted successfully',
            mmsiList: settings.tracking.mmsiList
        });

    } catch (err) {
        console.error('Delete MMSI error:', err);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: err.message
        });
    }
});         


// add watchlist
// Create new watchlist
app.post('/addWatchlist', verifyToken, async (req, res) => {
    try {
        const { userId, name, description } = req.body;

        const settings = await SettingsModel.findOne({ 
            userId: new mongoose.Types.ObjectId(userId) 
        });

        if (!settings) {
            return res.status(404).json({
                success: false,
                message: 'Settings not found for this user'
            });
        }

        // Check if watchlist name already exists
        if (settings.tracking.watchlists.some(w => w.name === name)) {
            return res.status(400).json({
                success: false,
                message: 'Watchlist name already exists'
            });
        }

        settings.tracking.watchlists.push({
            name,
            description,
            mmsiList: [],
            isActive: false
        });

        await settings.save();

        res.json({
            success: true,
            message: 'Watchlist created successfully',
            watchlists: settings.tracking.watchlists
        });
    } catch (err) {
        console.error('Add watchlist error:', err);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Add MMSI to specific watchlist
app.post('/addMMSIToWatchlist', verifyToken, async (req, res) => {
    try {
        const { userId, watchlistName, mmsiId } = req.body;

        // Validate MMSI format
        const mmsiRegex = /^\d{9}$/;
        if (!mmsiRegex.test(mmsiId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid MMSI format'
            });
        }

        const settings = await SettingsModel.findOne({ 
            userId: new mongoose.Types.ObjectId(userId) 
        });

        const watchlist = settings.tracking.watchlists.find(w => w.name === watchlistName);
        if (!watchlist) {
            return res.status(404).json({
                success: false,
                message: 'Watchlist not found'
            });
        }

        if (watchlist.mmsiList.includes(mmsiId)) {
            return res.status(400).json({
                success: false,
                message: 'MMSI already exists in this watchlist'
            });
        }

        watchlist.mmsiList.push(mmsiId);
        await settings.save();

        res.json({
            success: true,
            message: 'MMSI added to watchlist successfully',
            watchlist: watchlist
        });
    } catch (err) {
        console.error('Add MMSI to watchlist error:', err);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
}); 

//get watchlist
// Get Watchlists endpoint
app.get('/getWatchlists/:userId', verifyToken, async (req, res) => {
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
            return res.status(404).json({
                success: false,
                message: 'Settings not found for this user'
            });
        }

        res.json({
            success: true,
            watchlists: settings.tracking.watchlists
        });

    } catch (err) {
        console.error('Get watchlists error:', err);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});  

//delete watchlist
// Delete watchlist endpoint
app.delete('/deleteWatchlist/:userId/:watchlistName', verifyToken, async (req, res) => {
    try {
        const userId = req.params.userId;
        const watchlistName = decodeURIComponent(req.params.watchlistName); // Decode the URL-encoded name

        console.log('Deleting watchlist:', { userId, watchlistName }); // Debug log

        if (!userId || !watchlistName) {
            return res.status(400).json({
                success: false,
                message: 'UserId and watchlist name are required'
            });
        }

        const settings = await SettingsModel.findOne({ 
            userId: new mongoose.Types.ObjectId(userId) 
        });

        if (!settings) {
            return res.status(404).json({
                success: false,
                message: 'Settings not found for this user'
            });
        }

        // Find and remove the watchlist
        const watchlistIndex = settings.tracking.watchlists.findIndex(w => w.name === watchlistName);
        if (watchlistIndex === -1) {
            return res.status(404).json({
                success: false,
                message: 'Watchlist not found'
            });
        }

        settings.tracking.watchlists.splice(watchlistIndex, 1);
        await settings.save();

        console.log('Watchlist deleted successfully'); // Debug log

        res.json({
            success: true,
            message: 'Watchlist deleted successfully',
            watchlists: settings.tracking.watchlists
        });

    } catch (err) {
        console.error('Delete watchlist error:', err);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: err.message
        });
    }
}); 

//rename watchlist
// Rename watchlist endpoint
app.put('/renameWatchlist/:userId/:oldName/:newName', verifyToken, async (req, res) => {
    try {
        const userId = req.params.userId;
        const oldName = decodeURIComponent(req.params.oldName);
        const newName = decodeURIComponent(req.params.newName);

        console.log('Renaming watchlist:', { userId, oldName, newName }); // Debug log

        if (!userId || !oldName || !newName) {
            return res.status(400).json({
                success: false,
                message: 'UserId, old name, and new name are required'
            });
        }

        const settings = await SettingsModel.findOne({ 
            userId: new mongoose.Types.ObjectId(userId) 
        });

        if (!settings) {
            return res.status(404).json({
                success: false,
                message: 'Settings not found for this user'
            });
        }

        // Check if new name already exists
        if (settings.tracking.watchlists.some(w => w.name === newName)) {
            return res.status(400).json({
                success: false,
                message: 'A watchlist with this name already exists'
            });
        }

        // Find and rename the watchlist
        const watchlist = settings.tracking.watchlists.find(w => w.name === oldName);
        if (!watchlist) {
            return res.status(404).json({
                success: false,
                message: 'Watchlist not found'
            });
        }

        watchlist.name = newName;
        await settings.save();

        res.json({
            success: true,
            message: 'Watchlist renamed successfully',
            watchlists: settings.tracking.watchlists
        });

    } catch (err) {
        console.error('Rename watchlist error:', err);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: err.message
        });
    }
}); 

//delete mmsi from watchlist
// Delete MMSI from watchlist endpoint
app.delete('/deleteMMSIFromWatchlist/:userId/:watchlistName/:mmsiId', verifyToken, async (req, res) => {
    try {
        const userId = req.params.userId;
        const watchlistName = decodeURIComponent(req.params.watchlistName);
        const mmsiId = req.params.mmsiId;

        console.log('Deleting MMSI from watchlist:', { userId, watchlistName, mmsiId });

        if (!userId || !watchlistName || !mmsiId) {
            return res.status(400).json({
                success: false,
                message: 'UserId, watchlist name, and mmsiId are required'
            });
        }

        const settings = await SettingsModel.findOne({ 
            userId: new mongoose.Types.ObjectId(userId) 
        });

        if (!settings) {
            return res.status(404).json({
                success: false,
                message: 'Settings not found for this user'
            });
        }

        // Find the watchlist
        const watchlist = settings.tracking.watchlists.find(w => w.name === watchlistName);
        if (!watchlist) {
            return res.status(404).json({
                success: false,
                message: 'Watchlist not found'
            });
        }

        // Find and remove the MMSI
        const mmsiIndex = watchlist.mmsiList.indexOf(mmsiId);
        if (mmsiIndex === -1) {
            return res.status(404).json({
                success: false,
                message: 'MMSI not found in watchlist'
            });
        }

        watchlist.mmsiList.splice(mmsiIndex, 1);
        await settings.save();

        console.log('MMSI deleted from watchlist successfully');

        res.json({
            success: true,
            message: 'MMSI deleted from watchlist successfully',
            watchlist: watchlist
        });

    } catch (err) {
        console.error('Delete MMSI from watchlist error:', err);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: err.message
        });
    }
});

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


// Save UI Position (integrates with existing saveSettings endpoint)
app.post('/saveUIPosition', verifyToken, async (req, res) => {
    try {
        const { userId, x, y } = req.body;

        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'UserId is required'
            });
        }

        // Update only the UI position
        const result = await SettingsModel.findOneAndUpdate(
            { userId: new mongoose.Types.ObjectId(userId) },
            { 
                $set: {
                    'ui.searchBar.x': x,
                    'ui.searchBar.y': y,
                    updatedAt: new Date()
                }
            },
            { upsert: true, new: true }
        );

        res.json({
            success: true,
            message: 'UI position saved successfully',
            position: result.ui.searchBar
        });

    } catch (err) {
        console.error('Save UI position error:', err);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: err.message
        });
    }
});

// Get UI Position (separate from getSettings for efficiency)
app.get('/getUIPosition/:userId', verifyToken, async (req, res) => {
    try {
        const userId = req.params.userId;

        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'UserId is required'
            });
        }

        const settings = await SettingsModel.findOne(
            { userId: new mongoose.Types.ObjectId(userId) },
            { 'ui.searchBar': 1 }
        );

        const position = settings?.ui?.searchBar || { x: 10, y: 10 };

        res.json({
            success: true,
            position: position
        });

    } catch (err) {
        console.error('Get UI position error:', err);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: err.message
        });
    }
});

// Migration script for adding UI positions
async function addUIPositionsToExistingSettings() {
    try {
        const result = await SettingsModel.updateMany(
            { 'ui.searchBar': { $exists: false } },
            { 
                $set: { 
                    'ui.searchBar': { 
                        x: 10, 
                        y: 10 
                    } 
                } 
            }
        );
        console.log('UI positions migration complete:', result);
    } catch (err) {
        console.error('UI positions migration error:', err);
    }
}  

// watchList migrations
// async function migrateToWatchlists() {
//     try {
//         // Find all settings documents that have mmsiList but no watchlists
//         const settings = await SettingsModel.find({
//             'tracking.mmsiList': { $exists: true },
//             'tracking.watchlists': { $exists: false }
//         });

//         console.log(`Found ${settings.length} settings to migrate`);

//         for (const setting of settings) {
//             // Create default watchlist with existing MMSIs
//             const existingMmsiList = setting.tracking.mmsiList || [];
            
//             setting.tracking.watchlists = [{
//                 name: "Default Watchlist",
//                 description: "Migrated from original MMSI list",
//                 mmsiList: existingMmsiList,
//                 isActive: true
//             }];

//             // Remove old mmsiList field
//             setting.tracking = {
//                 ...setting.tracking,
//                 mmsiList: undefined
//             };

//             await setting.save();
//             console.log(`Migrated settings for user ${setting.userId}`);
//         }

//         console.log('Watchlist migration completed successfully');
//     } catch (err) {
//         console.error('Watchlist migration error:', err);
//     }
// }


// Update the migration script
async function migrateToWatchlists() {
    try {
        const defaultWatchlists = [
            {
                name: "Watchlist 1",
                description: "First watchlist",
                mmsiList: [],
                isActive: false
            },
            {
                name: "Watchlist 2",
                description: "Second watchlist",
                mmsiList: [],
                isActive: false
            },
            {
                name: "Watchlist 3",
                description: "Third watchlist",
                mmsiList: [],
                isActive: false
            },
            {
                name: "Watchlist 4",
                description: "Fourth watchlist",
                mmsiList: [],
                isActive: false
            },
            {
                name: "Watchlist 5",
                description: "Fifth watchlist",
                mmsiList: [],
                isActive: false
            }
        ];

        // Update all existing settings documents
        const result = await SettingsModel.updateMany(
            {'tracking.watchlists': { $exists: false } }, // Match all documents
            { 
                $set: { 
                    'tracking.watchlists': defaultWatchlists 
                } 
            }
        );

        console.log('Watchlist migration complete:', result);
    } catch (err) {
        console.error('Watchlist migration error:', err);
    }
}  

// Add migration for viewport and preferredLocation
async function addViewportAndLocationToExistingSettings() {
    try {
        // Update all documents that don't have viewport or preferredLocation
        const result = await SettingsModel.updateMany(
            {
                $or: [
                    { viewport: { $exists: false } },
                    { preferredLocation: { $exists: false } }
                ]
            },
            {
                $set: {
                    viewport: {
                        latitude: 23.745451463033906,
                        longitude: 58.11198214362875,
                        zoomLevel: 6
                    },
                    preferredLocation: {
                        name: "0",
                        WKT: "0",
                        isPreferred: false
                    }
                }
            },
            { multi: true }
        );

        console.log('Migration results:', {
            matchedCount: result.matchedCount,
            modifiedCount: result.modifiedCount,
            upsertedCount: result.upsertedCount
        });

        // Verify the update
        const remainingDocs = await SettingsModel.countDocuments({
            $or: [
                { viewport: { $exists: false } },
                { preferredLocation: { $exists: false } }
            ]
        });

        console.log(`Remaining documents without viewport/preferredLocation: ${remainingDocs}`);

        if (result.modifiedCount > 0) {
            console.log('Viewport and PreferredLocation migration completed successfully');
        } else {
            console.log('No documents needed migration');
        }
    } catch (err) {
        console.error('Error in viewport and preferredLocation migration:', err);
        throw err;
    }
}

// Run both migrations when the server starts
async function runAllMigrations() {
    try {
        // Run existing theme migration
        //await addThemeToExistingSettings();
        
        // Run UI settings migration
        await addUIPositionsToExistingSettings(); 

        //watchList migration
        await migrateToWatchlists(); 

        // Run viewport and preferredLocation migration
        //await addViewportAndLocationToExistingSettings();
        
        console.log('All migrations completed');
    } catch (err) {
        console.error('Migrations error:', err);
    }
}

// Run the migrations when the server starts
runAllMigrations();

///////////////////////////////

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});       





