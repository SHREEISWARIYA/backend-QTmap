const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 10;

// Use the same MongoDB connection string as your main app
const MONGODB_URI = 'mongodb://localhost:27017/QT_map';

// User Schema (copy from your main app to ensure consistency)
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false }
});

const UserModel = mongoose.model('users', UserSchema);

async function migratePasswords() {
    try {
        // Connect to MongoDB
        await mongoose.connect(MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log('Connected to MongoDB');

        // Get all users
        const users = await UserModel.find({});
        console.log(`Found ${users.length} users to migrate`);

        // Keep track of migration progress
        let migrated = 0;
        let errors = 0;

        // Process each user
        for (const user of users) {
            try {
                // Check if password is already hashed (basic check)
                const isAlreadyHashed = user.password.length > 40; // bcrypt hashes are typically longer

                if (!isAlreadyHashed) {
                    // Hash the plain text password
                    const hashedPassword = await bcrypt.hash(user.password, SALT_ROUNDS);
                    
                    // Update user with hashed password
                    await UserModel.updateOne(
                        { _id: user._id },
                        { $set: { password: hashedPassword } }
                    );

                    console.log(`Migrated user: ${user.username}`);
                    migrated++;
                } else {
                    console.log(`Skipping already hashed password for user: ${user.username}`);
                }
            } catch (err) {
                console.error(`Error migrating user ${user.username}:`, err);
                errors++;
            }
        }

        console.log('\nMigration Summary:');
        console.log(`Total users: ${users.length}`);
        console.log(`Successfully migrated: ${migrated}`);
        console.log(`Errors: ${errors}`);

    } catch (err) {
        console.error('Migration failed:', err);
    } finally {
        // Close MongoDB connection
        await mongoose.connection.close();
        console.log('Database connection closed');
    }
}

// Run the migration
migratePasswords().then(() => {
    console.log('Migration completed');
    process.exit(0);
}).catch(err => {
    console.error('Migration failed:', err);
    process.exit(1);
});